# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests of the viewer's audit log (viewer/audit.py)."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from viewer import audit  # noqa: E402


class AuditTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"INGETRAZO_STATE": self.tmp.name},
                                   clear=False)
        self.env.start()
        for k in ("VIEWER_AUDIT", "VIEWER_AUDIT_FILE", "VIEWER_AUDIT_MAX_MB",
                  "VIEWER_AUDIT_KEEP", "VIEWER_AUDIT_DAYS", "VIEWER_TRUSTED_PROXIES",
                  "PROXY_TRUSTED_IPS"):
            os.environ.pop(k, None)

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def test_record_and_read_newest_first(self):
        audit.record("access", user="anna", ip="10.0.0.5", method="GET", path="/", status=200)
        audit.record("login", user="bob", status=401, detail="wrong user name or password")
        audit.record("error", detail="model.igz: sheet:2: timed out")
        rows, more = audit.read()
        self.assertFalse(more)
        self.assertEqual([r["kind"] for r in rows], ["error", "login", "access"])
        self.assertEqual(rows[2]["user"], "anna")
        self.assertNotIn("user", rows[0])               # empty fields are left out
        self.assertTrue((Path(self.tmp.name) / "audit.log").is_file())

    def test_filters(self):
        audit.record("access", user="Anna", path="/m/house")
        audit.record("access", user="bob", path="/m/garage")
        audit.record("admin", user="Anna", action="delete", target="bob")
        self.assertEqual(len(audit.read(kind="access")[0]), 2)
        self.assertEqual(len(audit.read(user="anna")[0]), 2)    # case-insensitive
        self.assertEqual([r["path"] for r in audit.read(text="GARAGE")[0]], ["/m/garage"])
        self.assertEqual(audit.read(since="2999-01-01")[0], [])
        self.assertEqual(audit.users(), ["Anna", "bob"])

    def test_paging(self):
        for i in range(5):
            audit.record("access", path=f"/{i}")
        rows, more = audit.read(limit=2)
        self.assertEqual([r["path"] for r in rows], ["/4", "/3"])
        self.assertTrue(more)
        rows, more = audit.read(offset=4, limit=2)
        self.assertEqual([r["path"] for r in rows], ["/0"])
        self.assertFalse(more)

    def test_access_link_token_is_redacted(self):
        audit.record("access", path="/t/itv_secret123?next=/", detail='GET /t/itv_x "a"')
        text = (Path(self.tmp.name) / "audit.log").read_text()
        self.assertNotIn("itv_secret123", text)
        self.assertNotIn("itv_x", text)
        self.assertEqual(audit.read()[0][0]["path"], "/t/…?next=/")

    def test_rotation_keeps_the_newest(self):
        os.environ["VIEWER_AUDIT_MAX_MB"] = "1"
        os.environ["VIEWER_AUDIT_KEEP"] = "2"
        big = "x" * 1500
        for i in range(2000):                           # ~3 MB: rotates twice or more
            audit.record("access", path=f"/{i}", detail=big)
        logs = sorted(p.name for p in Path(self.tmp.name).iterdir())
        self.assertEqual(logs, ["audit.log", "audit.log.1", "audit.log.2"])
        for p in Path(self.tmp.name).iterdir():
            self.assertLessEqual(p.stat().st_size, 1024 * 1024)
        rows, _ = audit.read(limit=1)
        self.assertEqual(rows[0]["path"], "/1999")

    def test_old_entries_are_not_shown(self):
        f = Path(self.tmp.name) / "audit.log"
        f.write_text(json.dumps({"ts": "2000-01-01T00:00:00+00:00", "kind": "access"}) + "\n")
        audit.record("access", path="/new")
        self.assertEqual([r.get("path") for r in audit.read()[0]], ["/new"])
        os.environ["VIEWER_AUDIT_DAYS"] = "0"           # no limit
        self.assertEqual(len(audit.read()[0]), 2)

    def test_off(self):
        os.environ["VIEWER_AUDIT"] = "false"
        audit.record("access", path="/")
        self.assertFalse((Path(self.tmp.name) / "audit.log").exists())

    def test_client_address(self):
        # Without trusted proxies: the connection's address, the header unverified.
        self.assertEqual(audit.client("192.168.1.208", "203.0.113.7"),
                         ("192.168.1.208", "203.0.113.7"))
        self.assertEqual(audit.client("192.168.1.208", ""), ("192.168.1.208", ""))
        os.environ["VIEWER_TRUSTED_PROXIES"] = "192.168.1.208, 10.0.0.0/8"
        self.assertEqual(audit.client("192.168.1.208", "203.0.113.7"), ("203.0.113.7", ""))
        # A forged first hop does not win: the last untrusted one does.
        self.assertEqual(audit.client("192.168.1.208", "1.2.3.4, 203.0.113.7, 10.1.1.1"),
                         ("203.0.113.7", ""))
        # From anyone else the header is not believed.
        self.assertEqual(audit.client("198.51.100.1", "203.0.113.7"),
                         ("198.51.100.1", "203.0.113.7"))

    def test_proxy_trusted_ips_are_used_too(self):
        os.environ["PROXY_TRUSTED_IPS"] = "172.30.0.0/24"
        self.assertEqual(audit.client("172.30.0.2", "203.0.113.9"), ("203.0.113.9", ""))


if __name__ == "__main__":
    unittest.main()
