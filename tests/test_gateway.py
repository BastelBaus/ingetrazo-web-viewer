# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests of the MCP gateway over HTTP (mcp_http/server.py,
mcp_http/auth.py): the login modes, the Streamable HTTP transport, the
JSON-RPC edge cases and the path rules, with a fake engine behind it. No
container needed:

    python -m unittest discover -s tests -p "test_*.py"
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp_http import auth as mcp_auth  # noqa: E402
from mcp_http import folders, server  # noqa: E402
from mcp_http.users import Users  # noqa: E402

TOKEN = "gateway-token-0123456789"


class FakeApp:
    """IngeTrazo's MCP handler in the engine; records what reaches it."""

    def __init__(self) -> None:
        self.open: str | None = None
        self.seen: list[dict] = []
        self.fail = False

    def call(self, tool, args=None):
        if tool == "list_documents":
            docs = [{"document_id": "d1", "path": self.open}] if self.open else []
            return {"ok": True, "result": {"documents": docs}}
        return {"ok": False, "error": "no"}

    def handle(self, msg):
        if self.fail:
            raise RuntimeError("engine exploded")
        self.seen.append(msg)
        if "id" not in msg:
            return None
        method = msg.get("method")
        if method == "initialize":
            return {"jsonrpc": "2.0", "id": msg["id"], "result": {
                "protocolVersion": "2024-11-05", "serverInfo": {"name": "ingetrazo"}}}
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": msg["id"], "result": {"tools": [
                {"name": n} for n in ("open_document", "run_python", "shutdown",
                                      "list_documents", "query_model")]}}
        if method == "tools/call" and msg["params"]["name"] == "open_document":
            self.open = msg["params"]["arguments"]["path"]
        return {"jsonrpc": "2.0", "id": msg["id"], "result": {"content": [], "isError": False}}

    def probe(self, max_busy):
        return 200, {"status": "ok"}


class Base(unittest.TestCase):
    MODE = "token"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name).resolve()
        self.data = base / "data"
        for rel in ("work/m.igz", "lib/n.igz"):
            (self.data / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.data / rel).write_bytes(b"x")
        (base / "outside.igz").write_bytes(b"x")
        self.env = mock.patch.dict(os.environ, {
            "MCP_AUTH": self.MODE, "MCP_TOKEN": TOKEN, "USERS_DB": str(base / "users.db"),
            "MCP_ALLOWED_ORIGINS": "", "PUBLIC_URL": "", "DEFAULT_SHARES": ""})
        self.env.start()
        self.saved = (folders.DATA_DIR, folders.FOLDERS, getattr(server, "app", None),
                      getattr(server, "auth", None))
        folders.DATA_DIR = self.data
        folders.FOLDERS = folders.parse("work:rw; lib:ro", data_dir=self.data)
        self.users = Users(base / "users.db")
        with mock.patch.object(mcp_auth, "log"):
            server.auth = mcp_auth.Auth()
        server.app = self.app = FakeApp()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        folders.DATA_DIR, folders.FOLDERS, server.app, server.auth = self.saved
        self.env.stop()
        self.tmp.cleanup()

    def req(self, path="/mcp", body=None, headers=None, method=None, token=TOKEN):
        data = body if isinstance(body, bytes) or body is None else json.dumps(body).encode()
        h = {"Content-Type": "application/json", **(headers or {})}
        if token:
            h["Authorization"] = f"Bearer {token}"
        r = urllib.request.Request(self.url + path, data, h, method=method)
        try:
            with urllib.request.urlopen(r, timeout=10) as resp:
                raw = resp.read()
                return resp.status, dict(resp.headers), json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, dict(e.headers), json.loads(raw) if raw else None
            except ValueError:
                return e.code, dict(e.headers), raw

    def tool(self, name, token=TOKEN, **args):
        status, _, reply = self.req(body={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                          "params": {"name": name, "arguments": args}},
                                    token=token)
        self.assertEqual(status, 200, reply)
        result = reply["result"]
        return result.get("isError"), ((result.get("content") or [{}])[0].get("text") or "")


class TokenModeTest(Base):
    def test_who_gets_in(self):
        msg = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
        status, headers, _ = self.req(body=msg, token=None)
        self.assertEqual(status, 401)
        self.assertEqual(headers["WWW-Authenticate"], 'Bearer realm="ingetrazo"')
        for token in ("wrong", TOKEN[:-1], TOKEN + "x", "itz_made-up", " "):
            self.assertEqual(self.req(body=msg, token=token)[0], 401, token)
        for value in (TOKEN, f"Basic {TOKEN}", f"Token {TOKEN}"):
            status = self.req(body=msg, headers={"Authorization": value}, token=None)[0]
            self.assertEqual(status, 401, value)
        self.assertEqual(self.req(body=msg, headers={"Authorization": f"bearer {TOKEN}"},
                                  token=None)[0], 200)            # the scheme ignores case
        self.assertEqual(self.app.seen, [msg])

    def test_personal_tokens(self):
        self.users.create("anna", "anna-pass")
        self.users.set_rights("anna", mcp=True)
        token = self.users.create_token("anna")
        self.assertEqual(self.req(body={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                                  token=token)[0], 200)
        # A guest or access-link account never gets an MCP token through.
        acc, _ = self.users.create_link("Visitor")
        self.assertIsNone(server.auth.caller({"Authorization": "Bearer " + _}))

    def test_settings(self):
        for env, msg in (({"MCP_AUTH": "magic"}, "MCP_AUTH"),
                         ({"MCP_TOKEN": "short"}, "16")):
            with mock.patch.dict(os.environ, env), self.assertRaisesRegex(SystemExit, msg):
                mcp_auth.Auth()


class TransportTest(Base):
    def test_routes(self):
        self.assertEqual(self.req("/mcp", method="GET")[0], 405)
        self.assertEqual(self.req("/mcp", method="GET", token=None)[0], 401)
        self.assertEqual(self.req("/mcp", method="DELETE")[0], 405)
        self.assertEqual(self.req("/nowhere", method="GET")[0], 404)
        self.assertEqual(self.req("/nowhere", body={})[0], 404)
        self.assertEqual(self.req("/token", body={})[0], 404)      # no OAuth in token mode
        status, _, body = self.req("/healthz", token=None)
        self.assertEqual((status, body), (200, {"status": "ok"}))

    def test_initialize(self):
        status, headers, reply = self.req(body={
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18"}})
        self.assertEqual(reply["result"]["protocolVersion"], "2025-06-18")
        self.assertEqual(reply["result"]["serverInfo"]["name"], "ingetrazo-web-viewer")
        self.assertEqual(len(headers["Mcp-Session-Id"]), 32)
        _, _, reply = self.req(body={"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                     "params": {"protocolVersion": "1999-01-01"}})
        self.assertEqual(reply["result"]["protocolVersion"], "2024-11-05")   # the engine's

    def test_tools_list(self):
        _, _, reply = self.req(body={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        names = [t["name"] for t in reply["result"]["tools"]]
        self.assertNotIn("shutdown", names)
        self.assertEqual(names.count("list_documents"), 1)
        self.assertIn("run_python", names)

    def test_malformed(self):
        status, _, reply = self.req(body=b"{not json")
        self.assertEqual((status, reply["error"]["code"]), (400, -32700))
        for body in ([], [1], "x", 3, [{"id": 1}, "x"]):
            status, _, reply = self.req(body=body)
            self.assertEqual((status, reply["error"]["code"]), (400, -32600), body)
        self.assertEqual(self.app.seen, [])

    def test_notifications_and_responses(self):
        status, _, body = self.req(body={"jsonrpc": "2.0", "method": "notifications/initialized"})
        self.assertEqual((status, body), (202, None))
        status, _, body = self.req(body={"jsonrpc": "2.0", "id": 5, "result": {}})
        self.assertEqual((status, body), (202, None))
        self.assertEqual(len(self.app.seen), 1)

    def test_batch(self):
        status, _, reply = self.req(body=[
            {"jsonrpc": "2.0", "id": 1, "method": "ping"},
            {"jsonrpc": "2.0", "method": "notifications/x"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "shutdown", "arguments": {}}}])
        self.assertEqual(status, 200)
        self.assertEqual([r["id"] for r in reply], [1, 2])
        self.assertTrue(reply[1]["result"]["isError"])

    def test_engine_errors_become_json_rpc_errors(self):
        self.app.fail = True
        status, _, reply = self.req(body={"jsonrpc": "2.0", "id": 7, "method": "tools/list"})
        self.assertEqual((status, reply["id"], reply["error"]["code"]), (200, 7, -32603))
        status, _, _ = self.req(body={"jsonrpc": "2.0", "method": "notifications/x"})
        self.assertEqual(status, 202)

    def test_odd_tool_calls_do_not_crash(self):
        for params in ({"name": ["x"]}, {"name": "open_document", "arguments": ["x"]},
                       "params", {"name": None}):
            status, _, reply = self.req(body={"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                              "params": params})
            self.assertEqual(status, 200, params)
            self.assertEqual(reply["id"], 3)


class PathsTest(Base):
    def test_full_access_stays_in_the_model_folders(self):
        outside = str(Path(self.tmp.name) / "outside.igz")
        for name, args in (("open_document", {"path": outside}),
                           ("open_document", {"path": "../outside.igz"}),
                           ("open_document", {"path": "work/../../outside.igz"}),
                           ("open_document", {"path": "/etc/passwd"}),
                           ("open_document", {"path": "~/x.igz"}),
                           ("open_document", {"path": "work/missing.igz"}),
                           ("import_file", {"path": "/etc/passwd"}),
                           ("save_document", {"path": "lib/n.igz"}),         # read-only folder
                           ("export_pdf", {"path": "lib/x.pdf"}),
                           ("export_pdf", {"path": "/tmp/x.pdf"}),
                           ("render_sheet", {"path": "/tmp/x.png"}),
                           ("screenshot", {"path": "/tmp/x.png"})):
            err, text = self.tool(name, **args)
            self.assertTrue(err, (name, args, text))
        self.assertEqual(self.app.seen, [])
        self.assertFalse(self.tool("open_document", path="work/m.igz")[0])
        self.assertEqual(self.app.open, str(self.data / "work" / "m.igz"))   # made absolute

    def test_symlink_out_of_a_folder(self):
        try:
            (self.data / "work" / "link.igz").symlink_to(Path(self.tmp.name) / "outside.igz")
        except OSError:
            self.skipTest("no symlinks here")
        err, text = self.tool("open_document", path="work/link.igz")
        self.assertTrue(err)
        self.assertIn("outside", text)

    def test_saving_in_place_needs_a_writable_folder(self):
        self.tool("open_document", path="lib/n.igz")
        err, text = self.tool("save_document")
        self.assertTrue(err)
        self.assertIn("read-only", text)

    def test_restricted_user(self):
        self.users.create("anna", "anna-pass")
        self.users.set_rights("anna", mcp=True)
        self.users.set_shares("anna", [{"path": "work", "access": "r"}])
        anna = self.users.create_token("anna")
        self.assertTrue(self.tool("run_python", token=anna, code="1")[0])
        self.assertTrue(self.tool("open_document", token=anna, path="lib/n.igz")[0])
        self.assertFalse(self.tool("open_document", token=anna, path="work/m.igz")[0])
        self.assertTrue(self.tool("save_document", token=anna)[0])            # read only
        self.assertTrue(self.tool("export_pdf", token=anna, path="work/x.pdf")[0])
        # Someone with every right opens a model anna may not read.
        self.tool("open_document", path="lib/n.igz")
        err, text = self.tool("query_model", token=anna)
        self.assertTrue(err)
        self.assertIn("may not read", text)
        _, _, reply = self.req(body={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                     "params": {"name": "list_documents"}}, token=anna)
        listing = json.loads(reply["result"]["content"][0]["text"])
        self.assertEqual(listing["open_documents"],
                         [{"note": "a document you have no access to is open"}])
        self.assertNotIn("lib/n.igz", json.dumps(listing))


class NoneModeTest(Base):
    MODE = "none"

    def test_anyone_but_foreign_browser_pages(self):
        msg = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
        self.assertEqual(self.req(body=msg, token=None)[0], 200)
        for origin, want in (("https://evil.example", 403), ("http://localhost:6274", 200),
                             ("http://127.0.0.1", 200), ("null", 403),
                             ("http://localhost.evil.example", 403)):
            status = self.req(body=msg, headers={"Origin": origin}, token=None)[0]
            self.assertEqual(status, want, origin)
        with mock.patch.dict(os.environ, {"MCP_ALLOWED_ORIGINS": "https://app.example.org/"}):
            self.assertEqual(self.req(body=msg, headers={"Origin": "https://app.example.org"},
                                      token=None)[0], 200)


class OAuthModeChallengeTest(unittest.TestCase):
    def test_challenge_names_the_metadata(self):
        a = mcp_auth.Auth.__new__(mcp_auth.Auth)
        a.mode = "oauth"
        self.assertEqual(a.challenge("https://mcp.example.org"),
                         'Bearer resource_metadata="https://mcp.example.org/'
                         '.well-known/oauth-protected-resource"')


if __name__ == "__main__":
    unittest.main()
