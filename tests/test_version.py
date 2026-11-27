# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests of the viewer's version line (viewer/version.py)."""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from viewer import version  # noqa: E402


class VersionTest(unittest.TestCase):
    def setUp(self):
        version.info.cache_clear()

    def tearDown(self):
        version.info.cache_clear()

    def test_commit_is_shortened(self):
        with mock.patch.dict(os.environ, {"WEB_VIEWER_VERSION": "59269dfb2d0d375cf4df4dc8610a3a00300c4081"}):
            self.assertEqual(version.info(), {
                "ingetrazo_web_viewer": "59269dfb2d0d375cf4df4dc8610a3a00300c4081"})
            self.assertEqual(version.text(), "ingetrazo-web-viewer 59269df")

    def test_tag_is_kept(self):
        with mock.patch.dict(os.environ, {"WEB_VIEWER_VERSION": "v1.2.0"}):
            self.assertEqual(version.text(), "ingetrazo-web-viewer v1.2.0")

    def test_nothing_known(self):
        with mock.patch.dict(os.environ, {"WEB_VIEWER_VERSION": ""}):
            self.assertEqual(version.text(), "ingetrazo-web-viewer dev")


class FooterTest(unittest.TestCase):
    def test_page_has_the_footer(self):
        from types import SimpleNamespace

        from viewer import server
        saved = getattr(server, "auth", None)
        server.auth = SimpleNamespace(mode="none")
        version.info.cache_clear()
        try:
            with mock.patch.dict(os.environ, {"WEB_VIEWER_VERSION": "v9.9"}):
                page = server._page("t", "<h1>t</h1>", "body").decode()
        finally:
            server.auth = saved
            version.info.cache_clear()
        self.assertIn('<footer class="ver">ingetrazo-web-viewer v9.9</footer>', page)


if __name__ == "__main__":
    unittest.main()
