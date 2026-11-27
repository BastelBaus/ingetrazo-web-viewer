# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests of the engine client (mcp_http/remote.py) and the gateway's
handler through it, against a fake engine: a real HTTP server that speaks
the engine's API (ingetrazo-docker's mcp_http/engine_server.py) with a fake
IngeTrazo behind it. No container needed:

    python -m unittest discover -s tests -p "test_*.py"
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp_http import remote  # noqa: E402

TOKEN = "test-token-0123456789abcdef"


class FakeEngine(BaseHTTPRequestHandler):
    """The engine's API: /healthz, /call (bridge calls), /rpc (MCP)."""
    up = True
    calls: list = []
    tools = [{"name": "query_model"}, {"name": "shutdown"}, {"name": "list_documents"}]

    def log_message(self, *a):
        return None

    def _json(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/healthz":
            return self._json(*((200, {"status": "ok"}) if self.up
                                else (503, {"status": "ingetrazo not running"})))
        return self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            return self._json(401, {"error": "unauthorized"})
        msg = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path == "/call":
            FakeEngine.calls.append((msg["tool"], msg.get("args"), msg.get("timeout")))
            if msg["tool"] == "shutdown":
                return self._json(403, {"ok": False, "error": "tool 'shutdown' is not available"})
            return self._json(200, {"ok": True, "result": {"tool": msg["tool"]}})
        if self.path == "/rpc":
            FakeEngine.calls.append(("rpc", msg, None))
            if "id" not in msg:
                return self._json(200, None)
            if msg.get("method") == "tools/list":
                return self._json(200, {"jsonrpc": "2.0", "id": msg["id"],
                                        "result": {"tools": FakeEngine.tools}})
            return self._json(200, {"jsonrpc": "2.0", "id": msg["id"],
                                    "result": {"echo": msg.get("method")}})
        return self._json(404, {"error": "not found"})


class SettingsTest(unittest.TestCase):
    def test_token_from_env_or_file(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "token"
            with mock.patch.dict(os.environ, {"ENGINE_TOKEN": "", "ENGINE_TOKEN_FILE": str(f)}):
                self.assertEqual(remote.engine_token(), "")         # not made yet
                f.write_text(TOKEN + "\n")
                self.assertEqual(remote.engine_token(), TOKEN)
            with mock.patch.dict(os.environ, {"ENGINE_TOKEN": " abc ", "ENGINE_TOKEN_FILE": str(f)}):
                self.assertEqual(remote.engine_token(), "abc")

    def test_urls(self):
        with mock.patch.dict(os.environ, {"ENGINE_URLS": "", "ENGINE_TOKEN": ""}):
            self.assertEqual(remote.engine_urls(), [])
        with mock.patch.dict(os.environ, {"ENGINE_URLS": "http://a:1/, http://b:2",
                                          "ENGINE_TOKEN": TOKEN}):
            self.assertEqual(remote.engine_urls(), ["http://a:1", "http://b:2"])
        with mock.patch.dict(os.environ, {"ENGINE_URLS": "a:1", "ENGINE_TOKEN": TOKEN}):
            with self.assertRaises(SystemExit):
                remote.engine_urls()
        with mock.patch.dict(os.environ, {"ENGINE_URLS": "http://a:1", "ENGINE_TOKEN": "",
                                          "ENGINE_TOKEN_FILE": ""}):
            with self.assertRaises(SystemExit):
                remote.engine_urls()
        with mock.patch.dict(os.environ, {"MCP_ENGINE_URL": "", "ENGINE_TOKEN": TOKEN}):
            self.assertIsNone(remote.mcp_engine_url())
        with mock.patch.dict(os.environ, {"MCP_ENGINE_URL": "http://e:8766/",
                                          "ENGINE_TOKEN": TOKEN}):
            self.assertEqual(remote.mcp_engine_url(), "http://e:8766")


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        FakeEngine.up = True
        FakeEngine.calls = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), FakeEngine)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def test_call(self):
        app = remote.RemoteApp(self.url, TOKEN)
        app.start()
        self.assertTrue(app.alive())
        self.assertEqual(app.call("list_sheets", {}), {"ok": True, "result": {"tool": "list_sheets"}})
        self.assertTrue(app.call("export_pdf", {"path": "/cache/s.pdf"}, timeout=5)["ok"])
        self.assertEqual(FakeEngine.calls[-1], ("export_pdf", {"path": "/cache/s.pdf"}, 5))

    def test_refused_and_wrong_token(self):
        reply = remote.RemoteApp(self.url, TOKEN).call("shutdown", {})
        self.assertFalse(reply["ok"])
        self.assertIn("not available", reply["error"])
        reply = remote.RemoteApp(self.url, "wrong-token-0123456789").call("list_sheets")
        self.assertIn("unauthorized", reply["error"])

    def test_engine_down_and_unreachable(self):
        app = remote.RemoteApp(self.url, TOKEN)
        app.ready = True
        FakeEngine.up = False
        self.assertFalse(app.alive())
        self.assertEqual(app.probe()[0], 503)
        reply = remote.RemoteApp("http://127.0.0.1:9", TOKEN).call("list_sheets")
        self.assertFalse(reply["ok"])
        self.assertIn("engine http://127.0.0.1:9", reply["error"])

    def test_rpc(self):
        app = remote.RemoteApp(self.url, TOKEN)
        reply = app.handle({"jsonrpc": "2.0", "id": 7, "method": "ping"})
        self.assertEqual(reply, {"jsonrpc": "2.0", "id": 7, "result": {"echo": "ping"}})
        self.assertIsNone(app.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        with self.assertRaises(RuntimeError):
            remote.RemoteApp(self.url, "wrong-token-0123456789").handle(
                {"jsonrpc": "2.0", "id": 1, "method": "ping"})

    def test_gateway(self):
        """mcp_http.server's handler with the engine as its app: the
        gateway's own list_documents is added, shutdown stays hidden."""
        from mcp_http import server
        with mock.patch.object(server, "app", remote.RemoteApp(self.url, TOKEN), create=True):
            reply = server._handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            names = [t["name"] for t in reply["result"]["tools"]]
            self.assertEqual(names, ["query_model", "list_documents"])
            hidden = server._handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                     "params": {"name": "shutdown", "arguments": {}}})
            self.assertTrue(hidden["result"]["isError"])
            self.assertFalse(any(c[0] == "rpc" and c[1].get("method") == "tools/call"
                                 for c in FakeEngine.calls))


if __name__ == "__main__":
    unittest.main()
