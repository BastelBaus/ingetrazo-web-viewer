# SPDX-License-Identifier: AGPL-3.0-or-later
"""The long end-to-end checks of the full test against the compose stack
as shipped (tests/full.sh starts it): every item of the example model
rendered with VIEWER_PRERENDER=all and served, MCP through the gateway, and
the security of the real servers.

    python tests/full_viewer.py <viewer URL> <admin password> <MCP URL> <MCP token> <data dir>
"""
from __future__ import annotations

import base64
import json
import re
import socket
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlencode, urlsplit

VIEWER, PASSWORD = sys.argv[1].rstrip("/"), sys.argv[2]
MCP, TOKEN = sys.argv[3].rstrip("/"), sys.argv[4]
DATA = Path(sys.argv[5])
MAGIC = {"png": b"\x89PNG", "pdf": b"%PDF", "glb": b"glTF"}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


OPENER = urllib.request.build_opener(NoRedirect)
COOKIE = ""


def get(url, data=None, headers=None, timeout=60):
    h = {"Accept": "text/html", **({"Cookie": COOKIE} if COOKIE else {}), **(headers or {})}
    body = urlencode(data).encode() if isinstance(data, dict) else data
    try:
        with OPENER.open(urllib.request.Request(url, body, h), timeout=timeout) as r:
            return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


def mcp(msg, token=TOKEN):
    status, _, body = get(MCP + "/mcp", json.dumps(msg).encode(),
                          {"Content-Type": "application/json", "Accept": "application/json",
                           **({"Authorization": f"Bearer {token}"} if token else {})},
                          timeout=900)
    return status, json.loads(body) if body else None


def tool(name, **args):
    status, reply = mcp({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                         "params": {"name": name, "arguments": args}})
    assert status == 200, (name, status, reply)
    return reply["result"]


def ok(result: dict) -> dict:
    """A tool result that is no error (else its text in the assertion)."""
    assert not result.get("isError"), (result.get("content") or [{}])[0].get("text")
    return result


def check(name, fn):
    t0 = time.monotonic()
    fn()
    print(f"  ok  {name} ({time.monotonic() - t0:.1f}s)", flush=True)


def raw_http(base, data: bytes) -> bytes:
    u = urlsplit(base)
    with socket.create_connection((u.hostname, u.port), timeout=5) as s:
        s.sendall(data)
        got = b""
        try:
            while chunk := s.recv(65536):
                got += chunk
        except TimeoutError:
            pass
    return got


def main():
    global COOKIE
    print("== viewer (VIEWER_PRERENDER=all)")
    status, headers, _ = get(VIEWER + "/login", {"user": "admin", "password": PASSWORD,
                                                 "next": "/"})
    assert status == 303, status
    COOKIE = headers["Set-Cookie"].split(";")[0]

    def everything_rendered():
        deadline = time.monotonic() + 40 * 60
        busy = ('class="st queued"', 'class="st rendering"', 'class="st missing"',
                'class="st outdated"')
        while True:
            page = get(VIEWER + "/admin/renders")[2].decode()
            counts = re.findall(r"(\d+ / \d+) rendered", page)
            # Listed (its sheets are known), and nothing left to do; a 3D
            # model over VIEWER_GLB_MAX_MB counts as done ("skipped").
            if "?sheet=" in page and not any(b in page for b in busy):
                print(f"      {counts}")
                return page
            assert 'class="st failed"' not in page, "a render failed:\n" + re.sub(
                r"<[^>]+>", " ", page)[-3000:]
            assert time.monotonic() < deadline, f"not done after 40 minutes: {counts}"
            time.sleep(10)
    renders = {}
    check("every sheet, view, the PDF and the 3D model rendered",
          lambda: renders.setdefault("page", everything_rendered()))

    def served():
        page = renders["page"]
        links = sorted(set(re.findall(r'href="(/m/[A-Za-z0-9._-]+\?(?:sheet|view|3d|pdf)=\d+)"',
                                      page)))
        assert any("sheet=" in u for u in links) and any("pdf=" in u for u in links), links
        seen = 0
        for link in links:
            status, headers, body = get(VIEWER + link)
            if "pdf=" in link:
                assert status == 303, (link, status)
                urls = [headers["Location"]]
            else:
                assert status == 200, (link, status)
                urls = re.findall(r'["\'](/files/[A-Za-z0-9._/-]+\.(?:png|glb))["\']', body.decode())
                if "3d=" in link and not urls and b"VIEWER_GLB_MAX_MB" in body:
                    print("      the 3D model is over VIEWER_GLB_MAX_MB: left out")
                    continue
            assert urls, f"{link}: no file"
            for url in urls:
                status, headers, data = get(VIEWER + url)
                kind = url.rsplit(".", 1)[1]
                assert status == 200 and data[:4] == MAGIC[kind], (url, status, data[:8])
                assert "immutable" in headers["Cache-Control"]
                seen += 1
        print(f"      {len(links)} pages, {seen} files")
    check("each one served from /files and a real PNG, PDF or GLB", served)

    print("== MCP gateway")

    def protocol():
        status, reply = mcp({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                             "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                        "clientInfo": {"name": "full", "version": "0"}}})
        assert status == 200 and reply["result"]["protocolVersion"] == "2025-06-18", reply
        status, reply = mcp({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = {t["name"] for t in reply["result"]["tools"]}
        assert "shutdown" not in names and "list_documents" in names, names
        assert mcp({"jsonrpc": "2.0", "id": 3, "method": "ping"}, token=None)[0] == 401
        assert mcp({"jsonrpc": "2.0", "id": 3, "method": "ping"}, token=TOKEN + "x")[0] == 401
    check("initialize, tools/list without shutdown, 401 without the token", protocol)

    def work():
        listing = json.loads(tool("list_documents")["content"][0]["text"])
        paths = [d["path"] for f in listing["folders"] for d in f["documents"]]
        assert "arco.igz" in paths, paths
        ok(tool("open_document", path="arco.igz", discard_changes=True))
        ok(tool("export_pdf", path="full-out/plan.pdf", format="pdf"))
        assert (DATA / "full-out" / "plan.pdf").read_bytes()[:4] == b"%PDF"
        for name, args in (("open_document", {"path": "/etc/passwd"}),
                           ("export_pdf", {"path": "../outside.pdf"}),
                           ("shutdown", {})):
            assert tool(name, **args).get("isError"), name
    check("open, export into the data folder; outside paths and shutdown refused", work)

    print("== security of the running servers")

    def no_way_in():
        global COOKIE
        saved, COOKIE = COOKIE, ""
        try:
            for path in ("/", "/admin", "/admin/log.jsonl", "/account", "/version",
                         "/admin/renders", "/events"):
                assert get(VIEWER + path)[0] in (303, 401), path
            forged = base64.urlsafe_b64encode(json.dumps(
                {"u": "admin", "r": "admin", "s": "local", "e": 9999999999}).encode()).decode()
            assert get(VIEWER + "/admin", headers={"Cookie": f"itz_viewer={forged}.00"})[0] == 303
        finally:
            COOKIE = saved
    check("no page without a login, no forged session", no_way_in)

    def redirects():
        for bad in ("//evil.example", "/\t/evil.example", "/\r\nX-Injected: 1"):
            status, headers, _ = get(VIEWER + "/login", {"user": "admin", "password": PASSWORD,
                                                         "next": bad})
            assert status == 303 and headers["Location"] == "/", (bad, headers["Location"])
            assert headers.get("X-Injected") is None
    check("login redirects stay on the server, no header injection", redirects)

    def desync():
        inner = "GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n"
        for base, head in ((VIEWER, "POST /admin"), (MCP, "POST /mcp"), (MCP, "POST /register")):
            got = raw_http(base, f"{head} HTTP/1.1\r\nHost: x\r\nContent-Length: {len(inner)}"
                                 f"\r\n\r\n{inner}".encode())
            assert got.count(b"HTTP/1.1 ") == 1, (base, head, got[:300])
    check("an unread body never runs as a second request", desync)

    print("== full viewer test passed")


if __name__ == "__main__":
    main()
