# SPDX-License-Identifier: AGPL-3.0-or-later
"""The MCP gateway: MCP over Streamable HTTP for a headless IngeTrazo.

``POST /mcp`` takes JSON-RPC and answers with JSON (the stateless form of
the Streamable HTTP transport); ``GET /mcp`` offers no server-initiated
stream (405). ``GET /healthz`` is the container's health probe.

Every request goes to IngeTrazo's own MCP handler (scripts/ingetrazo_mcp.py)
in an engine (``MCP_ENGINE_URL``, an ingetrazo-docker container with
``ENGINE_MODE=mcp`` on an internal network), so the tools and their
descriptions are the app's. The gateway adds:
``list_documents`` (the model folders and their files), the confinement of
file paths to the model folders (writing only into read/write ones, see
folders.py), and hides ``shutdown`` (the container's lifetime is the
orchestrator's).

A caller who is a user of the user list (auth.py) and not an admin is
held to their folders (shares.py): they list, open and use only what they
may read, and save and export only where they may write. ``run_python``
(``ADMIN_TOOLS``) is not theirs: Python in the container reaches every
file, which would make the folders meaningless. There is one IngeTrazo
and one open document for every caller.

The users, OAuth and folder rights stay here; the engine knows only its
service token.
"""
from __future__ import annotations

import json
import os
import secrets
import sys
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from pathlib import Path

from . import folders, shares
from .common import DATA_DIR, content_length, log, must_close
from .auth import FULL, Auth, Caller
from .remote import RemoteApp, mcp_engine_url

#: Protocol revisions this server can speak; the tool and content shapes it
#: uses are the same in all of them.
KNOWN_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
HIDDEN_TOOLS = {"shutdown"}
#: Tools only callers with every right (admins, MCP_TOKEN) get.
ADMIN_TOOLS = {"run_python"}
#: Tools whose ``path`` argument names a file, confined to the model
#: folders: (writes it, must exist). A tool that writes needs a read/write
#: folder.
PATH_TOOLS = {"open_document": (False, True), "import_file": (False, True),
              "save_document": (True, False), "export_pdf": (True, False),
              "export_view": (True, False), "export_file": (True, False),
              "render_sheet": (True, False), "screenshot": (True, False)}

LIST_DOCUMENTS = {
    "name": "list_documents",
    "description": (
        "List the document open in IngeTrazo (open_documents: its "
        "document_id, which every other tool needs) and the model folders "
        "with their documents (.igz): size, modification time and which "
        "one is open. After open_document the document_id changes: use the "
        "one it returns, or call this again. Paths for open_document, "
        "save_document, import and the export tools are relative to the "
        "data folder, as listed here (e.g. <folder>/<file>.igz; absolute "
        "paths must lie inside it). A folder with mode 'ro' is read-only: "
        "save and export into an 'rw' one."),
    "inputSchema": {"type": "object", "properties": {}},
}

app: RemoteApp
auth: Auth
MAX_BUSY = float(os.environ.get("HEALTH_MAX_BUSY_SECONDS") or 900)
#: The largest MCP request body read (``MCP_MAX_BODY_MB``, default 16).
MAX_BODY = int(float(os.environ.get("MCP_MAX_BODY_MB") or 16) * 1_000_000)


def _text(result: object, is_error: bool = False) -> dict:
    text = result if isinstance(result, str) else json.dumps(
        result, indent=2, ensure_ascii=False)
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


def _open_path() -> tuple[list, str | None]:
    """IngeTrazo's own listing (the live document and its ids) and the
    open document's path."""
    reply = app.call("list_documents")
    live = ((reply.get("result") or {}).get("documents") or []
            if reply.get("ok") else [])
    return live, (live[0].get("path") if live else None)


def _rel(path) -> str | None:
    """A path as named from the data folder; None outside it."""
    try:
        return folders.display_name(Path(path).resolve())
    except (ValueError, OSError):
        return None


def _list_documents(caller: Caller = FULL) -> dict:
    """The live document and the model folders with their models (a
    restricted caller: those they may read)."""
    live, open_path = _open_path()
    acc = caller.account if caller.restricted else None
    if acc is not None and open_path and not shares.can_read(acc, _rel(open_path) or ""):
        live = [{"note": "a document you have no access to is open"}]
    groups = []
    for folder in folders.FOLDERS:
        docs = []
        mode = folder.mode
        if acc is not None:
            base = _rel(folder.root) or ""
            mode = shares.effective(acc, base or "*")
        for p in folder.models():
            if acc is not None and not shares.can_read(acc, folders.display_name(p)):
                continue
            try:
                st = p.stat()
            except OSError:
                continue
            docs.append({
                "path": folders.display_name(p),
                "size_bytes": st.st_size,
                "modified": datetime.fromtimestamp(
                    st.st_mtime, timezone.utc).isoformat(timespec="seconds"),
                "open": open_path is not None and str(p) == str(open_path),
            })
        if acc is not None and not docs and mode == "none":
            continue
        groups.append({"name": folder.name, "path": str(folder.root),
                       "mode": mode if acc is None else {"rw": "rw", "r": "ro"}.get(mode, "ro"),
                       "documents": docs})
    return _text({"open_documents": live, "data_folder": str(DATA_DIR),
                  "folders": groups})


def _allowed(caller: Caller, path, write: bool) -> None:
    """A restricted caller's folders (shares.py); PermissionError if not."""
    if not caller.restricted:
        return
    rel = _rel(path) or ""
    ok = (shares.can_write if write else shares.can_read)(caller.account, rel)
    if not ok:
        raise PermissionError(
            f"{caller.account.name} may not {'write' if write else 'read'} {rel or path}: "
            "ask an admin to share the folder" + (" with read & write" if write else ""))


def _confine(name: str, args: dict, caller: Caller = FULL) -> None:
    """Paths into the model folders (and the caller's); raises
    PermissionError or FileNotFoundError with a message for the agent."""
    write, must_exist = PATH_TOOLS[name]
    if args.get("path"):
        args["path"] = str(folders.resolve(str(args["path"]), write=write,
                                           must_exist=must_exist))
        _allowed(caller, args["path"], write)
    elif name == "save_document":
        # Saved to its own path: that must be in a read/write folder too.
        _, open_path = _open_path()
        if open_path:
            folders.resolve(str(open_path), write=True)
            _allowed(caller, open_path, True)


def _handle(msg: dict, caller: Caller = FULL) -> dict | None:
    method = msg.get("method")
    msg_id = msg.get("id")
    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name", "")
        args = dict(params.get("arguments") or {})
        if name in HIDDEN_TOOLS or (caller.restricted and name in ADMIN_TOOLS):
            return {"jsonrpc": "2.0", "id": msg_id,
                    "result": _text(f"{name} is not available"
                                    + (" to you" if name in ADMIN_TOOLS else " in the container"),
                                    is_error=True)}
        if name == "list_documents":
            return {"jsonrpc": "2.0", "id": msg_id, "result": _list_documents(caller)}
        try:
            if name in PATH_TOOLS:
                _confine(name, args, caller)
                msg = {**msg, "params": {**params, "arguments": args}}
            if caller.restricted and not (name == "open_document" and args.get("path")):
                # Every other tool works on the open document.
                _, open_path = _open_path()
                if open_path:
                    _allowed(caller, open_path, False)
        except (PermissionError, FileNotFoundError) as exc:
            return {"jsonrpc": "2.0", "id": msg_id,
                    "result": _text(str(exc), is_error=True)}
    reply = app.handle(msg)
    if reply is None:
        return None
    if method == "initialize":
        wanted = (msg.get("params") or {}).get("protocolVersion")
        result = reply.setdefault("result", {})
        if wanted in KNOWN_VERSIONS:
            result["protocolVersion"] = wanted
        result["serverInfo"] = {"name": "ingetrazo-web-viewer", "version": "0.1.0"}
    elif method == "tools/list":
        # The app's list_documents gives way to the container's, which
        # includes it.
        hidden = HIDDEN_TOOLS | {"list_documents"} | (ADMIN_TOOLS if caller.restricted else set())
        tools = [t for t in reply["result"]["tools"] if t.get("name") not in hidden]
        reply["result"]["tools"] = tools + [LIST_DOCUMENTS]
    return reply


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ingetrazo-web-viewer"

    # ---- plumbing -------------------------------------------------------------
    def log_message(self, fmt, *args):          # one quiet line per request
        if self.path != "/healthz":
            sys.stderr.write("[http] %s %s\n" % (self.address_string(),
                                                 fmt % args))

    def send_response(self, code, message=None):
        super().send_response(code, message)
        if must_close(self, code):
            self.send_header("Connection", "close")
            self.close_connection = True

    def send_header(self, keyword, value):
        """A header never carries a line break: input that reaches one (a
        redirect target) cannot start a header of its own."""
        if "\r" in str(value) or "\n" in str(value):
            raise ValueError(f"line break in the {keyword} header")
        super().send_header(keyword, value)

    def _send(self, status: int, body: bytes = b"",
              ctype: str = "application/json", headers: dict | None = None):
        self.send_response(status)
        if body or status not in (202, 204):
            self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _json(self, status: int, obj, headers: dict | None = None):
        self._send(status, json.dumps(obj).encode(), headers=headers)

    def base_url(self) -> str:
        public = os.environ.get("PUBLIC_URL", "").strip().rstrip("/")
        if public:
            return public
        host = self.headers.get("Host", f"localhost:{self.server.server_port}")
        return f"http://{host}"

    def _origin_ok(self) -> bool:
        """DNS-rebinding guard of the MCP spec: a browser page from a
        foreign origin must not reach an unauthenticated server."""
        origin = self.headers.get("Origin")
        if not origin or auth.mode != "none":
            return True
        allowed = {o.strip().rstrip("/") for o in
                   os.environ.get("MCP_ALLOWED_ORIGINS", "").split(",") if o.strip()}
        if origin.rstrip("/") in allowed:
            return True
        return (urlsplit(origin).hostname or "") in ("localhost", "127.0.0.1", "::1")

    def _authorised(self) -> Caller | None:
        caller = auth.caller(self.headers)
        if caller is not None:
            return caller
        self._json(401, {"error": "unauthorized"}, headers={
            "WWW-Authenticate": auth.challenge(self.base_url())})
        return None

    # ---- routes -------------------------------------------------------------
    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/healthz":
            status, body = app.probe(MAX_BUSY)
            return self._json(status, body)
        if auth.oauth is not None and auth.oauth.route(self, "GET"):
            return None
        if path == "/mcp":
            if not self._authorised():
                return None
            return self._send(405, headers={"Allow": "POST"})
        if path == "/":
            return self._send(200, b"IngeTrazo MCP server: POST /mcp\n",
                              "text/plain; charset=utf-8")
        return self._json(404, {"error": "not found"})

    def do_OPTIONS(self):
        """CORS preflight of the OAuth endpoints (a browser-based client
        such as the MCP Inspector registers and fetches tokens itself)."""
        if auth.oauth is not None and auth.oauth.route(self, "OPTIONS"):
            return None
        return self._json(404, {"error": "not found"})

    def do_DELETE(self):
        if urlsplit(self.path).path == "/mcp":
            return self._send(405, headers={"Allow": "POST"})
        return self._json(404, {"error": "not found"})

    def do_POST(self):
        path = urlsplit(self.path).path
        if auth.oauth is not None and auth.oauth.route(self, "POST"):
            return None
        if path != "/mcp":
            return self._json(404, {"error": "not found"})
        if not self._origin_ok():
            return self._json(403, {"error": "origin not allowed"})
        caller = self._authorised()
        if caller is None:
            return None
        length = content_length(self.headers)
        if length is None:
            return self._json(400, {"error": "bad Content-Length"})
        if length > MAX_BODY:
            return self._json(413, {"jsonrpc": "2.0", "id": None, "error": {
                "code": -32600, "message": f"request larger than {MAX_BODY // 1_000_000} MB "
                                           "(MCP_MAX_BODY_MB)"}})
        try:
            payload = json.loads(self.rfile.read(length) or b"null")
        except ValueError:
            return self._json(400, {"jsonrpc": "2.0", "id": None, "error": {
                "code": -32700, "message": "parse error"}})
        batch = isinstance(payload, list)
        messages = payload if batch else [payload]
        if not messages or not all(isinstance(m, dict) for m in messages):
            return self._json(400, {"jsonrpc": "2.0", "id": None, "error": {
                "code": -32600, "message": "invalid request"}})
        headers = {}
        replies = []
        for m in messages:
            if m.get("method") == "initialize":
                headers["Mcp-Session-Id"] = secrets.token_hex(16)
            if "method" not in m:           # a client's response: nothing to do
                continue
            try:
                r = _handle(m, caller)
            except Exception as exc:        # never drop the connection silently
                log(f"error handling {m.get('method')}: {exc!r}")
                r = None if m.get("id") is None else {
                    "jsonrpc": "2.0", "id": m.get("id"),
                    "error": {"code": -32603, "message": str(exc)}}
            if r is not None:
                replies.append(r)
        if not replies:
            return self._send(202, headers=headers)
        return self._json(200, replies if batch else replies[0], headers)


def main() -> None:
    global app, auth
    auth = Auth()
    engine = mcp_engine_url()
    if not engine:
        raise SystemExit("MCP_ENGINE_URL must name the engine (an ingetrazo-docker "
                         "container with ENGINE_MODE=mcp), e.g. http://mcp-engine:8766")
    app = RemoteApp(engine)
    port = int(os.environ.get("MCP_PORT", 8765))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    server.daemon_threads = True
    # Listen first, so /healthz says "starting" while IngeTrazo opens.
    import threading
    threading.Thread(target=server.serve_forever, name="http",
                     daemon=True).start()
    log(f"MCP endpoint on :{port}/mcp (auth: {auth.mode}, engine {engine}); "
        "model folders: " + "; ".join(f.describe() for f in folders.FOLDERS))
    app.start()                 # the engine opens INGETRAZO_MODEL, saves or not
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
