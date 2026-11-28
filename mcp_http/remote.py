# SPDX-License-Identifier: AGPL-3.0-or-later
"""IngeTrazo in other containers: the engines of the ingetrazo-docker image
(``engine`` command, https://github.com/BastelBaus/ingetrazo-docker). This
image has no IngeTrazo, no X server and no OpenGL of its own.

- The viewer: ``ENGINE_URLS`` (comma-separated, e.g.
  ``http://viewer-engine:8766``), one render engine per render worker. The
  files an engine writes land in the cache volume both mount at one path.
- The MCP gateway: ``MCP_ENGINE_URL``, one engine in ``mcp`` mode.

``ENGINE_TOKEN`` is the shared secret the engines check, or
``ENGINE_TOKEN_FILE`` where the engine wrote it (a volume both mount).

The engine's API (its side: ingetrazo-docker's mcp_http/engine_server.py):

``POST /call``  ``{"tool", "args", "timeout"?}`` → the IngeTrazo bridge's
  reply ``{"ok", "result" | "error"}``.
``POST /rpc``  one MCP JSON-RPC message (``ENGINE_MODE=mcp``) → its reply.
``GET /healthz``  ``{"status": "ok" | "busy" | ...}``.

``RemoteApp`` is one engine: ``start``, ``alive``, ``call``, ``handle`` and
``probe``.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

from pathlib import Path

from .common import ai_timeout, log

MIN_TOKEN = 16


def engine_token() -> str:
    """The shared secret: ``ENGINE_TOKEN``, or else the file
    ``ENGINE_TOKEN_FILE`` names (the engine makes it on its first start).
    "" when there is none yet."""
    token = os.environ.get("ENGINE_TOKEN", "").strip()
    if token:
        return token
    name = os.environ.get("ENGINE_TOKEN_FILE", "").strip()
    if not name:
        return ""
    try:
        return Path(name).read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return ""

#: How long the viewer waits for an engine to come up at start.
START_WAIT = float(os.environ.get("ENGINE_START_SECONDS") or 600)


def _need_token(what: str) -> None:
    if not (os.environ.get("ENGINE_TOKEN", "").strip()
            or os.environ.get("ENGINE_TOKEN_FILE", "").strip()):
        raise SystemExit(f"{what} needs ENGINE_TOKEN or ENGINE_TOKEN_FILE "
                         "(the engines' shared secret)")


def mcp_engine_url() -> str | None:
    """``MCP_ENGINE_URL``: the engine the MCP gateway forwards to."""
    url = os.environ.get("MCP_ENGINE_URL", "").strip().rstrip("/")
    if not url:
        return None
    if not url.startswith(("http://", "https://")):
        raise SystemExit(f"MCP_ENGINE_URL: {url!r} is not an http(s) URL")
    _need_token("MCP_ENGINE_URL")
    return url


def engine_urls() -> list[str]:
    raw = os.environ.get("ENGINE_URLS", "")
    urls = [u.strip().rstrip("/") for u in raw.split(",") if u.strip()]
    for u in urls:
        if not u.startswith(("http://", "https://")):
            raise SystemExit(f"ENGINE_URLS: {u!r} is not an http(s) URL")
    if len(urls) > 16:
        raise SystemExit("ENGINE_URLS: at most 16 engines")
    if urls:
        _need_token("ENGINE_URLS")
    return urls


class RemoteApp:
    """One render engine, reached over HTTP. One call at a time per engine
    (the renderer gives each worker its own engine)."""

    def __init__(self, url: str, token: str | None = None) -> None:
        self.url = url.rstrip("/")
        self.token = token if token is not None else engine_token()
        self.ready = False
        self._alive_at = 0.0
        self._alive = False
        # The engine's bridge answers "timed out" after its own limit; wait
        # a minute longer so that answer, not a socket timeout, arrives.
        self.timeout = max(ai_timeout() or 180.0, 180.0) + 60.0

    def __repr__(self) -> str:
        return f"RemoteApp({self.url})"

    def _health(self, timeout: float = 5.0) -> tuple[int, dict]:
        try:
            with urllib.request.urlopen(self.url + "/healthz", timeout=timeout) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read() or b"{}")
            except ValueError:
                return exc.code, {}
        except (OSError, ValueError) as exc:
            return 0, {"status": str(exc)}

    def start(self) -> None:
        """Waits until the engine answers its health probe; the service is
        no use without it, so a missing engine ends the container. (What it
        opens and whether it saves is the engine's own setting.)"""
        t0 = time.monotonic()
        last = None
        while time.monotonic() - t0 < START_WAIT:
            if len(self.token) < MIN_TOKEN:          # the engine writes it on start
                self.token = engine_token()
            status, body = self._health()
            if status == 200 and len(self.token) >= MIN_TOKEN:
                self.ready = True
                log(f"engine {self.url} ready after {time.monotonic() - t0:.1f}s")
                return
            if body.get("status") != last:
                last = body.get("status")
                log(f"waiting for engine {self.url}: {last or status}")
            time.sleep(2.0)
        raise SystemExit(f"engine {self.url} not ready after {START_WAIT:.0f}s")

    def alive(self) -> bool:
        """Health of the engine, asked at most every 10 s (the viewer's own
        /healthz asks often). ``busy`` counts as alive."""
        if not self.ready:
            return False
        now = time.monotonic()
        if now - self._alive_at > 10.0:
            status, _ = self._health(timeout=5.0)
            self._alive, self._alive_at = status == 200, now
        return self._alive

    def build(self) -> str | None:
        """The IngeTrazo build the engine runs, as its ``/healthz`` names it
        (``build``); None when it does not say."""
        _status, body = self._health(timeout=10.0)
        found = body.get("build")
        return str(found) if found else None

    def probe(self, max_busy: float = 0.0) -> tuple[int, dict]:
        """``/healthz`` of the service: the engine's own."""
        status, body = self._health(timeout=15.0)
        if status == 0:
            return 503, {"status": "engine not answering", "error": body.get("status")}
        return status, body

    def handle(self, msg: dict) -> dict | None:
        """One MCP JSON-RPC message through the engine (``mcp`` mode)."""
        req = urllib.request.Request(
            self.url + "/rpc", data=json.dumps(msg).encode(), method="POST",
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {self.token}"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read() or b"null")
        except urllib.error.HTTPError as exc:
            try:
                got = json.loads(exc.read() or b"{}")
            except ValueError:
                got = {}
            raise RuntimeError(got.get("error") or f"engine HTTP {exc.code}") from None
        except (OSError, ValueError) as exc:
            self._alive_at = 0.0
            raise RuntimeError(f"engine {self.url}: {exc}") from None

    def call(self, tool: str, args: dict | None = None,
             timeout: float | None = None) -> dict:
        body = {"tool": tool, "args": args or {}}
        if timeout is not None:
            body["timeout"] = timeout
        req = urllib.request.Request(
            self.url + "/call", data=json.dumps(body).encode(), method="POST",
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {self.token}"})
        wait = (timeout + 60.0) if timeout is not None else self.timeout
        try:
            with urllib.request.urlopen(req, timeout=wait) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as exc:
            try:
                got = json.loads(exc.read() or b"{}")
            except ValueError:
                got = {}
            return {"ok": False, "error": got.get("error") or f"engine HTTP {exc.code}"}
        except (OSError, ValueError) as exc:
            self._alive_at = 0.0                 # ask again at the next probe
            return {"ok": False, "error": f"engine {self.url}: {exc}"}
