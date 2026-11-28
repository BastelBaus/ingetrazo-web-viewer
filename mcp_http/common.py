# SPDX-License-Identifier: AGPL-3.0-or-later
"""Small helpers shared by the gateway and the viewer."""
from __future__ import annotations

import os
import sys

from .folders import DATA_DIR  # noqa: F401  (re-exported)


def log(msg: str) -> None:
    print(f"[ingetrazo-web-viewer] {msg}", file=sys.stderr, flush=True)


def env_flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def ai_timeout() -> float | None:
    """``INGETRAZO_AI_TIMEOUT`` in seconds, or None when unset/invalid: how
    long the engine's IngeTrazo may take for one call."""
    raw = os.environ.get("INGETRAZO_AI_TIMEOUT", "").strip()
    try:
        value = float(raw) if raw else 0.0
    except ValueError:
        return None
    return value if value > 0 else None


def must_close(handler, status: int) -> bool:
    """Whether a reply must end the connection: when the request's body may
    be left unread, which a kept-alive connection would otherwise parse as
    the next request (HTTP desync; behind a proxy that reuses connections,
    another user's reply). The handlers read the body of a POST they
    accept; everything else is not read: a refused or redirected POST, a
    body on any other method, and chunked bodies (not supported at all)."""
    headers = getattr(handler, "headers", None)
    if headers is None:
        return False
    if headers.get("Transfer-Encoding"):
        return True
    try:
        length = int(headers.get("Content-Length") or 0)
    except ValueError:
        return True
    if length <= 0:
        return False
    return handler.command != "POST" or status >= 300


def content_length(headers) -> int | None:
    """A request's Content-Length: 0 without one, None when it is not a
    number (a bad request, never a crash)."""
    raw = (headers.get("Content-Length") or "0").strip() if headers is not None else "0"
    if not raw.isdigit():
        return None
    return int(raw)
