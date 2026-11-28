# SPDX-License-Identifier: AGPL-3.0-or-later
"""The viewer's audit log: who opened what and when, logins, the admin
panel's changes, and errors – one JSON object per line in
``VIEWER_AUDIT_FILE`` (default ``/state/audit.log``), so it survives a
restart. Admins read it at ``/admin/log``.

Each entry has ``ts`` (UTC, ISO 8601), ``kind`` and, where it applies,
``user``, ``source`` (how they logged in), ``ip``, ``method``, ``path``,
``status``, ``ms`` and ``detail``. Kinds:

- ``access``: a page or API request (not ``/healthz``, rendered files,
  ``/static``, ``/events`` and avatars, which every page loads anyway);
- ``login`` / ``logout``: a login (password, guest, access link, OIDC),
  also a failed one;
- ``admin``: a change in the admin panel and its outcome;
- ``error``: a failed render, scan or login, an exception in a request.

The file is rotated at ``VIEWER_AUDIT_MAX_MB`` (10) and
``VIEWER_AUDIT_KEEP`` (5) old files are kept, so the log holds at most
about 60 MB; entries older than ``VIEWER_AUDIT_DAYS`` (90, ``0`` = no
limit) are dropped when the file rotates and are not shown. IP addresses
and user names are personal data: keep the days as short as you need.
``VIEWER_AUDIT=false`` turns it off.

The client's address: the connection's, or – when that is one of
``VIEWER_TRUSTED_PROXIES`` (or ``PROXY_TRUSTED_IPS``) – the last address
in ``X-Forwarded-For`` that is not a trusted proxy. From any other peer
the header is kept as ``fwd`` (unverified) next to the connection's address.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

KINDS = ("access", "login", "logout", "admin", "error")

#: Paths not logged as ``access``: loaded by every page, or health checks.
QUIET = ("/healthz", "/files/", "/static/", "/events", "/avatar/")

_lock = threading.Lock()
_TOKEN = re.compile(r"/t/[^\s?\"#]+")


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _int(name: str, default: int) -> int:
    try:
        return max(0, int(_env(name) or default))
    except ValueError:
        return default


def enabled() -> bool:
    return _env("VIEWER_AUDIT", "true").lower() not in ("0", "false", "no", "off")


def path() -> Path:
    state = Path(_env("INGETRAZO_STATE") or "/state")
    return Path(_env("VIEWER_AUDIT_FILE") or state / "audit.log")


def max_bytes() -> int:
    return _int("VIEWER_AUDIT_MAX_MB", 10) * 1024 * 1024


def keep() -> int:
    return _int("VIEWER_AUDIT_KEEP", 5)


def days() -> int:
    return _int("VIEWER_AUDIT_DAYS", 90)


def _networks() -> list:
    raw = _env("VIEWER_TRUSTED_PROXIES") or _env("PROXY_TRUSTED_IPS")
    nets = []
    for part in raw.split(","):
        part = part.strip()
        if part:
            try:
                nets.append(ipaddress.ip_network(part, strict=False))
            except ValueError:
                pass
    return nets


def _trusted(addr: str, nets: list) -> bool:
    try:
        ip = ipaddress.ip_address(addr.strip())
    except ValueError:
        return False
    return any(ip in n for n in nets)


def client(peer: str, forwarded: str) -> tuple[str, str]:
    """(the client's address, an unverified X-Forwarded-For or "")."""
    forwarded = (forwarded or "").strip()
    if not forwarded:
        return peer, ""
    nets = _networks()
    if not _trusted(peer, nets):
        return peer, forwarded[:200]
    for hop in reversed([h.strip() for h in forwarded.split(",") if h.strip()]):
        if not _trusted(hop, nets):
            return hop[:64], ""
    return peer, ""


def redact(text: str) -> str:
    """An access link's token never goes into the log."""
    return _TOKEN.sub("/t/…", text) if "/t/" in text else text


def record(kind: str, **fields) -> None:
    """Append one entry. Never raises: the log must not break a request."""
    if not enabled():
        return
    entry = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
             "kind": kind}
    for k, v in fields.items():
        if v is None or v == "":
            continue
        entry[k] = redact(v)[:2000] if isinstance(v, str) else v
    line = json.dumps(entry, ensure_ascii=False) + "\n"
    try:
        with _lock:
            f = path()
            f.parent.mkdir(parents=True, exist_ok=True)
            if f.exists() and f.stat().st_size + len(line) > max_bytes() > 0:
                _rotate(f)
            with f.open("a", encoding="utf-8") as out:
                out.write(line)
    except OSError:
        pass


def _rotate(f: Path) -> None:
    """audit.log → audit.log.1 → … → audit.log.<keep>; older ones go."""
    n = keep()
    for i in range(n, 0, -1):
        old = f.with_name(f"{f.name}.{i}")
        if i == n:
            old.unlink(missing_ok=True)
        elif old.exists():
            old.replace(f.with_name(f"{f.name}.{i + 1}"))
    if n:
        f.replace(f.with_name(f"{f.name}.1"))
    else:
        f.unlink(missing_ok=True)
    # Rotated files whose newest entry is past the days: gone.
    limit = days()
    if limit:
        cutoff = time.time() - limit * 86400
        for i in range(1, n + 1):
            old = f.with_name(f"{f.name}.{i}")
            try:
                if old.exists() and old.stat().st_mtime < cutoff:
                    old.unlink()
            except OSError:
                pass


def files() -> list[Path]:
    """The log files, newest first."""
    f = path()
    out = [f] if f.exists() else []
    for i in range(1, keep() + 1):
        old = f.with_name(f"{f.name}.{i}")
        if old.exists():
            out.append(old)
    return out


def _match(e: dict, kind: str, user: str, text: str, since: str) -> bool:
    if kind and e.get("kind") != kind:
        return False
    if user and str(e.get("user", "")).lower() != user.lower():
        return False
    if since and str(e.get("ts", "")) < since:
        return False
    if text:
        hay = " ".join(str(v) for v in e.values()).lower()
        if text.lower() not in hay:
            return False
    return True


def read(kind: str = "", user: str = "", text: str = "", since: str = "",
         offset: int = 0, limit: int = 200) -> tuple[list[dict], bool]:
    """Entries, newest first, that match; and whether there are more.
    ``since``: an ISO date or time (UTC); also cut at ``VIEWER_AUDIT_DAYS``."""
    if days():
        floor = (datetime.now(timezone.utc) - timedelta(days=days())).isoformat()
        since = max(since, floor) if since else floor
    found: list[dict] = []
    want = offset + limit + 1
    for f in files():
        try:
            lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in reversed(lines):
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if isinstance(e, dict) and _match(e, kind, user, text, since):
                found.append(e)
                if len(found) >= want:
                    return found[offset:offset + limit], True
    return found[offset:offset + limit], False


def users() -> list[str]:
    """Every user name in the log (for the filter), sorted."""
    names: set[str] = set()
    for f in files():
        try:
            for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
                m = re.search(r'"user": "((?:[^"\\]|\\.)*)"', line)
                if m:
                    names.add(json.loads(f'"{m.group(1)}"'))
        except (OSError, ValueError):
            continue
    return sorted(names, key=str.casefold)

