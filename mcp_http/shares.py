# SPDX-License-Identifier: AGPL-3.0-or-later
"""Which folders a user may see and write: their shares.

A share is a path in the data folder – a model folder (``projects``), a
folder inside one (``projects/2026``) or a single model
(``projects/2026/house.igz``) – and an access: ``r`` (see the models),
``rw`` (also save and export into it, MCP only) or ``none`` (carve a
folder out of a wider share). ``*`` stands for every folder.

A share's path can also be a pattern, to include or exclude many folders
and files at once (#43). Patterns are paths from the data folder too:
``*`` matches within one folder name, ``?`` one character, ``**`` any
number of folders::

    **/private:none           every folder named "private", at any depth
    projects/*/plans:r        the "plans" folder of each project
    **/*.bak.igz:none         backup copies, wherever they are
    archive/20??/**:r         everything inside archive/2000 … archive/2099

A pattern that matches a folder covers everything inside it, like a plain
path does.

Which share decides: the most specific one, i.e. the one that starts to
cover the path at the deepest level (``projects/secret`` beats
``projects``, ``**/private`` on ``a/b/private/x.igz`` counts at level 3).
On the same level a plain path beats a pattern (an exception for one
folder beats a rule for many), and of two patterns the one that gives
less access wins. Without a share there is no access. A read-only model
folder (``MODEL_FOLDERS``) allows ``r`` at most, whatever the share says.

Admins have ``rw`` everywhere. Every other user has the shares an admin
gave them in the admin panel; until then, ``DEFAULT_SHARES`` (default
``*:r``: every folder, read). The guest is a user like the others.

``DEFAULT_SHARES`` is a list like ``MODEL_FOLDERS``: ``path:access``,
separated by ``;``, e.g. ``*:none; projects/public:r; **/drafts:none``.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from . import folders

ACCESS = ("none", "r", "rw")
ALL = "*"
_RANK = {a: n for n, a in enumerate(ACCESS)}


def clean_path(path: str) -> str:
    """A share's path as stored: /-separated from the data folder (maybe a
    pattern with ``*``, ``?`` or ``**``), or ``*``."""
    path = (path or "").strip().replace("\\", "/").strip("/")
    if path in ("", ALL):
        return ALL
    parts = path.split("/")
    if any(p in ("", ".", "..") or p.startswith(".") for p in parts):
        raise ValueError(f"not a folder path: {path!r}")
    if any("**" in p and p != "**" for p in parts):
        raise ValueError(f"{path!r}: ** stands alone between slashes (a/**/b)")
    return "/".join(parts)


def is_pattern(path: str) -> bool:
    """Whether a share's path is a pattern (``*`` alone is every folder)."""
    return path != ALL and any(c in path for c in "*?")


def parse(spec: str) -> list[dict]:
    """``path:access; …`` as a list of shares."""
    out: list[dict] = []
    for entry in re.split(r"[;\n]", spec or ""):
        entry = entry.strip()
        if not entry:
            continue
        path, _, access = entry.rpartition(":")
        if not path:
            path, access = entry, "r"
        access = access.strip().lower()
        if access not in ACCESS:
            raise ValueError(f"{entry!r}: the access is one of {', '.join(ACCESS)}")
        out.append({"path": clean_path(path), "access": access})
    return out


def defaults() -> list[dict]:
    try:
        return parse(os.environ.get("DEFAULT_SHARES", f"{ALL}:r"))
    except ValueError as exc:
        raise SystemExit(f"[ingetrazo-web-viewer] DEFAULT_SHARES: {exc}") from None


def validate(shares: list) -> list[dict]:
    """Shares as an admin sent them: cleaned, one per path (the last wins)."""
    seen: dict[str, str] = {}
    for s in shares or []:
        if not isinstance(s, dict) or s.get("access") not in ACCESS:
            raise ValueError("a share is a path and one of " + ", ".join(ACCESS))
        seen[clean_path(str(s.get("path", "")))] = s["access"]
    return [{"path": p, "access": a} for p, a in sorted(seen.items())]


def _level(share: str, rel: str) -> int | None:
    """The level (number of names from the data folder) at which ``share``
    starts to cover ``rel``; None: it does not cover it. ``*``: level 0."""
    if share == ALL:
        return 0
    if not is_pattern(share):
        if rel == share or rel.startswith(share + "/"):
            return share.count("/") + 1
        return None
    rx = folders.glob_re(share)
    parts = rel.split("/")
    for n in range(1, len(parts) + 1):
        if rx.match("/".join(parts[:n])):
            return n
    return None


def decide(shares: list[dict], rel: str) -> tuple[str, dict | None]:
    """What ``shares`` allow on ``rel`` (a path from the data folder), and
    the share that decided (None: no share covers it)."""
    best, key = None, None
    for s in shares:
        level = _level(s["path"], rel)
        if level is None:
            continue
        # Deeper first; on one level a plain path before a pattern, then
        # less access before more; among equals the later share.
        k = (level, not is_pattern(s["path"]), -_RANK[s["access"]])
        if key is None or k >= key:
            best, key = s, k
    return (best["access"] if best else "none"), best


def access(shares: list[dict], rel: str) -> str:
    """What ``shares`` allow on ``rel``: the most specific share decides."""
    return decide(shares, rel)[0]


def own_shares(account) -> list[dict]:
    """The shares that apply to a user: their own, or DEFAULT_SHARES."""
    return account.shares if account.shares is not None else defaults()


def effective(account, rel: str) -> str:
    """What a user (``mcp_http.users.Account``, None: nobody) may do with
    ``rel``, capped by the model folder's mode."""
    if account is None or not account.active:
        return "none"
    got = "rw" if account.admin else access(own_shares(account), rel)
    p = (folders.DATA_DIR / rel).resolve()
    folder = folders.folder_of(p)
    if folder is None:
        return "none"
    if got == "rw" and not folder.writable:
        got = "r"
    return got


def can_read(account, rel: str) -> bool:
    return _RANK[effective(account, rel)] >= _RANK["r"]


def can_write(account, rel: str) -> bool:
    return effective(account, rel) == "rw"


def tree(max_depth: int = 3, limit: int = 400) -> list[str]:
    """The folders an admin may share: each model folder and the folders
    inside it, ``max_depth`` levels deep, as paths from the data folder
    (``""`` is the data folder itself when it is the one model folder)."""
    out: list[str] = []
    for f in folders.FOLDERS:
        base = folders.display_name(f.root) if f.root != folders.DATA_DIR else ""
        if base:
            out.append(base)
        if not f.root.is_dir():
            continue
        inner: list[str] = []
        for here, dirs, _ in os.walk(f.root):
            rel_dir = Path(here).relative_to(f.root).as_posix()
            level = 0 if rel_dir == "." else rel_dir.count("/") + 1
            prefix = "" if rel_dir == "." else rel_dir + "/"
            dirs[:] = sorted(d for d in dirs if not f.excluded(prefix + d))
            inner.extend(folders.display_name(Path(here) / d) for d in dirs)
            if level + 1 >= max_depth:
                dirs[:] = []
            if len(out) + len(inner) >= limit:
                break
        # Each folder right above the folders in it (os.walk goes level by level).
        out.extend(sorted(inner, key=lambda p: p.split("/")))
        if len(out) >= limit:
            return out[:limit]
    return out
