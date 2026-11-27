# SPDX-License-Identifier: AGPL-3.0-or-later
"""The viewer's own settings, changed by an admin at ``/admin`` and kept in
``<state>/site.json``: for now the title (the headline of the overview, the
login page and the browser tab). ``VIEWER_TITLE`` is the default an admin's
title replaces; *Default* goes back to it.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

DEFAULT_TITLE = os.environ.get("VIEWER_TITLE", "").strip() or "IngeTrazo"
MAX_TITLE = 80

_lock = threading.Lock()
_data: dict | None = None


def _file() -> Path:
    return Path(os.environ.get("INGETRAZO_STATE", "/state")) / "site.json"


def _load() -> dict:
    global _data
    if _data is None:
        try:
            raw = json.loads(_file().read_text(encoding="utf-8"))
            _data = raw if isinstance(raw, dict) else {}
        except (OSError, ValueError):
            _data = {}
    return _data


def title() -> str:
    with _lock:
        value = _load().get("title")
    return value if isinstance(value, str) and value.strip() else DEFAULT_TITLE


def set_title(value: str) -> str:
    """A new title; empty goes back to the default. Returns the title now."""
    value = " ".join((value or "").split())[:MAX_TITLE]
    with _lock:
        data = dict(_load())
        if value and value != DEFAULT_TITLE:
            data["title"] = value
        else:
            data.pop("title", None)
        f = _file()
        f.parent.mkdir(parents=True, exist_ok=True)
        tmp = f.with_suffix(".json.part")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
        tmp.replace(f)
        global _data
        _data = data
    return title()


def reset() -> None:
    """Forget what was read (tests)."""
    global _data
    with _lock:
        _data = None
