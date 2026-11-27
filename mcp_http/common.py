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
