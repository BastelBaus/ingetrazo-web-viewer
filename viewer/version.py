# SPDX-License-Identifier: AGPL-3.0-or-later
"""Which build is running: this repo's version (``WEB_VIEWER_VERSION``,
baked in from the build arg ``WEB_VIEWER_REF``). Shown in the viewer's
footer and at ``/version``. (Which IngeTrazo the engines run is the
engine image's: ingetrazo-docker shows it in its own logs.)
"""
from __future__ import annotations

import functools
import os
import re

_SHA = re.compile(r"^[0-9a-f]{12,40}$")


def _short(ref: str) -> str:
    """A commit hash as its first 7 characters; tags and names as they are."""
    return ref[:7] if _SHA.match(ref) else ref


@functools.lru_cache(maxsize=1)
def info() -> dict:
    return {"ingetrazo_web_viewer": os.environ.get("WEB_VIEWER_VERSION", "").strip() or "dev"}


def text() -> str:
    """One line, e.g. ``ingetrazo-web-viewer 59269df``."""
    return f"ingetrazo-web-viewer {_short(info()['ingetrazo_web_viewer'])}"
