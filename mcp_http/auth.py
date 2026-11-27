# SPDX-License-Identifier: AGPL-3.0-or-later
"""Who may call the MCP endpoint.

``MCP_AUTH``:

- ``none``  – anyone who reaches the port. Only for a trusted machine or LAN:
  ``run_python`` runs arbitrary Python inside the container.
- ``token`` – ``Authorization: Bearer <token>`` (Claude Code, Claude
  Desktop via mcp-remote, Cursor, VS Code, …): ``MCP_TOKEN`` (every
  right), or a user's personal token (made at the viewer's /account).
- ``oauth`` – a minimal OAuth 2.1 authorisation server for remote
  connectors such as claude.ai (see oauth.py).

A user of the user list (users.py) gets in only while they are switched
on and may use MCP, checked on every request; then they see and write
what their folders (shares.py) allow. ``MCP_TOKEN``, ``OAUTH_USER`` and
``none`` have every right, as before there was a user list.
"""
from __future__ import annotations

import hmac
import os
from dataclasses import dataclass

from .common import log
from .users import Account, Users

MODES = ("none", "token", "oauth")


@dataclass(frozen=True)
class Caller:
    """Who calls: a user of the list (``account``), or None for every right."""
    account: Account | None = None

    @property
    def restricted(self) -> bool:
        return self.account is not None and not self.account.admin

    @property
    def name(self) -> str:
        return self.account.name if self.account else "(full access)"


FULL = Caller()


class Auth:
    def __init__(self) -> None:
        self.mode = os.environ.get("MCP_AUTH", "token").strip().lower() or "token"
        if self.mode not in MODES:
            raise SystemExit(f"MCP_AUTH must be one of {', '.join(MODES)}, "
                             f"not {self.mode!r}")
        self.token = os.environ.get("MCP_TOKEN", "").strip()
        self.users = Users() if self.mode != "none" else None
        self.oauth = None
        if self.mode == "token" and self.token and len(self.token) < 16:
            raise SystemExit("MCP_TOKEN needs at least 16 characters "
                             "(e.g. `openssl rand -hex 32`)")
        if self.mode == "token" and not self.token:
            log("MCP_AUTH=token without MCP_TOKEN: only personal tokens of the user "
                "list get in (made at the viewer's /account)")
        if self.mode == "oauth":
            from .oauth import OAuthServer
            self.oauth = OAuthServer(self.users)
        if self.mode == "none":
            log("WARNING: MCP_AUTH=none — anyone who reaches this port can run "
                "arbitrary Python in the container (run_python). Use it only "
                "on a trusted machine or network.")

    def _user(self, name: str) -> Caller | None:
        acc = self.users.get(name) if self.users is not None else None
        return Caller(acc) if acc and acc.active and acc.mcp else None

    def caller(self, headers) -> Caller | None:
        """Who calls, or None: not let in."""
        if self.mode == "none":
            return FULL
        value = headers.get("Authorization", "")
        if not value.lower().startswith("bearer "):
            return None
        presented = value[7:].strip()
        if self.mode == "token":
            if self.token and hmac.compare_digest(presented.encode(), self.token.encode()):
                return FULL
            acc = self.users.by_token(presented) if presented else None
            return Caller(acc) if acc else None
        user = self.oauth.access_user(presented)
        if user is None:
            return None
        return FULL if user == "" else self._user(user)

    def check(self, headers) -> bool:
        return self.caller(headers) is not None

    def challenge(self, base_url: str) -> str:
        """The WWW-Authenticate header of a 401."""
        if self.mode == "oauth":
            return ('Bearer resource_metadata="'
                    f'{base_url}/.well-known/oauth-protected-resource"')
        return 'Bearer realm="ingetrazo"'
