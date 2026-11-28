# SPDX-License-Identifier: AGPL-3.0-or-later
"""Who may see the viewer: ``VIEWER_AUTH_MODE`` (or ``AUTH_MODE``).

- ``local`` (default) – the built-in login: the users of the user list
  (mcp_http/users.py) with a password, managed by admins at ``/admin``.
  ``ADMIN_USER`` (default ``admin``) / ``ADMIN_PASSWORD`` make the first
  admin while there is none (the older ``VIEWER_USER`` / ``VIEWER_PASSWORD``
  still work). A login page and a session cookie for browsers, Basic auth for
  scripts. Without any admin and without a password the viewer does not
  start.
- ``none``   – no login at all, on purpose; a warning in the log.
- ``oidc``   – OpenID Connect (Authentik, Keycloak, …): authorisation code
  flow with PKCE, then the viewer's own session cookie.
- ``proxy``  – a reverse proxy with forward auth (Traefik / nginx with
  Authentik) has logged the user in and names them in a header; only
  requests from ``PROXY_TRUSTED_IPS`` are believed.

Access links (``local`` and ``oidc``): an admin names one in the admin
panel and hands out its link, ``/t/<token>``; opening it logs the browser in
as that account (viewer only, its own folders). Scripts can send the token
as ``Authorization: Bearer itv_…``. The session carries the token's id, so
replacing or removing the link, switching it off or its expiry ends it.

``oidc`` and ``proxy`` add a user to the user list on first login, as
``user``; with an admin group set (``OIDC_ADMIN_GROUP`` /
``PROXY_ADMIN_GROUP``) the group decides who is ``admin``, else the admin
panel does. An admin may switch a user off there. Every request checks the
list, so that takes effect at once.

The ID token comes straight from the provider's token endpoint over TLS,
with the client secret, so its signature is not checked (OpenID Connect
Core 3.1.3.7); issuer, audience, expiry and nonce are.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

from mcp_http.common import log
from mcp_http.users import Account, UserError, Users

MODES = ("local", "none", "oidc", "proxy")
STATE_DIR = Path(os.environ.get("INGETRAZO_STATE", "/state"))


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _flag(name: str) -> bool:
    return _env(name).lower() in ("1", "true", "yes", "on")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@dataclass(frozen=True)
class User:
    name: str
    role: str = "user"            # "admin" or "user"
    source: str = "local"
    key: str = ""                 # access links: the id of the token used

    @property
    def admin(self) -> bool:
        return self.role == "admin"

    @classmethod
    def of(cls, acc: Account, key: str = "") -> "User":
        return cls(acc.name, acc.role, acc.source, key)


class Sessions:
    """Signed session cookies: ``<payload>.<hmac>``. The key is new on every
    start, so a restart logs everyone out. Each session has an id; logging
    out revokes it here, so a copy of the cookie ends with it (kept in
    memory until the session would have expired: the next start makes a
    new key anyway)."""

    def __init__(self, days: int) -> None:
        self.key = secrets.token_bytes(32)
        self.max_age = days * 86400
        self._revoked: dict[str, float] = {}
        self._lock = threading.Lock()

    def _sig(self, payload: str) -> str:
        return hmac.new(self.key, payload.encode(), hashlib.sha256).hexdigest()

    def issue(self, user: User) -> str:
        data = {"u": user.name, "r": user.role, "s": user.source,
                "e": int(time.time()) + self.max_age, "i": secrets.token_hex(8)}
        if user.key:
            data["k"] = user.key
        payload = _b64(json.dumps(data).encode())
        return f"{payload}.{self._sig(payload)}"

    def _data(self, value: str) -> dict | None:
        """The signed, unexpired, not revoked payload of a cookie value."""
        payload, _, sig = value.partition(".")
        if not payload or not hmac.compare_digest(sig.encode(), self._sig(payload).encode()):
            return None
        try:
            data = json.loads(_unb64(payload))
        except ValueError:
            return None
        if not isinstance(data, dict):
            return None
        try:
            if int(data.get("e", 0)) < time.time():
                return None
        except (TypeError, ValueError):
            return None
        with self._lock:
            if str(data.get("i", "")) in self._revoked:
                return None
        return data

    def read(self, value: str) -> User | None:
        data = self._data(value)
        if data is None:
            return None
        return User(str(data.get("u", "")), str(data.get("r", "user")),
                    str(data.get("s", "local")), str(data.get("k", "")))

    def revoke(self, value: str) -> bool:
        """Logout: this session ends, wherever a copy of its cookie is."""
        data = self._data(value)
        if data is None or not data.get("i"):
            return False
        now = time.time()
        with self._lock:
            for k in [k for k, exp in self._revoked.items() if exp < now]:
                del self._revoked[k]
            self._revoked[str(data["i"])] = float(data["e"])
        return True

    def csrf(self, name: str) -> str:
        """The token a form of this user's pages carries (admin, account)."""
        return hmac.new(self.key, b"csrf:" + name.encode(), hashlib.sha256).hexdigest()[:32]


class Throttle:
    """Wrong passwords and access links per client address
    (``VIEWER_LOGIN_LIMIT`` in ``VIEWER_LOGIN_WINDOW`` seconds; default 10
    in 15 minutes, 0: no limit). Past the limit that address may not try,
    not even with the right password, until the oldest failure is out of
    the window. The address is the one the audit log names: behind a proxy
    set ``VIEWER_TRUSTED_PROXIES``, else every user shares the proxy's."""

    MAX_KEYS = 10000

    def __init__(self) -> None:
        try:
            self.limit = max(0, int(_env("VIEWER_LOGIN_LIMIT") or 10))
            self.window = max(1, int(_env("VIEWER_LOGIN_WINDOW") or 900))
        except ValueError:
            raise SystemExit("VIEWER_LOGIN_LIMIT and VIEWER_LOGIN_WINDOW must be "
                             "whole numbers") from None
        self._fails: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _recent(self, key: str, now: float) -> list[float]:
        fails = [t for t in self._fails.get(key, []) if t > now - self.window]
        if fails:
            self._fails[key] = fails
        else:
            self._fails.pop(key, None)
        return fails

    def wait(self, key: str) -> int:
        """Seconds until ``key`` may try again; 0: now."""
        if not self.limit:
            return 0
        now = time.time()
        with self._lock:
            fails = self._recent(key, now)
            if len(fails) < self.limit:
                return 0
            return max(1, int(fails[-self.limit] + self.window - now) + 1)

    def failed(self, key: str) -> None:
        if not self.limit:
            return
        now = time.time()
        with self._lock:
            if len(self._fails) >= self.MAX_KEYS and key not in self._fails:
                for k in list(self._fails):
                    self._recent(k, now)
                if len(self._fails) >= self.MAX_KEYS:   # still full: forget the oldest
                    oldest = min(self._fails, key=lambda k: self._fails[k][-1])
                    del self._fails[oldest]
            self._fails.setdefault(key, []).append(now)
            self._fails[key] = self._fails[key][-self.limit:]


class OIDC:
    """The relying party of the authorisation code flow with PKCE."""

    def __init__(self) -> None:
        self.issuer = _env("OIDC_ISSUER_URL").rstrip("/")
        self.client_id = _env("OIDC_CLIENT_ID")
        self.client_secret = _env("OIDC_CLIENT_SECRET")
        self.redirect_uri = _env("OIDC_REDIRECT_URI")
        self.scopes = _env("OIDC_SCOPES") or "openid profile email"
        self.user_claim = _env("OIDC_USERNAME_CLAIM") or "preferred_username"
        self.groups_claim = _env("OIDC_GROUPS_CLAIM") or "groups"
        self.admin_group = _env("OIDC_ADMIN_GROUP")
        missing = [n for n, v in (("OIDC_ISSUER_URL", self.issuer),
                                  ("OIDC_CLIENT_ID", self.client_id),
                                  ("OIDC_CLIENT_SECRET", self.client_secret),
                                  ("OIDC_REDIRECT_URI", self.redirect_uri)) if not v]
        if missing:
            raise SystemExit("VIEWER_AUTH_MODE=oidc needs " + ", ".join(missing))
        if "openid" not in self.scopes.split():
            raise SystemExit("OIDC_SCOPES must include openid")
        if urlsplit(self.redirect_uri).path != "/auth/callback":
            raise SystemExit("OIDC_REDIRECT_URI must end in /auth/callback "
                             "(e.g. https://viewer.example.org/auth/callback)")
        insecure = [n for n, v in (("OIDC_ISSUER_URL", self.issuer),
                                   ("OIDC_REDIRECT_URI", self.redirect_uri))
                    if not v.startswith("https://")]
        if insecure and not _flag("OIDC_ALLOW_HTTP"):
            raise SystemExit(", ".join(insecure) + " must be https:// (the ID "
                             "token's signature is not checked; TLS is what "
                             "vouches for it). OIDC_ALLOW_HTTP=true for a lab.")
        self._meta: dict | None = None
        self._pending: dict[str, dict] = {}
        self._lock = threading.Lock()

    # ---- the provider ----------------------------------------------------------
    @staticmethod
    def _json(req: Request | str, timeout: float = 10.0) -> dict:
        with urlopen(req, timeout=timeout) as r:      # noqa: S310 — configured URL
            data = json.loads(r.read())
        if not isinstance(data, dict):
            raise ValueError("not a JSON object")
        return data

    def meta(self) -> dict:
        """The provider's discovery document, read on first use (the
        provider may start after the viewer)."""
        if self._meta is None:
            meta = self._json(self.issuer + "/.well-known/openid-configuration")
            for key in ("issuer", "authorization_endpoint", "token_endpoint"):
                if not meta.get(key):
                    raise ValueError(f"the discovery document has no {key}")
            if meta["issuer"].rstrip("/") != self.issuer:
                raise ValueError(f"issuer mismatch: {meta['issuer']!r}")
            self._meta = meta
        return self._meta

    # ---- the flow ------------------------------------------------------------------
    def start(self, nxt: str) -> str:
        """Where to send the browser to log in."""
        state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        verifier = secrets.token_urlsafe(48)
        now = time.time()
        with self._lock:
            for k in [k for k, v in self._pending.items() if v["t"] < now - 600]:
                del self._pending[k]
            if len(self._pending) > 1000:          # a flood of unfinished logins
                self._pending.clear()
            self._pending[state] = {"nonce": nonce, "verifier": verifier,
                                    "next": nxt, "t": now}
        challenge = _b64(hashlib.sha256(verifier.encode()).digest())
        return self.meta()["authorization_endpoint"] + "?" + urlencode({
            "response_type": "code", "client_id": self.client_id,
            "redirect_uri": self.redirect_uri, "scope": self.scopes,
            "state": state, "nonce": nonce,
            "code_challenge": challenge, "code_challenge_method": "S256"})

    def finish(self, code: str, state: str) -> tuple[str, list[str], str]:
        """The callback: (user name, groups, where to go next). ValueError
        when anything does not add up."""
        with self._lock:
            pending = self._pending.pop(state, None)
        if pending is None or pending["t"] < time.time() - 600:
            raise ValueError("unknown or expired login; start again")
        meta = self.meta()
        basic = base64.b64encode(
            f"{_quote(self.client_id)}:{_quote(self.client_secret)}".encode()).decode()
        tokens = self._json(Request(
            meta["token_endpoint"],
            data=urlencode({"grant_type": "authorization_code", "code": code,
                            "redirect_uri": self.redirect_uri,
                            "code_verifier": pending["verifier"]}).encode(),
            headers={"Authorization": f"Basic {basic}",
                     "Content-Type": "application/x-www-form-urlencoded",
                     "Accept": "application/json"}))
        claims = self._id_claims(tokens.get("id_token", ""), pending["nonce"])
        if (self.user_claim not in claims or self.groups_claim not in claims) \
                and tokens.get("access_token") and meta.get("userinfo_endpoint"):
            info = self._json(Request(meta["userinfo_endpoint"], headers={
                "Authorization": f"Bearer {tokens['access_token']}",
                "Accept": "application/json"}))
            if info.get("sub") == claims.get("sub"):
                claims = {**info, **claims}
        name = str(claims.get(self.user_claim) or claims.get("email")
                   or claims.get("sub") or "")
        if not name:
            raise ValueError("the provider named no user")
        groups = claims.get(self.groups_claim) or []
        groups = [str(g) for g in groups] if isinstance(groups, list) else [str(groups)]
        return name, groups, pending["next"]

    def _id_claims(self, token: str, nonce: str) -> dict:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("no ID token")
        claims = json.loads(_unb64(parts[1]))
        aud = claims.get("aud")
        auds = aud if isinstance(aud, list) else [aud]
        if claims.get("iss", "").rstrip("/") != self.issuer:
            raise ValueError("ID token from another issuer")
        if self.client_id not in auds or (len(auds) > 1 and claims.get("azp") != self.client_id):
            raise ValueError("ID token for another client")
        if int(claims.get("exp", 0)) < time.time() - 60:
            raise ValueError("ID token expired")
        if not hmac.compare_digest(str(claims.get("nonce", "")).encode(), nonce.encode()):
            raise ValueError("ID token nonce mismatch")
        return claims

    def end_session(self) -> str | None:
        try:
            return self.meta().get("end_session_endpoint") or None
        except (OSError, ValueError):
            return None


def _quote(text: str) -> str:
    """client_secret_basic form-encodes id and secret (RFC 6749 2.3.1)."""
    from urllib.parse import quote_plus
    return quote_plus(text)


class Proxy:
    """Forward auth: the user (and groups) a trusted proxy puts in headers."""

    def __init__(self) -> None:
        self.user_header = _env("PROXY_USER_HEADER") or "X-authentik-username"
        self.groups_header = _env("PROXY_GROUPS_HEADER")
        self.admin_group = _env("PROXY_ADMIN_GROUP")
        self.logout_url = _env("PROXY_LOGOUT_URL")
        raw = [p.strip() for p in _env("PROXY_TRUSTED_IPS").split(",") if p.strip()]
        if not raw:
            raise SystemExit("VIEWER_AUTH_MODE=proxy needs PROXY_TRUSTED_IPS: the "
                             "proxy's address(es) or networks, e.g. 172.18.0.0/16 — "
                             "a user header from anywhere else is ignored")
        try:
            self.trusted = [ipaddress.ip_network(p, strict=False) for p in raw]
        except ValueError as exc:
            raise SystemExit(f"PROXY_TRUSTED_IPS: {exc}") from None

    def trusts(self, addr: str) -> bool:
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        return any(ip in net for net in self.trusted)

    def user(self, addr: str, headers) -> tuple[str, list[str]] | None:
        if not self.trusts(addr):
            return None
        name = (headers.get(self.user_header) or "").strip()
        if not name:
            return None
        groups: list[str] = []
        if self.groups_header:
            raw = headers.get(self.groups_header) or ""
            sep = "|" if "|" in raw else ","        # Authentik joins with "|"
            groups = [g.strip() for g in raw.split(sep) if g.strip()]
        return name, groups


class Auth:
    def __init__(self) -> None:
        raw = _env("VIEWER_AUTH_MODE") or _env("AUTH_MODE") or "local"
        self.mode = raw.lower()
        if self.mode not in MODES:
            raise SystemExit(f"VIEWER_AUTH_MODE must be one of {', '.join(MODES)}, "
                             f"not {raw!r}")
        self.sessions = Sessions(int(_env("VIEWER_SESSION_DAYS") or 30))
        self.throttle = Throttle()
        # ADMIN_USER / ADMIN_PASSWORD; the older VIEWER_USER / VIEWER_PASSWORD
        # still work, so an update locks nobody out.
        self.user_name = _env("ADMIN_USER") or _env("VIEWER_USER") or "admin"
        password = os.environ.get("ADMIN_PASSWORD", "") or os.environ.get("VIEWER_PASSWORD", "")
        old = [k for k in ("VIEWER_USER", "VIEWER_PASSWORD") if _env(k)
               and not _env(k.replace("VIEWER_", "ADMIN_"))]
        self.oidc = OIDC() if self.mode == "oidc" else None
        self.proxy = Proxy() if self.mode == "proxy" else None
        self.users = Users() if self.mode != "none" else None
        if self.users is not None:
            added = self.users.import_json(STATE_DIR / "users.json")
            if added:
                log(f"viewer: {added} user(s) taken over from users.json")
        if self.mode == "local":
            if password and self.users.ensure_admin(self.user_name, password):
                log(f"viewer: first admin {self.user_name!r} from ADMIN_USER / ADMIN_PASSWORD")
            # The owner: always an admin, restored on every start.
            if self.users.protect_owner(self.user_name):
                log(f"viewer: owner {self.users.owner!r} (ADMIN_USER)")
            if old:
                log(f"viewer: {' / '.join(old)} is the old name; "
                    + " / ".join(k.replace("VIEWER_", "ADMIN_") for k in old) + " is the new one")
            if not self.users.active_admins():
                raise SystemExit(
                    "the viewer's login (VIEWER_AUTH_MODE=local, the default) needs "
                    "ADMIN_PASSWORD for its first admin. For a viewer without any "
                    "login, say so: VIEWER_AUTH_MODE=none")
        # "Log in as guest": one guest user (mcp_http/users.py GUEST) for
        # whoever does not log in, with a login page to offer it on.
        self.guest = _flag("VIEWER_GUEST")
        if self.guest and self.mode not in ("local", "oidc"):
            log(f"viewer: VIEWER_GUEST is for the local and oidc logins, not {self.mode}; ignored")
            self.guest = False
        if self.guest:
            acc = self.users.ensure_guest()
            log("viewer: guests may log in" + ("" if acc.active else
                " (but the guest user is switched off in the admin panel)"))
        if self.mode == "none":
            log("WARNING: VIEWER_AUTH_MODE=none — anyone who reaches the viewer "
                "sees every model in the data folder. Use it only on a trusted "
                "network or for a public showcase.")

    def describe(self) -> str:
        if self.mode == "oidc":
            return f"oidc, issuer {self.oidc.issuer}"
        if self.mode == "proxy":
            return (f"proxy, user from {self.proxy.user_header}, trusted "
                    + ", ".join(str(n) for n in self.proxy.trusted))
        return self.mode

    @property
    def admin_group(self) -> str:
        return (self.oidc.admin_group if self.oidc else
                self.proxy.admin_group if self.proxy else "")

    def login(self, name: str, pw: str) -> User | None:
        """``local``: the user whose password this is."""
        if self.mode != "local":
            return None
        acc = self.users.authenticate(name, pw)
        return User.of(acc) if acc and acc.web else None

    def guest_login(self) -> User | None:
        """``VIEWER_GUEST``: the guest user, unless an admin switched it off."""
        if not self.guest:
            return None
        acc = self.users.guest()
        return User.of(acc) if acc and acc.web else None

    @property
    def links(self) -> bool:
        """Whether access links work: with the viewer's own sessions."""
        return self.mode in ("local", "oidc")

    def link_login(self, token: str) -> User | None:
        """An access link's token: its account, if it may in now."""
        if not self.links or self.users is None:
            return None
        found = self.users.by_link(token.strip())
        return None if found is None else User.of(*found)

    def current(self, user: User) -> User | None:
        """A session's user as the list has them now: None when removed or
        switched off, with the role they have now."""
        if self.users is None:
            return user
        acc = self.users.get(user.name)
        if acc and acc.source == "guest" and not self.guest:
            return None                       # guests no longer welcome
        if (acc and acc.source == "link") or user.source == "link":
            # The same link, still usable; a password session never becomes one.
            ok = (self.links and user.source == "link" and user.key
                  and self.users.link_usable(acc, user.key))
            return User.of(acc, user.key) if ok else None
        return User.of(acc) if acc and acc.active and acc.web else None

    def settings(self, user: User | None) -> dict:
        """The settings ``user`` works with (mcp_http/users.py SETTINGS)."""
        acc = self.users.get(user.name) if self.users is not None and user else None
        return Users.settings_of(acc)

    def disabled(self, name: str) -> bool:
        """A known user who may not in: switched off, or no web viewer."""
        acc = self.users.get(name) if self.users is not None and name else None
        return bool(acc and (not acc.active or not acc.web or acc.expired))

    def _seen(self, name: str, groups: list[str], source: str) -> User | None:
        group = self.admin_group
        try:
            acc = self.users.seen(name, source, groups,
                                  (group in groups) if group else None)
        except UserError as exc:
            log(f"viewer: {source} user {name!r} refused: {exc}")
            return None
        if acc.source != source:
            log(f"viewer: {name!r} came through {source} but is a {acc.source} user; refused")
            return None
        return User.of(acc) if acc.active and acc.web else None

    def from_proxy(self, addr: str, headers) -> User | None:
        found = self.proxy.user(addr, headers)
        if found is None:
            return None
        return self._seen(*found, "proxy")

    def logged_in(self, name: str, groups: list[str]) -> User | None:
        """``oidc``: the user the provider named, recorded; None when an
        admin switched them off."""
        return self._seen(name, groups, "oidc")
