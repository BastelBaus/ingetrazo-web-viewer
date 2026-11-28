# SPDX-License-Identifier: AGPL-3.0-or-later
"""A minimal OAuth 2.1 authorisation server for ``MCP_AUTH=oauth``.

Enough for remote MCP connectors such as claude.ai, and for the MCP
Inspector or Claude Code on this machine:

- protected resource metadata (RFC 9728) and authorisation server metadata
  (RFC 8414) under ``/.well-known/``;
- dynamic client registration (RFC 7591) at ``/register``, for redirect
  URIs on the allow list ``OAUTH_REDIRECT_URIS``;
- ``/authorize``: the authorisation code flow with PKCE (S256 only), a
  login and consent page: a user of the user list who may use MCP
  (users.py), or ``OAUTH_USER`` / ``OAUTH_PASSWORD`` (every right, as
  before there was a user list);
- ``/token``: codes and refresh tokens (rotated on every use) for access
  tokens that expire.

Clients and tokens live in ``/state/oauth.json``; tokens and client
secrets only as SHA-256 hashes. ``PUBLIC_URL`` (https) is the issuer and
the base of the resource ``<PUBLIC_URL>/mcp``.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from html import escape
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

from .common import content_length, log

STATE_DIR = Path(os.environ.get("INGETRAZO_STATE", "/state"))
#: claude.ai's and claude.com's connector callbacks, and any port on this
#: machine (MCP Inspector, Claude Code: RFC 8252 loopback redirects).
DEFAULT_REDIRECTS = ("https://claude.ai/api/mcp/auth_callback",
                     "https://claude.com/api/mcp/auth_callback",
                     "http://localhost", "http://127.0.0.1", "http://[::1]")
LOOPBACK = ("localhost", "127.0.0.1", "::1")
SCOPE = "mcp"
CODE_TTL = 300
PENDING_TTL = 900
MAX_CLIENTS = 500


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _s256(verifier: str) -> str:
    return base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


class OAuthError(Exception):
    def __init__(self, error: str, description: str, status: int = 400) -> None:
        super().__init__(description)
        self.error, self.description, self.status = error, description, status
        #: The validated request, when the error may go back to the client.
        self.redirect: dict | None = None


class Store:
    """``oauth.json``: clients, access and refresh tokens (hashed)."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.lock = threading.RLock()
        try:
            data = json.loads(path.read_text("utf-8"))
        except (OSError, ValueError):
            data = {}
        self.clients: dict = data.get("clients", {})
        self.access: dict = data.get("access", {})
        self.refresh: dict = data.get("refresh", {})

    def save(self) -> None:
        now = time.time()
        for table in (self.access, self.refresh):
            for k in [k for k, v in table.items() if v["exp"] < now]:
                del table[k]
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".part")
            tmp.write_text(json.dumps({"clients": self.clients, "access": self.access,
                                       "refresh": self.refresh}, indent=1), "utf-8")
            os.chmod(tmp, 0o600)
            tmp.replace(self.path)
        except OSError as exc:
            log(f"oauth: cannot write {self.path}: {exc}")


class OAuthServer:
    def __init__(self, users=None) -> None:
        self.users = users                 # mcp_http.users.Users, or None
        self.base = _env("PUBLIC_URL").rstrip("/")
        allow_http = _env("OAUTH_ALLOW_HTTP").lower() in ("1", "true", "yes")
        if not self.base:
            raise SystemExit("MCP_AUTH=oauth needs PUBLIC_URL: the https URL clients "
                             "reach this server at, e.g. https://mcp.example.org")
        parts = urlsplit(self.base)
        if parts.scheme != "https" and not allow_http:
            raise SystemExit("PUBLIC_URL must be https:// for MCP_AUTH=oauth "
                             "(OAUTH_ALLOW_HTTP=true for a test on this machine)")
        if parts.query or parts.fragment or not parts.netloc:
            raise SystemExit(f"PUBLIC_URL is not a plain base URL: {self.base!r}")
        self.user = _env("OAUTH_USER") or "admin"
        self.password = os.environ.get("OAUTH_PASSWORD", "")
        if self.password and len(self.password) < 12:
            raise SystemExit("OAUTH_PASSWORD needs at least 12 characters: it "
                             "approves who may run Python here")
        if not self.password and self.users is None:
            raise SystemExit("MCP_AUTH=oauth needs OAUTH_PASSWORD (12+ characters) "
                             "or the user list (USERS_DB)")
        if not self.password:
            log("oauth: no OAUTH_PASSWORD; users of the user list who may use MCP approve clients")
        raw = [u.strip() for u in _env("OAUTH_REDIRECT_URIS").split(",") if u.strip()]
        self.redirects = [urlsplit(u) for u in (raw or DEFAULT_REDIRECTS)]
        self.access_ttl = int(_env("OAUTH_ACCESS_TOKEN_SECONDS") or 3600)
        self.refresh_ttl = int(_env("OAUTH_REFRESH_TOKEN_DAYS") or 30) * 86400
        self.resource = self.base + "/mcp"
        self.store = Store(STATE_DIR / "oauth.json")
        self.codes: dict[str, dict] = {}
        self.pending: dict[str, dict] = {}
        self.failures: list[float] = []
        log(f"oauth: issuer {self.base}, redirect URIs allowed: "
            + ", ".join(u.geturl() for u in self.redirects))

    # ---- metadata ------------------------------------------------------------
    def resource_metadata(self) -> dict:
        return {"resource": self.resource,
                "authorization_servers": [self.base],
                "scopes_supported": [SCOPE],
                "bearer_methods_supported": ["header"],
                "resource_name": "IngeTrazo MCP"}

    def server_metadata(self) -> dict:
        return {"issuer": self.base,
                "authorization_endpoint": self.base + "/authorize",
                "token_endpoint": self.base + "/token",
                "registration_endpoint": self.base + "/register",
                "scopes_supported": [SCOPE],
                "response_types_supported": ["code"],
                "response_modes_supported": ["query"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "token_endpoint_auth_methods_supported":
                    ["none", "client_secret_post", "client_secret_basic"],
                "code_challenge_methods_supported": ["S256"],
                "authorization_response_iss_parameter_supported": True}

    # ---- tokens --------------------------------------------------------------
    def access_user(self, token: str) -> str | None:
        """Who a valid access token was given to: a user of the list, ""
        for OAUTH_USER (every right); None when the token is not valid."""
        with self.store.lock:
            entry = self.store.access.get(_hash(token))
            if (entry is None or entry["exp"] <= time.time()
                    or entry["client_id"] not in self.store.clients):
                return None
            return entry.get("user", "")

    def valid_access_token(self, token: str) -> bool:
        return self.access_user(token) is not None

    def _issue(self, client_id: str, user: str = "") -> dict:
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        now = time.time()
        with self.store.lock:
            self.store.access[_hash(access)] = {"client_id": client_id, "user": user,
                                                "exp": now + self.access_ttl}
            self.store.refresh[_hash(refresh)] = {"client_id": client_id, "user": user,
                                                  "exp": now + self.refresh_ttl}
            self.store.clients[client_id]["last_used"] = int(now)
            self.store.save()
        return {"access_token": access, "token_type": "Bearer",
                "expires_in": self.access_ttl, "refresh_token": refresh,
                "scope": SCOPE}

    # ---- redirect URIs ---------------------------------------------------------
    def redirect_allowed(self, uri: str) -> bool:
        """``uri`` matches the allow list: same scheme and host, the path
        under the allowed one; an allowed loopback host without a port
        takes any port. No user info, no fragment. No control characters,
        spaces or backslashes (urlsplit drops tabs and line breaks, but the
        URI goes into a Location header as it is), and no ``.``/``..``
        segments (they would leave the allowed path)."""
        if not isinstance(uri, str) or re.search(r"[\x00-\x20\x7f\\]", uri):
            return False
        try:
            u = urlsplit(uri)
            port = u.port
        except ValueError:
            return False
        if u.username or u.password or u.fragment or not u.hostname:
            return False
        if any(seg in (".", "..") or seg.lower() in ("%2e", "%2e%2e", ".%2e", "%2e.")
               for seg in u.path.split("/")):
            return False
        for a in self.redirects:
            if u.scheme != a.scheme or u.hostname != a.hostname:
                continue
            if a.port is not None and port != a.port:
                continue
            if a.port is None and port is not None and a.hostname not in LOOPBACK:
                continue
            path = a.path.rstrip("/")
            if not path or u.path == path or u.path.startswith(path + "/"):
                return True
        return False

    # ---- endpoints -------------------------------------------------------------
    def register(self, body: dict) -> dict:
        uris = body.get("redirect_uris")
        if not isinstance(uris, list) or not uris or not all(isinstance(u, str) for u in uris):
            raise OAuthError("invalid_redirect_uri", "redirect_uris: a list of URIs is required")
        bad = [u for u in uris if not self.redirect_allowed(u)]
        if bad:
            raise OAuthError("invalid_redirect_uri",
                             "not an allowed redirect URI (OAUTH_REDIRECT_URIS): "
                             + ", ".join(bad))
        method = body.get("token_endpoint_auth_method") or "client_secret_basic"
        if method not in ("none", "client_secret_post", "client_secret_basic"):
            raise OAuthError("invalid_client_metadata",
                             f"token_endpoint_auth_method {method!r} is not supported")
        for g in body.get("grant_types") or []:
            if g not in ("authorization_code", "refresh_token"):
                raise OAuthError("invalid_client_metadata", f"grant type {g!r} is not supported")
        name = str(body.get("client_name") or "an MCP client")[:120]
        client_id = secrets.token_urlsafe(16)
        now = int(time.time())
        entry = {"client_name": name, "redirect_uris": uris,
                 "token_endpoint_auth_method": method,
                 "created": now, "last_used": now}
        reply = {"client_id": client_id, "client_id_issued_at": now,
                 "client_name": name, "redirect_uris": uris,
                 "grant_types": ["authorization_code", "refresh_token"],
                 "response_types": ["code"],
                 "token_endpoint_auth_method": method}
        if method != "none":
            secret = secrets.token_urlsafe(32)
            entry["secret_hash"] = _hash(secret)
            reply.update(client_secret=secret, client_secret_expires_at=0)
        with self.store.lock:
            if len(self.store.clients) >= MAX_CLIENTS:     # forget the stalest
                stale = min(self.store.clients,
                            key=lambda c: self.store.clients[c].get("last_used", 0))
                del self.store.clients[stale]
            self.store.clients[client_id] = entry
            self.store.save()
        log(f"oauth: registered {name!r} ({client_id}), redirect {', '.join(uris)}")
        return reply

    def check_authorize(self, q: dict) -> dict:
        """The validated request, or OAuthError. ``redirect`` in the error
        says whether it may go back to the client."""
        with self.store.lock:
            client = self.store.clients.get(q.get("client_id", ""))
        if client is None:
            raise OAuthError("invalid_client", "unknown client_id: register first")
        uri = q.get("redirect_uri") or ""
        if not uri and len(client["redirect_uris"]) == 1:
            uri = client["redirect_uris"][0]
        if uri not in client["redirect_uris"]:
            raise OAuthError("invalid_request", "redirect_uri is not registered for this client")
        req = {"client_id": q["client_id"], "redirect_uri": uri,
               "state": q.get("state"), "client_name": client["client_name"]}
        try:
            if q.get("response_type") != "code":
                raise OAuthError("unsupported_response_type", "only response_type=code")
            if q.get("code_challenge_method") != "S256" or not q.get("code_challenge"):
                raise OAuthError("invalid_request", "PKCE with code_challenge_method=S256 is required")
            resource = q.get("resource")
            if resource and resource.rstrip("/") not in (self.resource, self.base):
                raise OAuthError("invalid_target", f"unknown resource {resource!r}")
        except OAuthError as exc:
            exc.redirect = req
            raise
        req["code_challenge"] = q["code_challenge"]
        return req

    def error_redirect(self, req: dict, exc: OAuthError) -> str:
        params = {"error": exc.error, "error_description": exc.description, "iss": self.base}
        if req.get("state"):
            params["state"] = req["state"]
        return self._with_query(req["redirect_uri"], params)

    @staticmethod
    def _with_query(uri: str, params: dict) -> str:
        return uri + ("&" if urlsplit(uri).query else "?") + urlencode(params)

    def _throttled(self) -> bool:
        now = time.time()
        self.failures = [t for t in self.failures if t > now - 900]
        return len(self.failures) >= 20

    def approve(self, form: dict) -> tuple[str | None, str]:
        """The consent form: (redirect URL, "") or (None, error for the page)."""
        req = self.pending.get(form.get("tx", ""))
        if req is None or req["t"] < time.time() - PENDING_TTL:
            return None, "This request has expired. Start again from your MCP client."
        if form.get("decision") == "deny":
            self.pending.pop(form["tx"], None)
            return self.error_redirect(req, OAuthError("access_denied", "the user said no")), ""
        if self._throttled():
            return None, "Too many wrong passwords. Wait 15 minutes."
        name, pw = form.get("user", "").strip(), form.get("password", "")
        user = None
        if self.password and (hmac.compare_digest(name.encode(), self.user.encode())
                              & hmac.compare_digest(pw.encode(), self.password.encode())):
            user = ""                                   # OAUTH_USER: every right
        elif self.users is not None:
            acc = self.users.authenticate(name, pw)
            if acc is not None and acc.mcp:
                user = acc.name
        if user is None:
            self.failures.append(time.time())
            time.sleep(1.0)
            return None, "Wrong user name or password."
        self.pending.pop(form["tx"], None)
        code = secrets.token_urlsafe(32)
        now = time.time()
        for k in [k for k, v in self.codes.items() if v["t"] < now - CODE_TTL]:
            del self.codes[k]
        self.codes[code] = {**req, "t": now, "user": user}
        log(f"oauth: {user or self.user} approved {req['client_name']!r} ({req['client_id']})")
        params = {"code": code, "iss": self.base}
        if req.get("state"):
            params["state"] = req["state"]
        return self._with_query(req["redirect_uri"], params), ""

    def _client(self, form: dict, headers) -> str:
        """The authenticated client's id (RFC 6749 2.3)."""
        cid, secret = form.get("client_id", ""), form.get("client_secret")
        value = headers.get("Authorization", "")
        if value.startswith("Basic "):
            from urllib.parse import unquote_plus
            try:
                raw = base64.b64decode(value[6:]).decode()
            except ValueError:
                raise OAuthError("invalid_client", "bad Basic header", 401) from None
            cid, _, secret = raw.partition(":")
            cid, secret = unquote_plus(cid), unquote_plus(secret)
        with self.store.lock:
            client = self.store.clients.get(cid)
        if client is None:
            raise OAuthError("invalid_client", "unknown client", 401)
        if client["token_endpoint_auth_method"] != "none":
            if not secret or not hmac.compare_digest(_hash(secret), client.get("secret_hash", "")):
                raise OAuthError("invalid_client", "client authentication failed", 401)
        return cid

    def token(self, form: dict, headers) -> dict:
        cid = self._client(form, headers)
        grant = form.get("grant_type")
        if grant == "authorization_code":
            code = self.codes.pop(form.get("code", ""), None)
            if (code is None or code["t"] < time.time() - CODE_TTL
                    or code["client_id"] != cid):
                raise OAuthError("invalid_grant", "unknown, used or expired code")
            if form.get("redirect_uri", code["redirect_uri"]) != code["redirect_uri"]:
                raise OAuthError("invalid_grant", "redirect_uri does not match")
            verifier = form.get("code_verifier", "")
            if not verifier or not hmac.compare_digest(_s256(verifier).encode(),
                                                       str(code["code_challenge"]).encode()):
                raise OAuthError("invalid_grant", "PKCE verification failed")
            return self._issue(cid, code.get("user", ""))
        if grant == "refresh_token":
            key = _hash(form.get("refresh_token", ""))
            with self.store.lock:
                entry = self.store.refresh.pop(key, None)   # rotated: once only
                if entry is None or entry["exp"] < time.time() or entry["client_id"] != cid:
                    self.store.save()
                    raise OAuthError("invalid_grant", "unknown, used or expired refresh token")
            return self._issue(cid, entry.get("user", ""))
        raise OAuthError("unsupported_grant_type", f"grant_type {grant!r} is not supported")

    # ---- HTTP ------------------------------------------------------------------
    CORS = {"Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Authorization, Content-Type, mcp-protocol-version",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS"}
    PUBLIC = ("/.well-known/oauth-protected-resource", "/.well-known/oauth-authorization-server",
              "/.well-known/openid-configuration", "/register", "/token")

    def route(self, h, method: str) -> bool:
        """Answer ``h``'s request if it is one of ours; False otherwise."""
        url = urlsplit(h.path)
        path = url.path
        public = any(path == p or path.startswith(p + "/") for p in self.PUBLIC)
        if method == "OPTIONS":
            if not public:
                return False
            h._send(204, headers=self.CORS)
            return True
        if method == "GET" and path.startswith("/.well-known/oauth-protected-resource"):
            return self._json(h, 200, self.resource_metadata())
        if method == "GET" and path.startswith(("/.well-known/oauth-authorization-server",
                                                "/.well-known/openid-configuration")):
            return self._json(h, 200, self.server_metadata())
        if method == "POST" and path in ("/register", "/token", "/authorize"):
            length = content_length(h.headers)
            if length is None or length > self.MAX_BODY:
                return self._json(h, 413 if length else 400, {
                    "error": "invalid_request",
                    "error_description": "body too large or bad Content-Length"})
        if path == "/register" and method == "POST":
            try:
                body = json.loads(self._body(h) or b"null")
                if not isinstance(body, dict):
                    raise ValueError
            except ValueError:
                return self._json(h, 400, {"error": "invalid_client_metadata",
                                           "error_description": "a JSON object is required"})
            try:
                return self._json(h, 201, self.register(body))
            except OAuthError as exc:
                return self._json(h, exc.status, {"error": exc.error,
                                                  "error_description": exc.description})
        if path == "/token" and method == "POST":
            form = {k: v[0] for k, v in parse_qs(self._body(h).decode("utf-8", "replace")).items()}
            try:
                return self._json(h, 200, self.token(form, h.headers))
            except OAuthError as exc:
                extra = ({"WWW-Authenticate": 'Basic realm="ingetrazo"'}
                         if exc.status == 401 else None)
                return self._json(h, exc.status, {"error": exc.error,
                                                  "error_description": exc.description}, extra)
        if path == "/authorize" and method == "GET":
            q = {k: v[0] for k, v in parse_qs(url.query).items()}
            try:
                req = self.check_authorize(q)
            except OAuthError as exc:
                if getattr(exc, "redirect", None):
                    h._send(302, headers={"Location": self.error_redirect(exc.redirect, exc)})
                    return True
                return self._page(h, 400, self._message(exc.description))
            tx = secrets.token_urlsafe(24)
            now = time.time()
            for k in [k for k, v in self.pending.items() if v["t"] < now - PENDING_TTL]:
                del self.pending[k]
            self.pending[tx] = {**req, "t": now}
            return self._page(h, 200, self._consent(tx, req, ""))
        if path == "/authorize" and method == "POST":
            form = {k: v[0] for k, v in parse_qs(self._body(h).decode("utf-8", "replace")).items()}
            target, error = self.approve(form)
            if target:
                h._send(302, headers={"Location": target})
                return True
            req = self.pending.get(form.get("tx", ""))
            body = (self._consent(form["tx"], req, error) if req
                    else self._message(error))
            return self._page(h, 401 if req else 400, body)
        return False

    MAX_BODY = 65536

    @staticmethod
    def _body(h) -> bytes:
        """The request body; route() has refused one too large or with a
        bad Content-Length already, so it is always read in full."""
        length = content_length(h.headers) or 0
        return h.rfile.read(length) if length > 0 else b""

    def _json(self, h, status: int, obj: dict, extra: dict | None = None) -> bool:
        h._send(status, json.dumps(obj).encode(), "application/json",
                {**self.CORS, "Cache-Control": "no-store", "Pragma": "no-cache",
                 **(extra or {})})
        return True

    @staticmethod
    def _page(h, status: int, inner: str) -> bool:
        body = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>IngeTrazo MCP</title>
<style>:root{{--bg:#f6f6f4;--card:#fff;--fg:#1d1d1b;--muted:#6b6b66;--line:#e2e1dc;--accent:#2f6fb2}}
@media (prefers-color-scheme:dark){{:root{{--bg:#161615;--card:#20201e;--fg:#ecebe6;--muted:#9b9a94;--line:#33322f;--accent:#6aa5e6}}}}
body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.45 system-ui,sans-serif}}
.box{{max-width:400px;margin:10vh auto;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:24px}}
h1{{font-size:18px;margin:0 0 12px}}p{{margin:0 0 10px}}.muted{{color:var(--muted);font-size:13px}}
label{{display:block;font-size:13px;color:var(--muted);margin:12px 0 4px}}
input{{width:100%;box-sizing:border-box;padding:8px 10px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg);font:inherit}}
.row{{display:flex;gap:8px;margin-top:18px}}button{{flex:1;padding:9px;border-radius:6px;font:inherit;font-weight:600;cursor:pointer}}
.ok{{border:0;background:var(--accent);color:#fff}}.no{{border:1px solid var(--line);background:var(--card);color:var(--fg)}}
.err{{color:#c0392b;font-size:14px}}</style></head><body><div class="box">{inner}</div></body></html>"""
        h._send(status, body.encode("utf-8"), "text/html; charset=utf-8",
                {"Cache-Control": "no-store", "X-Frame-Options": "DENY",
                 "Content-Security-Policy": "frame-ancestors 'none'; form-action 'self' https: http:"})
        return True

    @staticmethod
    def _message(text: str) -> str:
        return f"<h1>IngeTrazo MCP</h1><p>{escape(text)}</p>"

    def _consent(self, tx: str, req: dict, error: str) -> str:
        host = urlsplit(req["redirect_uri"]).netloc
        err = f'<p class="err">{escape(error)}</p>' if error else ""
        return f"""<h1>Allow access to IngeTrazo?</h1>
<p><strong>{escape(req['client_name'])}</strong> <span class="muted">({escape(host)})</span>
wants to use this IngeTrazo server. It could open, change and save models, and run Python in the container.</p>
{err}<form method="post" action="/authorize"><input type="hidden" name="tx" value="{escape(tx)}">
<label for="u">User</label><input id="u" name="user" autocomplete="username" value="{escape(self.user if self.password else '')}">
<label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password" autofocus>
<div class="row"><button class="no" name="decision" value="deny" formnovalidate>Deny</button>
<button class="ok" name="decision" value="allow">Allow</button></div></form>"""
