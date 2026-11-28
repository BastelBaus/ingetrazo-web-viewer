# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests of the OAuth 2.1 server of MCP_AUTH=oauth (mcp_http/oauth.py):
its settings, redirect URIs, registration, the authorisation code flow
with PKCE, tokens, and the same over HTTP through the gateway. No
container needed:

    python -m unittest discover -s tests -p "test_*.py"
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlencode, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp_http import oauth  # noqa: E402
from mcp_http.users import Users  # noqa: E402

PASSWORD = "oauth-password-123"
CALLBACK = "https://claude.ai/api/mcp/auth_callback"


def s256(verifier: str) -> str:
    return base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


class Base(unittest.TestCase):
    """An OAuthServer with its state in a temporary folder; no sleeping."""

    ENV = {"PUBLIC_URL": "https://mcp.example.org", "OAUTH_PASSWORD": PASSWORD,
           "OAUTH_USER": "", "OAUTH_REDIRECT_URIS": "", "OAUTH_ALLOW_HTTP": "",
           "OAUTH_ACCESS_TOKEN_SECONDS": "", "OAUTH_REFRESH_TOKEN_DAYS": ""}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name)
        self.patches = [mock.patch.dict(os.environ, self.ENV),
                        mock.patch.object(oauth, "STATE_DIR", self.state),
                        mock.patch.object(oauth.time, "sleep", lambda s: None)]
        for p in self.patches:
            p.start()
        self.users = Users(self.state / "users.db")
        self.o = oauth.OAuthServer(self.users)

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def client(self, method="none", uris=(CALLBACK,)) -> dict:
        return self.o.register({"redirect_uris": list(uris),
                                "token_endpoint_auth_method": method,
                                "client_name": "Test client"})

    def authorize(self, client, verifier="v" * 50, **extra) -> dict:
        q = {"client_id": client["client_id"], "response_type": "code",
             "redirect_uri": client["redirect_uris"][0], "state": "st-1",
             "code_challenge": s256(verifier), "code_challenge_method": "S256", **extra}
        return self.o.check_authorize(q)

    def code(self, client, verifier="v" * 50, user="", password=PASSWORD) -> str:
        req = self.authorize(client, verifier)
        self.o.pending["tx"] = {**req, "t": time.time()}
        target, error = self.o.approve({"tx": "tx", "user": user or "admin",
                                        "password": password, "decision": "allow"})
        self.assertTrue(target, error)
        return parse_qs(urlsplit(target).query)["code"][0]


class SettingsTest(Base):
    def make(self, **env):
        with mock.patch.dict(os.environ, env):
            return oauth.OAuthServer(env.pop("_users", self.users))

    def test_refusals(self):
        for env, msg in (({"PUBLIC_URL": ""}, "PUBLIC_URL"),
                         ({"PUBLIC_URL": "http://mcp.example.org"}, "https"),
                         ({"PUBLIC_URL": "https://mcp.example.org/?x=1"}, "plain base URL"),
                         ({"PUBLIC_URL": "https://mcp.example.org/#f"}, "plain base URL"),
                         ({"PUBLIC_URL": "https://"}, "plain base URL"),
                         ({"OAUTH_PASSWORD": "short-11ch"}, "12 characters")):
            with self.assertRaisesRegex(SystemExit, msg, msg=env):
                self.make(**env)

    def test_no_password_needs_the_user_list(self):
        with mock.patch.dict(os.environ, {"OAUTH_PASSWORD": ""}):
            with self.assertRaisesRegex(SystemExit, "OAUTH_PASSWORD"):
                oauth.OAuthServer(None)
            self.assertIsNotNone(oauth.OAuthServer(self.users))

    def test_http_only_on_purpose(self):
        o = self.make(PUBLIC_URL="http://127.0.0.1:1/", OAUTH_ALLOW_HTTP="true")
        self.assertEqual(o.base, "http://127.0.0.1:1")
        self.assertEqual(o.resource, "http://127.0.0.1:1/mcp")

    def test_metadata(self):
        meta = self.o.server_metadata()
        self.assertEqual(meta["issuer"], "https://mcp.example.org")
        self.assertEqual(meta["code_challenge_methods_supported"], ["S256"])
        self.assertNotIn("plain", json.dumps(meta))
        self.assertNotIn("implicit", json.dumps(meta))
        self.assertEqual(self.o.resource_metadata()["resource"], "https://mcp.example.org/mcp")


class RedirectTest(Base):
    def test_defaults(self):
        ok = self.o.redirect_allowed
        for uri in (CALLBACK, CALLBACK + "/sub", "https://claude.com/api/mcp/auth_callback",
                    "http://localhost:6274/oauth/callback", "http://127.0.0.1/cb",
                    "http://[::1]:9/x"):
            self.assertTrue(ok(uri), uri)
        for uri in ("https://claude.ai/api/mcp/auth_callbackX",       # not below the path
                    "https://claude.ai/api/mcp/other",
                    "https://claude.ai.evil.example/api/mcp/auth_callback",
                    "https://evil.example/api/mcp/auth_callback",
                    "http://claude.ai/api/mcp/auth_callback",          # scheme
                    "https://claude.ai:8443/api/mcp/auth_callback",    # a port on a non-loopback
                    "https://user:pw@claude.ai/api/mcp/auth_callback",
                    "https://claude.ai@evil.example/api/mcp/auth_callback",
                    CALLBACK + "#frag", "http://localhost.evil.example/cb",
                    "javascript:alert(1)", "data:text/html,x", "", "/relative",
                    "http://localhost:99999/", "https://[::1/"):
            self.assertFalse(ok(uri), uri)

    def test_no_control_characters_or_dot_segments(self):
        ok = self.o.redirect_allowed
        for uri in ("http://localhost/\r\nSet-Cookie: x=1", "http://localhost/\nX: y",
                    "http://localhost/a\tb", CALLBACK + "\t", "http://localhost/ a",
                    "http://localhost/\x00", "http://localhost\\@evil.example/",
                    CALLBACK + "/../../evil", CALLBACK + "/./x", CALLBACK + "/%2e%2e/x",
                    CALLBACK + "/.%2E/x"):
            self.assertFalse(ok(uri), repr(uri))
        self.assertFalse(ok(None))
        self.assertFalse(ok(["http://localhost/"]))

    def test_own_list(self):
        with mock.patch.dict(os.environ, {"OAUTH_REDIRECT_URIS": "https://app.example.org/cb, "
                                                                 "https://app.example.org:8443/x"}):
            o = oauth.OAuthServer(self.users)
        self.assertTrue(o.redirect_allowed("https://app.example.org/cb"))
        self.assertTrue(o.redirect_allowed("https://app.example.org:8443/x/y"))
        self.assertFalse(o.redirect_allowed("https://app.example.org:9/cb"))
        self.assertFalse(o.redirect_allowed("https://app.example.org:9443/x"))
        self.assertFalse(o.redirect_allowed(CALLBACK))                 # defaults replaced
        self.assertFalse(o.redirect_allowed("http://localhost/"))


class RegisterTest(Base):
    def test_public_client(self):
        c = self.client()
        self.assertNotIn("client_secret", c)
        self.assertEqual(c["grant_types"], ["authorization_code", "refresh_token"])

    def test_confidential_client_secret_kept_hashed(self):
        c = self.client("client_secret_post")
        stored = json.loads((self.state / "oauth.json").read_text())
        self.assertNotIn(c["client_secret"], json.dumps(stored))
        self.assertEqual(stored["clients"][c["client_id"]]["secret_hash"],
                         hashlib.sha256(c["client_secret"].encode()).hexdigest())
        self.assertEqual((self.state / "oauth.json").stat().st_mode & 0o777, 0o600)

    def test_refusals(self):
        for body, err in (({}, "invalid_redirect_uri"),
                          ({"redirect_uris": []}, "invalid_redirect_uri"),
                          ({"redirect_uris": CALLBACK}, "invalid_redirect_uri"),
                          ({"redirect_uris": [1]}, "invalid_redirect_uri"),
                          ({"redirect_uris": [CALLBACK, "https://evil.example/cb"]},
                           "invalid_redirect_uri"),
                          ({"redirect_uris": [CALLBACK], "token_endpoint_auth_method":
                            "private_key_jwt"}, "invalid_client_metadata"),
                          ({"redirect_uris": [CALLBACK], "grant_types": ["implicit"]},
                           "invalid_client_metadata"),
                          ({"redirect_uris": [CALLBACK], "grant_types": ["client_credentials"]},
                           "invalid_client_metadata")):
            with self.assertRaises(oauth.OAuthError, msg=body) as cm:
                self.o.register(body)
            self.assertEqual(cm.exception.error, err, body)

    def test_long_name_is_cut(self):
        c = self.o.register({"redirect_uris": [CALLBACK], "client_name": "x" * 500})
        self.assertEqual(len(c["client_name"]), 120)

    def test_clients_are_capped(self):
        with mock.patch.object(oauth, "MAX_CLIENTS", 5):
            first = self.client()["client_id"]
            for _ in range(5):
                self.client()
        self.assertEqual(len(self.o.store.clients), 5)
        self.assertNotIn(first, self.o.store.clients)            # the stalest went

    def test_ids_and_secrets_are_random(self):
        ids = {self.client("client_secret_basic")["client_id"] for _ in range(20)}
        self.assertEqual(len(ids), 20)


class AuthorizeTest(Base):
    def test_unknown_client_or_redirect_never_redirects(self):
        c = self.client()
        with self.assertRaises(oauth.OAuthError) as cm:
            self.o.check_authorize({"client_id": "nope", "redirect_uri": CALLBACK})
        self.assertIsNone(cm.exception.redirect)
        with self.assertRaises(oauth.OAuthError) as cm:
            self.authorize({**c, "redirect_uris": ["http://localhost/other"]})
        self.assertIsNone(cm.exception.redirect)

    def test_errors_go_back_to_the_client(self):
        c = self.client()
        for extra, err in (({"response_type": "token"}, "unsupported_response_type"),
                           ({"code_challenge_method": "plain"}, "invalid_request"),
                           ({"code_challenge": ""}, "invalid_request"),
                           ({"resource": "https://other.example/mcp"}, "invalid_target")):
            with self.assertRaises(oauth.OAuthError, msg=extra) as cm:
                self.authorize(c, **extra)
            self.assertEqual(cm.exception.error, err)
            target = self.o.error_redirect(cm.exception.redirect, cm.exception)
            q = parse_qs(urlsplit(target).query)
            self.assertTrue(target.startswith(CALLBACK + "?"))
            self.assertEqual((q["error"][0], q["state"][0], q["iss"][0]),
                             (err, "st-1", "https://mcp.example.org"))

    def test_resource_of_this_server(self):
        c = self.client()
        self.assertTrue(self.authorize(c, resource="https://mcp.example.org/mcp"))
        self.assertTrue(self.authorize(c, resource="https://mcp.example.org/"))

    def test_the_one_registered_uri_when_none_is_given(self):
        c = self.client()
        req = self.o.check_authorize({"client_id": c["client_id"], "response_type": "code",
                                      "code_challenge": "x", "code_challenge_method": "S256"})
        self.assertEqual(req["redirect_uri"], CALLBACK)
        two = self.client(uris=(CALLBACK, "http://localhost/cb"))
        with self.assertRaises(oauth.OAuthError):
            self.o.check_authorize({"client_id": two["client_id"], "response_type": "code",
                                    "code_challenge": "x", "code_challenge_method": "S256"})


class ApproveTest(Base):
    def pending(self, c=None):
        req = self.authorize(c or self.client())
        tx = secrets.token_urlsafe(8)
        self.o.pending[tx] = {**req, "t": time.time()}
        return tx

    def approve(self, tx, user="admin", password=PASSWORD, decision="allow"):
        return self.o.approve({"tx": tx, "user": user, "password": password,
                               "decision": decision})

    def test_password_and_list_users(self):
        target, _ = self.approve(self.pending())
        self.assertIn("code=", target)
        self.users.create("anna", "anna-pass")
        self.assertEqual(self.approve(self.pending(), "anna", "anna-pass"),
                         (None, "Wrong user name or password."))     # no MCP right
        self.users.set_rights("anna", mcp=True)
        target, _ = self.approve(self.pending(), "anna", "anna-pass")
        code = parse_qs(urlsplit(target).query)["code"][0]
        self.assertEqual(self.o.codes[code]["user"], "anna")
        self.users.set_active("anna", False)
        self.assertIsNone(self.approve(self.pending(), "anna", "anna-pass")[0])

    def test_wrong_password_keeps_the_request(self):
        tx = self.pending()
        self.assertEqual(self.approve(tx, password="wrong"), (None, "Wrong user name or password."))
        self.assertIn(tx, self.o.pending)
        self.assertEqual(self.approve(tx, user="other")[0], None)
        self.assertIn("code=", self.approve(tx)[0])
        self.assertNotIn(tx, self.o.pending)                         # used once
        self.assertIn("expired", self.approve(tx)[1])

    def test_deny(self):
        tx = self.pending()
        target, _ = self.approve(tx, password="", decision="deny")
        self.assertIn("error=access_denied", target)
        self.assertIn("state=st-1", target)
        self.assertNotIn(tx, self.o.pending)

    def test_expired_or_unknown_request(self):
        tx = self.pending()
        self.o.pending[tx]["t"] -= oauth.PENDING_TTL + 1
        self.assertIn("expired", self.approve(tx)[1])
        self.assertIn("expired", self.approve("made-up")[1])

    def test_throttled_after_many_wrong_passwords(self):
        tx = self.pending()
        for _ in range(20):
            self.approve(tx, password="wrong")
        self.assertIn("Too many", self.approve(tx)[1])               # even the right one
        self.o.failures = [t - 901 for t in self.o.failures]          # 15 minutes later
        self.assertIn("code=", self.approve(tx)[0])

    def test_wrong_password_is_slowed_down(self):
        slept = []
        with mock.patch.object(oauth.time, "sleep", slept.append):
            self.approve(self.pending(), password="wrong")
        self.assertEqual(slept, [1.0])


class TokenTest(Base):
    def token(self, form, headers=None):
        return self.o.token(form, headers or {})

    def test_code_flow_and_refresh_rotation(self):
        c = self.client()
        code = self.code(c)
        t = self.token({"grant_type": "authorization_code", "code": code, "client_id":
                        c["client_id"], "redirect_uri": CALLBACK, "code_verifier": "v" * 50})
        self.assertEqual(self.o.access_user(t["access_token"]), "")
        self.assertEqual(t["token_type"], "Bearer")
        # The code works once.
        with self.assertRaises(oauth.OAuthError) as cm:
            self.token({"grant_type": "authorization_code", "code": code, "client_id":
                        c["client_id"], "code_verifier": "v" * 50})
        self.assertEqual(cm.exception.error, "invalid_grant")
        # Refresh: a new pair; the old refresh token is spent.
        t2 = self.token({"grant_type": "refresh_token", "refresh_token": t["refresh_token"],
                         "client_id": c["client_id"]})
        self.assertNotEqual(t2["access_token"], t["access_token"])
        with self.assertRaises(oauth.OAuthError):
            self.token({"grant_type": "refresh_token", "refresh_token": t["refresh_token"],
                        "client_id": c["client_id"]})
        # Tokens are kept hashed only.
        stored = (self.state / "oauth.json").read_text()
        for value in (t2["access_token"], t2["refresh_token"]):
            self.assertNotIn(value, stored)

    def test_pkce(self):
        c = self.client()
        for verifier in ("", "w" * 50, "v" * 49):
            code = self.code(c)
            with self.assertRaises(oauth.OAuthError, msg=verifier) as cm:
                self.token({"grant_type": "authorization_code", "code": code,
                            "client_id": c["client_id"], "code_verifier": verifier})
            self.assertIn("PKCE", cm.exception.description)

    def test_odd_challenge_is_refused_not_an_error(self):
        c = self.client()
        req = self.o.check_authorize({"client_id": c["client_id"], "response_type": "code",
                                      "code_challenge": "é" * 43, "code_challenge_method": "S256"})
        self.o.pending["tx"] = {**req, "t": time.time()}
        target, _ = self.o.approve({"tx": "tx", "user": "admin", "password": PASSWORD})
        code = parse_qs(urlsplit(target).query)["code"][0]
        with self.assertRaises(oauth.OAuthError):
            self.token({"grant_type": "authorization_code", "code": code,
                        "client_id": c["client_id"], "code_verifier": "v" * 50})

    def test_code_is_bound_to_client_and_redirect(self):
        c, other = self.client(), self.client()
        code = self.code(c)
        with self.assertRaises(oauth.OAuthError):
            self.token({"grant_type": "authorization_code", "code": code,
                        "client_id": other["client_id"], "code_verifier": "v" * 50})
        code = self.code(c)
        with self.assertRaises(oauth.OAuthError) as cm:
            self.token({"grant_type": "authorization_code", "code": code, "client_id":
                        c["client_id"], "redirect_uri": CALLBACK + "/x",
                        "code_verifier": "v" * 50})
        self.assertIn("redirect_uri", cm.exception.description)

    def test_expired_code(self):
        c = self.client()
        code = self.code(c)
        self.o.codes[code]["t"] -= oauth.CODE_TTL + 1
        with self.assertRaises(oauth.OAuthError):
            self.token({"grant_type": "authorization_code", "code": code,
                        "client_id": c["client_id"], "code_verifier": "v" * 50})

    def test_confidential_client_must_authenticate(self):
        c = self.client("client_secret_basic")
        form = {"grant_type": "authorization_code", "code_verifier": "v" * 50}
        for headers, extra in (({}, {"client_id": c["client_id"]}),
                               ({}, {"client_id": c["client_id"], "client_secret": "wrong"}),
                               ({"Authorization": "Basic !!!"}, {}),
                               ({"Authorization": "Basic " + base64.b64encode(
                                   f"{c['client_id']}:wrong".encode()).decode()}, {})):
            with self.assertRaises(oauth.OAuthError, msg=(headers, extra)) as cm:
                self.token({**form, "code": self.code(c), **extra}, headers)
            self.assertEqual((cm.exception.error, cm.exception.status), ("invalid_client", 401))
        basic = base64.b64encode(f"{c['client_id']}:{c['client_secret']}".encode()).decode()
        t = self.token({**form, "code": self.code(c)}, {"Authorization": f"Basic {basic}"})
        self.assertTrue(t["access_token"])
        t = self.token({**form, "code": self.code(c), "client_id": c["client_id"],
                        "client_secret": c["client_secret"]})
        self.assertTrue(t["access_token"])

    def test_refresh_token_of_another_client(self):
        c, other = self.client(), self.client()
        t = self.token({"grant_type": "authorization_code", "code": self.code(c),
                        "client_id": c["client_id"], "code_verifier": "v" * 50})
        with self.assertRaises(oauth.OAuthError):
            self.token({"grant_type": "refresh_token", "refresh_token": t["refresh_token"],
                        "client_id": other["client_id"]})
        # ...and that attempt spent it (rotation is once only, whoever tries).
        with self.assertRaises(oauth.OAuthError):
            self.token({"grant_type": "refresh_token", "refresh_token": t["refresh_token"],
                        "client_id": c["client_id"]})

    def test_access_token_expiry_and_forgotten_client(self):
        c = self.client()
        t = self.token({"grant_type": "authorization_code", "code": self.code(c),
                        "client_id": c["client_id"], "code_verifier": "v" * 50})
        key = hashlib.sha256(t["access_token"].encode()).hexdigest()
        self.o.store.access[key]["exp"] = time.time() - 1
        self.assertIsNone(self.o.access_user(t["access_token"]))
        self.o.store.access[key]["exp"] = time.time() + 60
        self.assertEqual(self.o.access_user(t["access_token"]), "")
        del self.o.store.clients[c["client_id"]]                       # evicted
        self.assertIsNone(self.o.access_user(t["access_token"]))
        self.assertIsNone(self.o.access_user(""))
        self.assertIsNone(self.o.access_user("made-up"))

    def test_unsupported_grants(self):
        c = self.client()
        for grant in ("password", "client_credentials", "implicit", None):
            with self.assertRaises(oauth.OAuthError) as cm:
                self.token({"grant_type": grant, "client_id": c["client_id"]})
            self.assertEqual(cm.exception.error, "unsupported_grant_type")

    def test_state_survives_a_restart(self):
        c = self.client()
        t = self.token({"grant_type": "authorization_code", "code": self.code(c),
                        "client_id": c["client_id"], "code_verifier": "v" * 50})
        again = oauth.OAuthServer(self.users)
        self.assertEqual(again.access_user(t["access_token"]), "")
        self.assertEqual(again.codes, {})                    # codes and pending: memory only

    def test_broken_state_file_starts_empty(self):
        (self.state / "oauth.json").write_text("{not json")
        self.assertEqual(oauth.OAuthServer(self.users).store.clients, {})


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class HttpFlowTest(Base):
    """The whole flow over HTTP, through the gateway's handler, as a remote
    connector does it: discovery, registration, consent page, token, /mcp."""

    ENV = {**Base.ENV, "MCP_AUTH": "oauth", "MCP_TOKEN": "",
           "PUBLIC_URL": "https://mcp.example.org"}

    def setUp(self):
        super().setUp()
        from mcp_http import auth as mcp_auth
        from mcp_http import server
        self.server = server
        os.environ["USERS_DB"] = str(self.state / "users.db")
        self.saved = getattr(server, "auth", None), getattr(server, "app", None)
        server.auth = mcp_auth.Auth()
        server.auth.oauth = self.o
        server.app = FakeApp()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.opener = urllib.request.build_opener(NoRedirect)

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.server.auth, self.server.app = self.saved
        os.environ.pop("USERS_DB", None)
        super().tearDown()

    def req(self, path, data=None, headers=None, method=None):
        r = urllib.request.Request(self.base + path, data, headers or {}, method=method)
        try:
            with self.opener.open(r, timeout=10) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    def test_flow(self):
        status, headers, body = self.req("/mcp", b"{}", {"Content-Type": "application/json"})
        self.assertEqual(status, 401)
        self.assertIn("resource_metadata=", headers["WWW-Authenticate"])
        status, _, body = self.req("/.well-known/oauth-protected-resource/mcp")
        self.assertEqual(json.loads(body)["authorization_servers"], ["https://mcp.example.org"])
        status, _, body = self.req("/.well-known/oauth-authorization-server")
        self.assertEqual(json.loads(body)["token_endpoint"], "https://mcp.example.org/token")
        status, _, body = self.req("/register", json.dumps({
            "redirect_uris": ["http://localhost:6274/cb"], "token_endpoint_auth_method": "none",
            "client_name": "<script>alert(1)</script>"}).encode(),
            {"Content-Type": "application/json"})
        self.assertEqual(status, 201)
        cid = json.loads(body)["client_id"]
        verifier = secrets.token_urlsafe(48)
        q = urlencode({"client_id": cid, "response_type": "code", "state": "abc",
                       "redirect_uri": "http://localhost:6274/cb",
                       "code_challenge": s256(verifier), "code_challenge_method": "S256"})
        status, headers, page = self.req("/authorize?" + q)
        self.assertEqual(status, 200)
        page = page.decode()
        self.assertNotIn("<script>alert(1)", page)                       # the name is escaped
        self.assertIn("&lt;script&gt;", page)
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertEqual(headers["Cache-Control"], "no-store")
        tx = re.search(r'name="tx" value="([^"]+)"', page).group(1)
        status, _, page = self.req("/authorize", urlencode({
            "tx": tx, "user": "admin", "password": "wrong", "decision": "allow"}).encode())
        self.assertEqual(status, 401)
        self.assertIn("Wrong user name or password", page.decode())
        status, headers, _ = self.req("/authorize", urlencode({
            "tx": tx, "user": "admin", "password": PASSWORD, "decision": "allow"}).encode())
        self.assertEqual(status, 302)
        loc = urlsplit(headers["Location"])
        q = parse_qs(loc.query)
        self.assertEqual((loc.netloc, q["state"][0], q["iss"][0]),
                         ("localhost:6274", "abc", "https://mcp.example.org"))
        status, headers, body = self.req("/token", urlencode({
            "grant_type": "authorization_code", "code": q["code"][0], "client_id": cid,
            "redirect_uri": "http://localhost:6274/cb", "code_verifier": verifier}).encode())
        self.assertEqual(status, 200, body)
        self.assertEqual(headers["Cache-Control"], "no-store")
        access = json.loads(body)["access_token"]
        status, _, body = self.req("/mcp", json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode(),
            {"Content-Type": "application/json", "Authorization": f"Bearer {access}"})
        self.assertEqual(status, 200)
        self.assertIn("list_documents", body.decode())

    def test_bad_requests(self):
        status, _, body = self.req("/register", b"[1]", {"Content-Type": "application/json"})
        self.assertEqual((status, json.loads(body)["error"]), (400, "invalid_client_metadata"))
        status, _, body = self.req("/register", b"{bad", {"Content-Type": "application/json"})
        self.assertEqual(status, 400)
        status, headers, body = self.req("/token", b"grant_type=authorization_code&client_id=x")
        self.assertEqual(status, 401)
        self.assertIn("Basic", headers["WWW-Authenticate"])
        status, _, page = self.req("/authorize?client_id=nope")
        self.assertEqual(status, 400)
        self.assertIn("unknown client_id", page.decode())
        status, _, page = self.req("/authorize", b"tx=nope&decision=allow")
        self.assertEqual(status, 400)

    def test_error_redirect_to_the_client(self):
        c = self.client(uris=("http://127.0.0.1:9/cb",))
        status, headers, _ = self.req("/authorize?" + urlencode({
            "client_id": c["client_id"], "response_type": "token", "state": "s"}))
        self.assertEqual(status, 302)
        self.assertTrue(headers["Location"].startswith("http://127.0.0.1:9/cb?error="))

    def test_cors_only_on_the_public_endpoints(self):
        status, headers, _ = self.req("/token", method="OPTIONS")
        self.assertEqual(status, 204)
        self.assertEqual(headers["Access-Control-Allow-Origin"], "*")
        status, headers, _ = self.req("/authorize", method="OPTIONS")
        self.assertEqual(status, 404)
        self.assertNotIn("Access-Control-Allow-Origin", headers)
        status, headers, _ = self.req("/mcp", method="OPTIONS")
        self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_token_of_a_switched_off_user(self):
        self.users.create("anna", "anna-pass")
        self.users.set_rights("anna", mcp=True)
        c = self.client()
        code = self.code(c, user="anna", password="anna-pass")
        t = self.o.token({"grant_type": "authorization_code", "code": code,
                          "client_id": c["client_id"], "code_verifier": "v" * 50}, {})
        auth = {"Authorization": f"Bearer {t['access_token']}", "Content-Type": "application/json"}
        msg = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode()
        self.assertEqual(self.req("/mcp", msg, auth)[0], 200)
        self.users.set_active("anna", False)
        self.assertEqual(self.req("/mcp", msg, auth)[0], 401)
        self.users.set_active("anna", True)
        self.users.set_rights("anna", mcp=False)
        self.assertEqual(self.req("/mcp", msg, auth)[0], 401)


class FakeApp:
    def call(self, tool, args=None):
        return {"ok": True, "result": {"documents": []}}

    def handle(self, msg):
        if "id" not in msg:
            return None
        if msg.get("method") == "tools/list":
            return {"jsonrpc": "2.0", "id": msg["id"], "result": {"tools": [{"name": "query_model"}]}}
        return {"jsonrpc": "2.0", "id": msg["id"], "result": {}}

    def probe(self, max_busy):
        return 200, {"status": "ok"}


if __name__ == "__main__":
    unittest.main()
