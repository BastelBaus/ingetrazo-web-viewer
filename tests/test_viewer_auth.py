# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests of the viewer's logins (viewer/auth.py): session cookies,
OpenID Connect against a provider in this process (ID tokens of the wrong
issuer, audience, nonce, age), forward auth through a proxy, and the
settings that refuse to start. No container needed:

    python -m unittest discover -s tests -p "test_*.py"
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlencode, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from viewer import auth as viewer_auth  # noqa: E402
from viewer.auth import Sessions, User  # noqa: E402


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class SessionsTest(unittest.TestCase):
    def setUp(self):
        self.s = Sessions(1)

    def test_round_trip(self):
        u = User("anna", "admin", "oidc", "abc123")
        self.assertEqual(self.s.read(self.s.issue(u)), u)

    def test_tampering_is_refused(self):
        cookie = self.s.issue(User("anna"))
        payload, _, sig = cookie.partition(".")
        data = json.loads(base64.urlsafe_b64decode(payload + "=="))
        forged = b64(json.dumps({**data, "r": "admin"}).encode())
        for value in (f"{forged}.{sig}", f"{payload}.{sig[:-1]}0", f"{payload}.", payload,
                      "", ".", f".{sig}", "x.y", cookie + "x", "é.é"):
            self.assertIsNone(self.s.read(value), value)

    def test_another_key_or_restart(self):
        cookie = self.s.issue(User("anna"))
        self.assertIsNone(Sessions(1).read(cookie))

    def test_expiry(self):
        cookie = self.s.issue(User("anna"))
        with mock.patch.object(viewer_auth.time, "time", return_value=time.time() + 86401):
            self.assertIsNone(self.s.read(cookie))

    def test_signed_garbage_is_refused(self):
        for payload in (b64(b"[1,2]"), b64(b"not json"), b64(b'"text"'), "%%%"):
            self.assertIsNone(self.s.read(f"{payload}.{self.s._sig(payload)}"), payload)

    def test_non_ascii_cookie_is_no_error(self):
        """compare_digest raises TypeError on non-ASCII str: a forged cookie
        must be refused, not crash the request."""
        for value in ("é.é", "a.ÿ", "\u00e9.x"):
            self.assertIsNone(self.s.read(value), value)

    def test_csrf_per_user_and_start(self):
        self.assertEqual(self.s.csrf("anna"), self.s.csrf("anna"))
        self.assertNotEqual(self.s.csrf("anna"), self.s.csrf("bob"))
        self.assertNotEqual(self.s.csrf("anna"), Sessions(1).csrf("anna"))
        self.assertEqual(len(self.s.csrf("anna")), 32)


class Provider(BaseHTTPRequestHandler):
    """A test OpenID provider. ``CLAIMS`` overrides what goes into the next
    ID token; ``USERINFO`` is what /userinfo answers."""
    ISSUER = ""
    CLAIMS: dict = {}
    USERINFO: dict = {}
    CODES: dict = {}
    META: dict = {}

    def log_message(self, *a):
        return None

    def _json(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urlsplit(self.path)
        if url.path == "/.well-known/openid-configuration":
            return self._json(200, {"issuer": self.ISSUER,
                                    "authorization_endpoint": self.ISSUER + "/authorize",
                                    "token_endpoint": self.ISSUER + "/token",
                                    "userinfo_endpoint": self.ISSUER + "/userinfo",
                                    "end_session_endpoint": self.ISSUER + "/logout",
                                    **self.META})
        if url.path == "/userinfo":
            return self._json(200, self.USERINFO)
        return self._json(404, {})

    def do_POST(self):
        form = {k: v[0] for k, v in parse_qs(self.rfile.read(
            int(self.headers["Content-Length"])).decode()).items()}
        asked = self.CODES.pop(form.get("code"), None)
        if asked is None or b64(hashlib.sha256(form["code_verifier"].encode()).digest()) \
                != asked["code_challenge"]:
            return self._json(400, {"error": "invalid_grant"})
        now = int(time.time())
        claims = {"iss": self.ISSUER, "aud": "viewer", "sub": "u-1", "exp": now + 300,
                  "nonce": asked["nonce"], "preferred_username": "alice",
                  "groups": ["staff"], **self.CLAIMS}
        token = f"{b64(b'{}')}.{b64(json.dumps(claims).encode())}.{b64(b'sig')}"
        return self._json(200, {"id_token": token, "access_token": "at"})


class ProviderCase(unittest.TestCase):
    """A test provider and the OIDC settings that point at it."""

    def setUp(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        Provider.ISSUER = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        Provider.CLAIMS, Provider.USERINFO, Provider.CODES, Provider.META = {}, {}, {}, {}
        self.env = mock.patch.dict(os.environ, {
            "OIDC_ISSUER_URL": Provider.ISSUER, "OIDC_CLIENT_ID": "viewer",
            "OIDC_CLIENT_SECRET": "s3cret", "OIDC_ALLOW_HTTP": "true",
            "OIDC_REDIRECT_URI": "http://viewer.test/auth/callback", "OIDC_SCOPES": "",
            "OIDC_USERNAME_CLAIM": "", "OIDC_GROUPS_CLAIM": "", "OIDC_ADMIN_GROUP": ""})
        self.env.start()
        self.oidc = viewer_auth.OIDC()

    def tearDown(self):
        self.env.stop()
        self.httpd.shutdown()
        self.httpd.server_close()


class OidcTest(ProviderCase):
    def login(self, nxt="/m/x"):
        """The browser's trip to the provider: (code, state)."""
        url = urlsplit(self.oidc.start(nxt))
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        self.assertEqual((q["response_type"], q["code_challenge_method"], q["client_id"]),
                         ("code", "S256", "viewer"))
        code = os.urandom(8).hex()
        Provider.CODES[code] = q
        return code, q["state"]

    def test_login(self):
        code, state = self.login()
        self.assertEqual(self.oidc.finish(code, state), ("alice", ["staff"], "/m/x"))

    def test_state_is_used_once(self):
        code, state = self.login()
        self.oidc.finish(code, state)
        with self.assertRaisesRegex(ValueError, "unknown or expired"):
            self.oidc.finish(code, state)
        with self.assertRaisesRegex(ValueError, "unknown or expired"):
            self.oidc.finish(code, "made-up")

    def test_old_state_expires(self):
        code, state = self.login()
        self.oidc._pending[state]["t"] -= 601
        with self.assertRaises(ValueError):
            self.oidc.finish(code, state)

    def test_bad_id_tokens(self):
        for claims, msg in (({"iss": "https://evil.example"}, "issuer"),
                            ({"aud": "other"}, "another client"),
                            ({"aud": ["viewer", "other"]}, "another client"),     # no azp
                            ({"exp": int(time.time()) - 120}, "expired"),
                            ({"exp": None}, ""),
                            ({"nonce": "replayed"}, "nonce"),
                            ({"nonce": "é"}, "nonce")):            # no TypeError
            Provider.CLAIMS = {k: v for k, v in claims.items() if v is not None}
            if claims.get("exp", 1) is None:
                Provider.CLAIMS["exp"] = 0
            code, state = self.login()
            with self.assertRaisesRegex(ValueError, msg, msg=claims):
                self.oidc.finish(code, state)

    def test_several_audiences_with_azp(self):
        Provider.CLAIMS = {"aud": ["viewer", "other"], "azp": "viewer"}
        code, state = self.login()
        self.assertEqual(self.oidc.finish(code, state)[0], "alice")

    def test_groups_from_userinfo_only_for_the_same_subject(self):
        Provider.CLAIMS = {"groups": None}
        Provider.USERINFO = {"sub": "u-1", "groups": ["viewer-admins"]}
        # The ID token has no groups claim: drop it.
        Provider.CLAIMS = {"groups": []}
        with mock.patch.dict(os.environ, {"OIDC_GROUPS_CLAIM": "roles"}):
            oidc = viewer_auth.OIDC()
        self.oidc = oidc
        Provider.USERINFO = {"sub": "u-1", "roles": ["viewer-admins"]}
        code, state = self.login()
        self.assertEqual(self.oidc.finish(code, state)[1], ["viewer-admins"])
        Provider.USERINFO = {"sub": "someone-else", "roles": ["viewer-admins"],
                             "preferred_username": "mallory"}
        code, state = self.login()
        self.assertEqual(self.oidc.finish(code, state)[:2], ("alice", []))

    def test_no_user_named(self):
        Provider.CLAIMS = {"preferred_username": "", "sub": ""}
        code, state = self.login()
        with self.assertRaisesRegex(ValueError, "no user"):
            self.oidc.finish(code, state)

    def test_issuer_mismatch_in_discovery(self):
        Provider.META = {"issuer": "https://evil.example"}
        with self.assertRaisesRegex(ValueError, "issuer mismatch"):
            self.oidc.start("/")

    def test_pending_logins_are_bounded(self):
        for _ in range(1002):
            self.oidc.start("/")
        self.assertLessEqual(len(self.oidc._pending), 1001)

    def test_settings(self):
        for env, msg in (({"OIDC_CLIENT_SECRET": ""}, "OIDC_CLIENT_SECRET"),
                         ({"OIDC_SCOPES": "profile email"}, "openid"),
                         ({"OIDC_REDIRECT_URI": "http://viewer.test/callback"}, "auth/callback"),
                         ({"OIDC_ALLOW_HTTP": ""}, "https")):
            with mock.patch.dict(os.environ, env), self.assertRaisesRegex(SystemExit, msg):
                viewer_auth.OIDC()


class ProxyTest(unittest.TestCase):
    def make(self, ips="10.0.0.5, 172.18.0.0/16, fd00::/8", **env):
        with mock.patch.dict(os.environ, {"PROXY_TRUSTED_IPS": ips, "PROXY_USER_HEADER": "",
                                          "PROXY_GROUPS_HEADER": "X-Groups",
                                          "PROXY_ADMIN_GROUP": "", **env}):
            return viewer_auth.Proxy()

    def test_trusted_addresses(self):
        p = self.make()
        for addr, want in (("10.0.0.5", True), ("10.0.0.6", False), ("172.18.3.4", True),
                           ("::ffff:10.0.0.5", True), ("fd00::1", True), ("::1", False),
                           ("127.0.0.1", False), ("", False), ("not-an-ip", False)):
            self.assertEqual(p.trusts(addr), want, addr)

    def test_headers_only_from_the_proxy(self):
        p = self.make()
        headers = {"X-authentik-username": " bob ", "X-Groups": "a|b| |c"}
        self.assertEqual(p.user("10.0.0.5", headers), ("bob", ["a", "b", "c"]))
        self.assertIsNone(p.user("10.0.0.9", headers))
        self.assertIsNone(p.user("10.0.0.5", {"X-Groups": "a"}))
        self.assertEqual(p.user("10.0.0.5", {"X-authentik-username": "bob",
                                             "X-Groups": "x, y"})[1], ["x", "y"])

    def test_settings(self):
        with self.assertRaisesRegex(SystemExit, "PROXY_TRUSTED_IPS"):
            self.make(ips="")
        with self.assertRaisesRegex(SystemExit, "PROXY_TRUSTED_IPS"):
            self.make(ips="10.0.0.0/8, nonsense")


class AuthTest(unittest.TestCase):
    """viewer.auth.Auth: modes, the first admin, and who comes in."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.patches = [
            mock.patch.object(viewer_auth, "STATE_DIR", Path(self.tmp.name)),
            mock.patch.object(viewer_auth, "log"),
            mock.patch.dict(os.environ, {
                "USERS_DB": str(Path(self.tmp.name) / "users.db"), "VIEWER_AUTH_MODE": "local",
                "AUTH_MODE": "", "ADMIN_USER": "boss", "ADMIN_PASSWORD": "boss-password",
                "VIEWER_USER": "", "VIEWER_PASSWORD": "", "VIEWER_GUEST": "",
                "PROXY_TRUSTED_IPS": "10.0.0.5", "PROXY_ADMIN_GROUP": "admins",
                "PROXY_GROUPS_HEADER": "X-Groups"})]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def test_modes(self):
        with mock.patch.dict(os.environ, {"VIEWER_AUTH_MODE": "open"}):
            with self.assertRaisesRegex(SystemExit, "VIEWER_AUTH_MODE"):
                viewer_auth.Auth()
        with mock.patch.dict(os.environ, {"ADMIN_PASSWORD": ""}):
            with self.assertRaisesRegex(SystemExit, "VIEWER_AUTH_MODE=none"):
                viewer_auth.Auth()
        a = viewer_auth.Auth()
        self.assertIsNone(a.login("boss", "wrong"))
        self.assertTrue(a.login("boss", "boss-password").admin)
        self.assertIsNone(a.link_login("itv_made-up"))
        self.assertIsNone(a.guest_login())

    def test_a_provider_user_cannot_take_over_a_local_one(self):
        viewer_auth.Auth()                                     # makes the local admin boss
        with mock.patch.dict(os.environ, {"VIEWER_AUTH_MODE": "proxy"}):
            a = viewer_auth.Auth()
        self.assertIsNone(a.from_proxy("10.0.0.5", {"X-authentik-username": "boss",
                                                    "X-Groups": "admins"}))
        self.assertIsNone(a.from_proxy("10.0.0.5", {"X-authentik-username": "BOSS"}))
        bob = a.from_proxy("10.0.0.5", {"X-authentik-username": "bob", "X-Groups": "admins"})
        self.assertTrue(bob.admin)                              # the group decides
        bob = a.from_proxy("10.0.0.5", {"X-authentik-username": "bob", "X-Groups": "staff"})
        self.assertFalse(bob.admin)
        self.assertIsNone(a.from_proxy("10.0.0.6", {"X-authentik-username": "bob"}))
        a.users.set_active("bob", False)
        self.assertIsNone(a.from_proxy("10.0.0.5", {"X-authentik-username": "bob"}))
        self.assertTrue(a.disabled("bob"))

    def test_sessions_follow_the_user_list(self):
        a = viewer_auth.Auth()
        a.users.create("anna", "anna-pass")
        anna = a.login("anna", "anna-pass")
        self.assertEqual(a.current(anna).role, "user")
        a.users.set_role("anna", "admin")
        self.assertEqual(a.current(anna).role, "admin")          # the role it has now
        a.users.set_role("anna", "user")
        a.users.set_rights("anna", web=False)
        self.assertIsNone(a.current(anna))
        a.users.set_rights("anna", web=True)
        a.users.delete("anna")
        self.assertIsNone(a.current(anna))
        # A forged "link" session without the link's token id.
        acc, token = a.users.create_link("Visitor")
        self.assertIsNone(a.current(User("Visitor", "user", "link", "")))
        self.assertIsNone(a.current(User("Visitor", "user", "local", "")))
        user = a.link_login(token)
        self.assertEqual(a.current(user), user)
        a.users.new_link("Visitor")                              # replaced: the old one ends
        self.assertIsNone(a.current(user))

    def test_guest(self):
        with mock.patch.dict(os.environ, {"VIEWER_GUEST": "true"}):
            a = viewer_auth.Auth()
        guest = a.guest_login()
        self.assertEqual(guest.source, "guest")
        self.assertFalse(guest.admin)
        a.guest = False                                          # switched off again
        self.assertIsNone(a.current(guest))
        with mock.patch.dict(os.environ, {"VIEWER_GUEST": "true", "VIEWER_AUTH_MODE": "proxy"}):
            self.assertFalse(viewer_auth.Auth().guest)           # not with a proxy


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class OidcViewerTest(ProviderCase):
    """The OIDC login through the viewer over HTTP: /auth/login, the
    provider, /auth/callback, the session; and what it refuses."""

    def setUp(self):
        super().setUp()
        from viewer import server
        self.tmp = tempfile.TemporaryDirectory()
        self.env2 = mock.patch.dict(os.environ, {
            "VIEWER_AUTH_MODE": "oidc", "USERS_DB": str(Path(self.tmp.name) / "users.db"),
            "VIEWER_AUDIT_FILE": str(Path(self.tmp.name) / "audit.log"),
            "OIDC_ADMIN_GROUP": "viewer-admins", "VIEWER_GUEST": "", "ADMIN_PASSWORD": ""})
        self.env2.start()
        self.patches = [mock.patch.object(viewer_auth, "STATE_DIR", Path(self.tmp.name)),
                        mock.patch.object(viewer_auth, "log"),
                        mock.patch("sys.stderr", __import__("io").StringIO())]
        for p in self.patches:
            p.start()
        self.server = server
        self.saved = getattr(server, "auth", None)
        server.auth = viewer_auth.Auth()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.opener = urllib.request.build_opener(NoRedirect)

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.server.auth = self.saved
        for p in reversed(self.patches):
            p.stop()
        self.env2.stop()
        self.tmp.cleanup()
        super().tearDown()

    def get(self, path, cookie=""):
        r = urllib.request.Request(self.base + path, headers={
            "Accept": "text/html", **({"Cookie": cookie} if cookie else {})})
        try:
            with self.opener.open(r, timeout=10) as resp:
                return resp.status, resp.headers, resp.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read().decode()

    def browser_login(self, nxt="/account"):
        status, headers, _ = self.get("/auth/login?" + urlencode({"next": nxt}))
        self.assertEqual(status, 303)
        q = {k: v[0] for k, v in parse_qs(urlsplit(headers["Location"]).query).items()}
        code = os.urandom(8).hex()
        Provider.CODES[code] = q
        return self.get("/auth/callback?" + urlencode({"code": code, "state": q["state"]}))

    def test_login_and_admin_group(self):
        self.assertEqual(self.get("/")[0], 303)
        Provider.CLAIMS = {"groups": ["viewer-admins"]}
        status, headers, _ = self.browser_login("/admin")
        self.assertEqual((status, headers["Location"]), (303, "/admin"))
        cookie = headers["Set-Cookie"].split(";")[0]
        self.assertEqual(self.get("/admin", cookie)[0], 200)
        Provider.CLAIMS = {"groups": ["staff"]}                  # the group decides each time
        cookie = self.browser_login()[1]["Set-Cookie"].split(";")[0]
        self.assertEqual(self.get("/admin", cookie)[0], 403)

    def test_next_stays_on_this_server(self):
        for bad in ("//evil.example", "https://evil.example", "/\t/evil.example"):
            status, headers, _ = self.browser_login(bad)
            self.assertEqual((status, headers["Location"]), (303, "/"), bad)

    def test_callback_refusals(self):
        status, _, page = self.get("/auth/callback?code=x&state=made-up")
        self.assertEqual(status, 400)
        self.assertIn("unknown or expired", page)
        status, _, page = self.get("/auth/callback?" + urlencode({
            "error": "access_denied", "error_description": "<b>no</b>"}))
        self.assertEqual(status, 400)
        self.assertNotIn("<b>no</b>", page)
        Provider.CLAIMS = {"nonce": "other"}
        status, _, page = self.browser_login()
        self.assertEqual(status, 400)
        self.assertNotIn("Set-Cookie", dict(self.get("/")[1]))

    def test_provider_name_of_a_local_user_is_refused(self):
        self.server.auth.users.create("alice", "alice-pass", "admin")
        status, headers, _ = self.browser_login()
        self.assertEqual(status, 403)
        self.assertIsNone(headers.get("Set-Cookie"))

    def test_switched_off_user(self):
        cookie = self.browser_login()[1]["Set-Cookie"].split(";")[0]
        self.assertEqual(self.get("/account", cookie)[0], 200)
        self.server.auth.users.set_active("alice", False)
        self.assertEqual(self.get("/account", cookie)[0], 403)
        self.assertEqual(self.browser_login()[0], 403)

    def test_logout_offers_the_provider(self):
        cookie = self.browser_login()[1]["Set-Cookie"].split(";")[0]
        status, headers, page = self.get("/logout", cookie)
        self.assertEqual(status, 200)
        self.assertIn("Max-Age=0", headers["Set-Cookie"])
        self.assertIn(Provider.ISSUER + "/logout?client_id=viewer", page)


if __name__ == "__main__":
    unittest.main()
