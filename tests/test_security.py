# SPDX-License-Identifier: AGPL-3.0-or-later
"""Security tests of the viewer and the gateway over HTTP: redirects and
header injection, cookies, CSRF, who may see and change what, path
traversal, escaping, secrets kept out of logs, HTTP desync, and the
compose file's hardening. A fake engine renders two models; no container
needed:

    python -m unittest discover -s tests -p "test_*.py"

A gap that is still open gets a test marked ``expectedFailure`` (its
docstring says what is open); it turns into an error once the gap is
closed, so the marker goes then.
"""
from __future__ import annotations

import io
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock
from urllib.parse import quote, urlencode

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp_http import folders  # noqa: E402
from viewer import render  # noqa: E402
from tests.test_render import FakeApp  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
FULL = bool(os.environ.get("FULL_TEST"))
XSS = '<script>alert("x")</script>'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def raw_http(port: int, data: bytes, timeout: float = 3.0) -> bytes:
    """Everything the server sends back on one connection."""
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        s.sendall(data)
        got = b""
        try:
            while chunk := s.recv(65536):
                got += chunk
        except TimeoutError:
            pass
    return got


class Viewer(unittest.TestCase):
    """A viewer with the local login, users boss (admin) and anna (only the
    folder ``p``), two rendered models: p/house.igz and q/secret.igz."""

    EXTRA_ENV: dict = {}

    def setUp(self):
        from viewer import auth as auth_mod
        from viewer import server
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name).resolve()
        self.data, self.cache = base / "data", base / "cache"
        for rel in ("p/house.igz", "q/secret.igz"):
            (self.data / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.data / rel).write_bytes(b"model")
            os.utime(self.data / rel, (time.time() - 60, time.time() - 60))
        self.audit_file = base / "audit.log"
        self.env = mock.patch.dict(os.environ, {
            "VIEWER_AUTH_MODE": "local", "ADMIN_USER": "boss", "ADMIN_PASSWORD": "boss-password",
            "USERS_DB": str(base / "users.db"), "VIEWER_AUDIT_FILE": str(self.audit_file),
            "INGETRAZO_STATE": str(base), "VIEWER_GUEST": "", "VIEWER_COOKIE_SECURE": "",
            "DEFAULT_SHARES": "", **self.EXTRA_ENV})
        self.env.start()
        self.saved = (folders.DATA_DIR, folders.FOLDERS, render.DATA_DIR, render.CACHE_DIR,
                      render.PRERENDER, server.CACHE_DIR, auth_mod.STATE_DIR,
                      getattr(server, "auth", None), getattr(server, "renderer", None))
        folders.DATA_DIR = render.DATA_DIR = self.data
        folders.FOLDERS = folders.parse("p:rw; q:rw", data_dir=self.data)
        render.CACHE_DIR = server.CACHE_DIR = self.cache
        render.PRERENDER = "previews"
        auth_mod.STATE_DIR = base
        self.server = server
        self.stderr = mock.patch("sys.stderr", io.StringIO())
        self.stderr.start()
        server.auth = auth_mod.Auth()
        server.auth.users.create("anna", "anna-pass")
        server.auth.users.set_shares("anna", [{"path": "p", "access": "r"}])
        app = FakeApp()
        app.alive = lambda: True
        self.renderer = server.renderer = render.Renderer(app)
        self.slugs = {m["name"]: m["slug"] for m in self.renderer.models()}
        for slug in self.slugs.values():
            self.renderer.request(slug, "preview")
        while not self.renderer.queue.empty():
            slug, item, prio = self.renderer.queue.pop(None)
            self.renderer._task(slug, item, prio)
        self.httpd = server.Server(("127.0.0.1", 0), server.Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.port = self.httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.opener = urllib.request.build_opener(NoRedirect)

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.stderr.stop()
        (folders.DATA_DIR, folders.FOLDERS, render.DATA_DIR, render.CACHE_DIR, render.PRERENDER,
         self.server.CACHE_DIR, state, self.server.auth, self.server.renderer) = self.saved
        from viewer import auth as auth_mod
        auth_mod.STATE_DIR = state
        self.env.stop()
        self.tmp.cleanup()

    # ---- helpers ---------------------------------------------------------------
    def req(self, path, data=None, cookie="", accept="text/html", headers=None, method=None):
        body = urlencode(data).encode() if isinstance(data, dict) else data
        h = {"Accept": accept, **({"Cookie": cookie} if cookie else {}), **(headers or {})}
        r = urllib.request.Request(self.base + path, body, h, method=method)
        try:
            with self.opener.open(r, timeout=10) as resp:
                return resp.status, resp.headers, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read().decode("utf-8", "replace")

    def login(self, name, pw, nxt="/"):
        status, headers, _ = self.req("/login", {"user": name, "password": pw, "next": nxt})
        self.assertEqual(status, 303, name)
        return headers["Set-Cookie"].split(";")[0]

    def csrf(self, cookie, path="/account"):
        page = self.req(path, cookie=cookie)[2]
        return re.search(r'name="csrf" value="([0-9a-f]+)"', page).group(1)

    def file_url(self, name):
        html = self.server.overview().decode()
        slug = self.slugs[name]
        return re.search(rf'src="(/files/{re.escape(slug)}/[^"]+)"', html).group(1)


class RedirectTest(Viewer):
    BAD = ("//evil.example", "/\\evil.example", "/\t/evil.example", "/\r\nSet-Cookie: x=1",
           "/\nX-Injected: 1", "https://evil.example", "javascript:alert(1)", "evil.example",
           "", "/%0d%0aX: 1\x00", "\\\\evil.example", "/\x0b/evil.example")

    def test_login_next(self):
        from viewer.server import _safe_next
        for bad in self.BAD:
            self.assertIn(_safe_next(bad), ("/", "/%0d%0aX: 1\x00"[:0] or "/"), repr(bad))
        for good in ("/", "/m/x?view=2", "/admin/shares?name=a%20b", "/%0d%0a"):
            self.assertEqual(_safe_next(good), good)

    def test_login_redirect_never_leaves_or_splits(self):
        for bad in self.BAD:
            status, headers, _ = self.req("/login", {"user": "boss", "password": "boss-password",
                                                     "next": bad})
            self.assertEqual((status, headers["Location"]), (303, "/"), repr(bad))
            self.assertEqual(len(headers.get_all("Set-Cookie")), 1, repr(bad))
            self.assertIsNone(headers.get("X-Injected"))

    def test_access_link_and_guest_next(self):
        acc, token = self.server.auth.users.create_link("Visitor")
        for bad in self.BAD:
            status, headers, _ = self.req(f"/t/{token}?" + urlencode({"next": bad}))
            self.assertEqual((status, headers["Location"]), (303, "/"), repr(bad))
            self.assertIsNone(headers.get("X-Injected"))
        self.server.auth.guest = True
        self.server.auth.users.ensure_guest()
        for bad in self.BAD:
            status, headers, _ = self.req("/login/guest", {"next": bad})
            self.assertEqual((status, headers["Location"]), (303, "/"), repr(bad))

    def test_raw_line_breaks_in_the_request(self):
        for target in ("/login?next=/%0d%0aX-Injected:%201", "/login?next=%0aX-Injected:1"):
            got = raw_http(self.port, f"GET {target} HTTP/1.1\r\nHost: x\r\n"
                                      "Connection: close\r\n\r\n".encode())
            head = got.split(b"\r\n\r\n")[0]
            self.assertNotIn(b"\nX-Injected", head, target)

    def test_no_header_ever_carries_a_line_break(self):
        """The handler's last line of defence (send_header)."""
        from viewer.server import Handler
        h = Handler.__new__(Handler)
        h._headers_buffer = []
        h.request_version = "HTTP/1.1"
        with self.assertRaises(ValueError):
            h.send_header("Location", "/\r\nSet-Cookie: x=1")
        with self.assertRaises(ValueError):
            h.send_header("Location", "/\nX: 1")
        h.send_header("Location", "/fine")


class CookieTest(Viewer):
    def test_flags(self):
        _, headers, _ = self.req("/login", {"user": "boss", "password": "boss-password"})
        cookie = headers["Set-Cookie"]
        for part in ("HttpOnly", "SameSite=Lax", "Path=/"):
            self.assertIn(part, cookie)
        self.assertNotIn("Secure", cookie)
        _, headers, _ = self.req("/login", {"user": "boss", "password": "boss-password"},
                                 headers={"X-Forwarded-Proto": "https"})
        self.assertIn("; Secure", headers["Set-Cookie"])
        with mock.patch.dict(os.environ, {"VIEWER_COOKIE_SECURE": "true"}):
            _, headers, _ = self.req("/login", {"user": "boss", "password": "boss-password"})
        self.assertIn("; Secure", headers["Set-Cookie"])

    def test_logout_clears_it(self):
        boss = self.login("boss", "boss-password")
        status, headers, _ = self.req("/logout", cookie=boss)
        self.assertEqual(status, 303)
        self.assertIn("Max-Age=0", headers["Set-Cookie"])

    def test_forged_and_foreign_sessions(self):
        from viewer.auth import Sessions, User
        anna = self.login("anna", "anna-pass")
        value = anna.split("=", 1)[1]
        payload, _, sig = value.partition(".")
        import base64
        data = json.loads(base64.urlsafe_b64decode(payload + "=="))
        forged = base64.urlsafe_b64encode(json.dumps({**data, "u": "boss", "r": "admin"})
                                          .encode()).rstrip(b"=").decode()
        foreign = Sessions(30).issue(User("boss", "admin"))
        for cookie in (f"itz_viewer={forged}.{sig}", f"itz_viewer={foreign}",
                       'itz_viewer="\\351.\\351"', "itz_viewer=é.é", "itz_viewer=",
                       "itz_viewer=" + "a" * 5000):
            status, headers, _ = self.req("/admin", cookie=cookie)
            self.assertEqual(status, 303, cookie[:40])
            self.assertTrue(headers["Location"].startswith("/login"))
        self.assertIn("boss", self.req("/admin", cookie=self.login("boss", "boss-password"))[2])

    def test_session_ends_when_the_password_changes_hands(self):
        """A session belongs to its user: deleting the user ends it, and a
        new user of the same name does not inherit it as admin."""
        users = self.server.auth.users
        users.create("carl", "carl-pass", "admin")
        carl = self.login("carl", "carl-pass")
        users.delete("carl")
        self.assertEqual(self.req("/account", cookie=carl)[0], 303)
        users.create("carl", "carl-pass2")
        self.assertEqual(self.req("/admin", cookie=carl)[0], 403)      # a user now


class CsrfTest(Viewer):
    def test_every_form_needs_its_token(self):
        boss = self.login("boss", "boss-password")
        anna = self.login("anna", "anna-pass")
        anna_token = self.csrf(anna)
        for path, form in (("/admin", {"action": "create", "name": "eve", "password": "eve-pass1",
                                       "role": "admin"}),
                           ("/admin/renders", {"action": "render-all"}),
                           ("/account", {"action": "token", "label": "x"}),
                           ("/account/settings", {"theme": "dark"})):
            for token in (None, "", "0" * 32, anna_token, "é" * 32):
                data = dict(form, **({"csrf": token} if token is not None else {}))
                status, _, _ = self.req(path, data, cookie=boss)
                self.assertEqual(status, 403, (path, token))
        self.assertIsNone(self.server.auth.users.get("eve"))
        self.assertEqual(self.server.auth.users.tokens("boss"), [])

    def test_get_never_changes_anything(self):
        boss = self.login("boss", "boss-password")
        self.req("/admin?" + urlencode({"action": "create", "name": "eve",
                                         "password": "eve-pass1"}), cookie=boss)
        self.req("/account?action=token", cookie=boss)
        self.assertIsNone(self.server.auth.users.get("eve"))
        self.assertEqual(self.server.auth.users.tokens("boss"), [])


class RightsTest(Viewer):
    ADMIN_GET = ("/admin", "/admin/renders", "/admin/log", "/admin/log.jsonl",
                 "/admin/shares?name=anna")

    def test_users_are_no_admins(self):
        anna = self.login("anna", "anna-pass")
        token = self.csrf(anna)
        for path in self.ADMIN_GET:
            self.assertEqual(self.req(path, cookie=anna)[0], 403, path)
        for path, form in (("/admin", {"action": "role", "name": "anna", "role": "admin"}),
                           ("/admin", {"action": "create", "name": "eve", "password": "eve-pass1",
                                       "role": "admin"}),
                           ("/admin", {"action": "password", "name": "boss",
                                       "password": "taken-over"}),
                           ("/admin", {"action": "title", "title": XSS}),
                           ("/admin/renders", {"action": "render-all"})):
            status, _, _ = self.req(path, {**form, "csrf": token}, cookie=anna)
            self.assertEqual(status, 403, form)
        self.assertEqual(self.server.auth.users.get("anna").role, "user")
        self.assertIsNotNone(self.server.auth.users.authenticate("boss", "boss-password"))

    def test_nobody_without_login(self):
        acc_slug = self.slugs["p/house.igz"]
        for path in ("/", "/admin", "/account", f"/m/{acc_slug}", self.file_url("p/house.igz"),
                     "/version", "/avatar/boss.svg", "/admin/log.jsonl", "/events"):
            status, headers, _ = self.req(path, accept="*/*")
            self.assertIn(status, (401, 303), path)
            status, headers, _ = self.req(path)
            self.assertIn(status, (401, 303), path)
        for path in ("/admin", "/account", "/account/settings", "/admin/renders"):
            self.assertIn(self.req(path, {"csrf": "x"})[0], (401, 303, 403), path)
        status, _, body = self.req("/healthz")
        self.assertEqual(set(json.loads(body)), {"status"})

    def test_models_and_files_of_other_folders(self):
        anna = self.login("anna", "anna-pass")
        boss = self.login("boss", "boss-password")
        secret, house = self.slugs["q/secret.igz"], self.slugs["p/house.igz"]
        secret_file, house_file = self.file_url("q/secret.igz"), self.file_url("p/house.igz")
        self.assertNotIn("secret", self.req("/", cookie=anna)[2])
        self.assertEqual(self.req(f"/m/{secret}", cookie=anna)[0], 404)
        self.assertEqual(self.req(f"/m/{secret}?pdf=1", cookie=anna)[0], 404)
        self.assertEqual(self.req(secret_file, cookie=anna)[0], 404)
        self.assertEqual(self.req(house_file, cookie=anna)[0], 200)
        self.assertEqual(self.req(secret_file, cookie=boss)[0], 200)
        self.assertEqual(self.req(f"/m/{house}", cookie=anna)[0], 200)

    def test_access_links(self):
        users = self.server.auth.users
        acc, token = users.create_link("Visitor")
        users.set_shares("Visitor", [{"path": "p", "access": "r"}])
        bearer = {"Authorization": f"Bearer {token}"}
        self.assertEqual(self.req(self.file_url("p/house.igz"), headers=bearer)[0], 200)
        self.assertEqual(self.req(self.file_url("q/secret.igz"), headers=bearer)[0], 404)
        self.assertEqual(self.req("/admin", headers=bearer)[0], 403)
        self.assertEqual(self.req("/", headers={"Authorization": f"Bearer {token}x"})[0], 303)
        # A link is never an admin, and has no password for Basic auth.
        with self.assertRaises(Exception):
            users.set_role("Visitor", "admin")
        users.set_active("Visitor", False)
        self.assertEqual(self.req("/", headers=bearer)[0], 303)
        users.set_active("Visitor", True)
        self.assertEqual(self.req("/", headers=bearer)[0], 200)
        users.new_link("Visitor")                                 # replaced
        self.assertEqual(self.req("/", headers=bearer)[0], 303)

    def test_basic_auth_for_scripts(self):
        import base64
        good = base64.b64encode(b"anna:anna-pass").decode()
        self.assertEqual(self.req("/version", headers={"Authorization": f"Basic {good}"},
                                  accept="*/*")[0], 200)
        for value in (base64.b64encode(b"anna:wrong").decode(), "!!!", "",
                      base64.b64encode(b"\xff\xfe:x").decode()):
            status = self.req("/version", headers={"Authorization": f"Basic {value}"},
                              accept="*/*")[0]
            self.assertEqual(status, 401, value)


class TraversalTest(Viewer):
    def test_files(self):
        boss = self.login("boss", "boss-password")
        slug = self.slugs["p/house.igz"]
        rev = self.file_url("p/house.igz").split("/")[3]
        (self.cache / slug / rev / ".hidden.png").write_bytes(b"x")
        for path in (f"/files/{slug}/index.json", f"/files/{slug}/{rev}/../index.json",
                     f"/files/{slug}/{rev}/%2e%2e/index.json", f"/files/{slug}/..%2f..%2findex.json",
                     f"/files/{slug}/{rev}/.hidden.png", f"/files/{slug}/{rev}/x/y.png",
                     "/files/../users.db", "/files/%2e%2e/%2e%2e/etc/passwd",
                     f"/files/{slug}/{rev}/%00.png", "/files/", "/files//x/y"):
            status, _, body = self.req(path, cookie=boss, accept="*/*")
            self.assertEqual(status, 404, path)
        self.assertEqual(self.req(self.file_url("p/house.igz"), cookie=boss)[0], 200)

    def test_static_and_avatars(self):
        boss = self.login("boss", "boss-password")
        for path in ("/static/three/../../server.py", "/static/three/%2e%2e/auth.py",
                     "/static/three/..", "/static/three/.%2e/x", "/avatar/..%2fboss.svg",
                     "/avatar/nobody.svg", "/m/..%2f..%2fetc", "/m/" + "a" * 300):
            status, _, body = self.req(path, cookie=boss, accept="*/*")
            self.assertEqual(status, 404, path)
            self.assertNotIn("import", body)

    def test_avatar_is_inert(self):
        boss = self.login("boss", "boss-password")
        status, headers, body = self.req("/avatar/boss.svg", cookie=boss)
        self.assertEqual(status, 200)
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
        self.assertNotIn("<script", body)


class EscapingTest(Viewer):
    def test_names_from_outside_are_escaped(self):
        boss = self.login("boss", "boss-password")
        token = self.csrf(boss, "/admin")
        # An access link's free-text name, the site title, a provider's group name.
        self.req("/admin", {"action": "link_create", "name": XSS, "csrf": token}, cookie=boss)
        self.req("/admin", {"action": "title", "title": XSS, "csrf": token}, cookie=boss)
        self.server.auth.users.seen("carl", "oidc", [XSS], None)
        for path in ("/admin", "/", "/account", "/admin/shares?name=" + quote(XSS),
                     "/admin/shares?name=anna&check=" + quote(XSS),
                     "/admin/log?q=" + quote(XSS) + "&user=" + quote(XSS),
                     "/admin/renders"):
            status, _, page = self.req(path, cookie=boss)
            self.assertNotIn(XSS, page, path)
        self.assertNotIn(XSS, self.req("/login")[2])

    def test_request_data_in_the_log_page_is_escaped(self):
        self.req("/nowhere" + quote(XSS), headers={"X-Forwarded-For": XSS})
        self.req("/login", {"user": XSS, "password": "x"})
        boss = self.login("boss", "boss-password")
        page = self.req("/admin/log", cookie=boss)[2]
        self.assertNotIn(XSS, page)
        self.assertIn("&lt;script&gt;", page)

    def test_model_file_names_are_escaped(self):
        name = '<img src=x onerror="alert(1)">'            # a file name may hold that
        (self.data / "p" / f"{name}.igz").write_bytes(b"model")
        os.utime(self.data / "p" / f"{name}.igz", (time.time() - 60, time.time() - 60))
        self.renderer._refresh_models()
        boss = self.login("boss", "boss-password")
        page = self.req("/", cookie=boss)[2]
        self.assertFalse(name in page, "the raw name is in the overview")
        self.assertTrue("&lt;img" in page, "the escaped name is not in the overview")
        slug = next(m["slug"] for m in self.renderer.models() if "onerror" in m["name"])
        self.assertRegex(slug, r"^[A-Za-z0-9._-]+$")
        self.assertNotIn(name, self.req(f"/m/{slug}", cookie=boss)[2])


class SecretsTest(Viewer):
    def test_tokens_stay_out_of_logs(self):
        boss = self.login("boss", "boss-password")
        token = self.csrf(boss, "/admin")
        page = self.req("/admin", {"action": "link_create", "name": "Visitor", "csrf": token},
                        cookie=boss)[2]
        link = re.search(r"/t/(itv_[A-Za-z0-9_-]+)", page).group(1)
        self.server.auth.users.set_rights("boss", mcp=True)
        page = self.req("/account", {"action": "token", "label": "x", "csrf": token},
                        cookie=boss)[2]
        mcp = re.search(r"itz_[A-Za-z0-9_-]+", page).group(0)
        self.req(f"/t/{link}")
        self.req(f"/t/{link}x")
        self.req("/", headers={"Authorization": f"Bearer {link}"})
        logs = self.audit_file.read_text() + sys.stderr.getvalue()
        for secret in (link, mcp, "boss-password", "anna-pass"):
            self.assertNotIn(secret, logs)
        # Only hashes in the database.
        db = Path(os.environ["USERS_DB"]).read_bytes()
        self.assertNotIn(link.encode(), db)
        self.assertNotIn(mcp.encode(), db)
        self.assertNotIn(b"boss-password", db)

    def test_secrets_are_not_shown_again(self):
        boss = self.login("boss", "boss-password")
        token = self.csrf(boss, "/admin")
        self.req("/admin", {"action": "link_create", "name": "Visitor", "csrf": token},
                 cookie=boss)
        for path in ("/admin", "/admin/shares?name=Visitor", "/admin/log", "/admin/log.jsonl"):
            self.assertNotRegex(self.req(path, cookie=boss)[2], r"itv_[A-Za-z0-9_-]{20}", path)


class DesyncTest(Viewer):
    """A body the server does not read must not become a request of its own
    on a kept-alive connection (behind a proxy: another user's reply)."""

    def test_unread_bodies_close_the_connection(self):
        inner = "GET /version HTTP/1.1\r\nHost: x\r\n\r\n"
        for head in ("POST /admin HTTP/1.1", "POST /nowhere HTTP/1.1",
                     "GET /login HTTP/1.1", "POST /login/guest HTTP/1.1"):
            got = raw_http(self.port, f"{head}\r\nHost: x\r\nContent-Length: {len(inner)}"
                                      f"\r\n\r\n{inner}".encode())
            self.assertEqual(got.count(b"HTTP/1.1 "), 1, head)
        got = raw_http(self.port, b"POST /login HTTP/1.1\r\nHost: x\r\n"
                                  b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n" + inner.encode())
        self.assertEqual(got.count(b"HTTP/1.1 "), 1)

    def test_keep_alive_still_works(self):
        req = b"GET /login HTTP/1.1\r\nHost: x\r\n\r\n"
        got = raw_http(self.port, req * 3, timeout=1.0)
        self.assertEqual(got.count(b"HTTP/1.1 200"), 3)


class HeadersTest(Viewer):
    """Response headers that keep a browser from misusing the pages."""

    def test_private_pages_are_not_cached(self):
        boss = self.login("boss", "boss-password")
        for path in ("/", "/admin", "/account", "/admin/log", "/admin/log.jsonl"):
            _, headers, _ = self.req(path, cookie=boss)
            self.assertEqual(headers["Cache-Control"], "no-store", path)

    def test_pages_cannot_be_framed_by_other_sites(self):
        """Clickjacking of the admin panel: only the viewer itself may frame
        its pages (VIEWER_FRAME_ANCESTORS widens or narrows that)."""
        boss = self.login("boss", "boss-password")
        for path in ("/login", "/", "/admin", "/account", "/nowhere"):
            _, headers, _ = self.req(path, cookie=boss)
            self.assertEqual(headers["X-Frame-Options"], "SAMEORIGIN", path)
            self.assertEqual(headers["Content-Security-Policy"], "frame-ancestors 'self'", path)
            self.assertEqual(headers["Referrer-Policy"], "same-origin", path)

    def test_frame_ancestors_setting(self):
        from viewer.server import security_headers
        for raw, xfo, csp in (
                ("none", "DENY", "frame-ancestors 'none'"),
                ("*", None, None),
                ("https://ha.example.org, http://wiki.lan:8123",
                 None, "frame-ancestors 'self' https://ha.example.org http://wiki.lan:8123"),
                ("https://ha.example.org; script-src *", None,           # no CSP injection
                 "frame-ancestors 'self' https://ha.example.org")):
            with mock.patch.dict(os.environ, {"VIEWER_FRAME_ANCESTORS": raw}):
                h = security_headers()
            self.assertEqual(h.get("X-Frame-Options"), xfo, raw)
            self.assertEqual(h.get("Content-Security-Policy"), csp, raw)
            self.assertEqual(h["X-Content-Type-Options"], "nosniff")

    def test_no_sniffing(self):
        boss = self.login("boss", "boss-password")
        for path in (self.file_url("p/house.igz"), "/", "/version", "/healthz"):
            _, headers, _ = self.req(path, cookie=boss)
            self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff", path)

    def test_the_access_link_keeps_its_own_referrer_policy(self):
        _, token = self.server.auth.users.create_link("Visitor")
        _, headers, _ = self.req(f"/t/{token}")
        self.assertEqual(headers.get_all("Referrer-Policy"), ["no-referrer"])


class GatewayDesyncTest(unittest.TestCase):
    def test_unread_bodies_close_the_connection(self):
        from mcp_http import auth as mcp_auth
        from mcp_http import server
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with mock.patch.dict(os.environ, {"MCP_AUTH": "token", "MCP_TOKEN": "t" * 20,
                                          "USERS_DB": str(Path(tmp.name) / "users.db")}), \
                mock.patch.object(mcp_auth, "log"), \
                mock.patch("sys.stderr", io.StringIO()):
            saved = getattr(server, "auth", None), getattr(server, "app", None)
            server.auth = mcp_auth.Auth()
            server.app = mock.Mock(probe=mock.Mock(return_value=(200, {"status": "ok"})))
            httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            try:
                inner = "GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n"
                for head in ("POST /mcp HTTP/1.1", "POST /nowhere HTTP/1.1",
                             "GET / HTTP/1.1", "DELETE /mcp HTTP/1.1"):
                    got = raw_http(httpd.server_address[1],
                                   f"{head}\r\nHost: x\r\nContent-Length: {len(inner)}"
                                   f"\r\n\r\n{inner}".encode())
                    self.assertEqual(got.count(b"HTTP/1.1 "), 1, head)
            finally:
                httpd.shutdown()
                httpd.server_close()
                server.auth, server.app = saved


class StorageTest(Viewer):
    """What is stored, and how."""

    def test_names_never_become_sql(self):
        users = self.server.auth.users
        name = "Robert'); DROP TABLE users;--"
        acc, token = users.create_link(name)
        self.assertEqual(users.get(name).name, name)
        users.set_shares(name, [{"path": "p/%_'\"", "access": "r"}])
        self.assertEqual(users.get(name).shares, [{"path": "p/%_'\"", "access": "r"}])
        self.assertIsNotNone(users.get("boss"))                 # the table is still there
        self.assertFalse(users.revoke_token("boss", "%"))       # no LIKE wildcards
        self.assertFalse(users.revoke_token("boss", "' OR 1=1 --"))
        self.assertIsNone(users.authenticate("boss' --", "x"))
        self.assertIsNone(users.authenticate("%", "boss-password"))

    def test_audit_lines_cannot_be_forged(self):
        """Line breaks in what a client sends stay inside one JSON entry."""
        self.req("/x%0a%7B%22kind%22%3A%22admin%22%7D")
        self.req("/login", {"user": 'eve\n{"kind": "admin", "user": "boss"}', "password": "x"})
        lines = self.audit_file.read_text().splitlines()
        entries = [json.loads(line) for line in lines]           # every line is JSON
        self.assertFalse([e for e in entries if e.get("kind") == "admin"])

    def test_private_files_are_not_world_readable(self):
        """users.db (password and token hashes) and audit.log (IP
        addresses): owner only, like oauth.json and the secrets."""
        self.req("/login", {"user": "boss", "password": "wrong"})
        db = Path(os.environ["USERS_DB"])
        for f in (db, Path(str(db) + "-wal"), self.audit_file):
            if f.exists():
                self.assertEqual(f.stat().st_mode & 0o077, 0, f.name)

    def test_files_of_an_older_version_are_made_private(self):
        from mcp_http.users import Users
        from viewer import audit
        db = Path(os.environ["USERS_DB"])
        audit.record("access", path="/first")
        os.chmod(db, 0o644)
        os.chmod(self.audit_file, 0o644)
        Users(db)                                             # the next start
        audit.record("access", path="/x")                     # the next entry
        self.assertEqual(db.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.audit_file.stat().st_mode & 0o777, 0o600)

    def test_logout_ends_the_session_everywhere(self):
        """Logging out ends that session, also a copy of its cookie; the
        user's other sessions stay."""
        boss = self.login("boss", "boss-password")
        other = self.login("boss", "boss-password")            # another browser
        self.assertEqual(self.req("/admin", cookie=boss)[0], 200)
        self.req("/logout", cookie=boss)
        self.assertEqual(self.req("/admin", cookie=boss)[0], 303)
        self.assertEqual(self.req("/admin", cookie=other)[0], 200)


class ThrottleTest(Viewer):
    """Wrong passwords and access links per client address
    (viewer/auth.py Throttle, VIEWER_LOGIN_LIMIT)."""

    EXTRA_ENV = {"VIEWER_LOGIN_LIMIT": "3", "VIEWER_TRUSTED_PROXIES": "127.0.0.1/32"}

    def wrong(self, n, addr="203.0.113.7"):
        for _ in range(n):
            status = self.req("/login", {"user": "boss", "password": "wrong"},
                              headers={"X-Forwarded-For": addr})[0]
        return status

    def setUp(self):
        super().setUp()
        self.sleep = mock.patch("viewer.server.time.sleep")
        self.sleep.start()

    def tearDown(self):
        self.sleep.stop()
        super().tearDown()

    def test_login(self):
        self.assertEqual(self.wrong(3), 401)
        status, headers, page = self.req("/login", {"user": "boss", "password": "boss-password"},
                                         headers={"X-Forwarded-For": "203.0.113.7"})
        self.assertEqual(status, 429)                         # not even the right one
        self.assertIn("Too many wrong passwords", page)
        self.assertGreater(int(headers["Retry-After"]), 0)
        # Another address is not affected.
        status, _, _ = self.req("/login", {"user": "boss", "password": "boss-password"},
                                headers={"X-Forwarded-For": "198.51.100.9"})
        self.assertEqual(status, 303)
        log = self.audit_file.read_text()
        self.assertIn('"status": 429', log)

    def test_access_links_and_scripts(self):
        import base64
        for _ in range(3):
            self.req("/t/itv_made-up", headers={"X-Forwarded-For": "203.0.113.8"})
        _, token = self.server.auth.users.create_link("Visitor")
        status, _, page = self.req(f"/t/{token}", headers={"X-Forwarded-For": "203.0.113.8"})
        self.assertEqual(status, 429)
        self.assertIn("Too many wrong access links", page)
        # Basic auth of scripts counts and is refused the same way.
        bad = base64.b64encode(b"boss:wrong").decode()
        good = base64.b64encode(b"boss:boss-password").decode()
        for _ in range(3):
            self.req("/version", headers={"Authorization": f"Basic {bad}",
                                          "X-Forwarded-For": "203.0.113.9"}, accept="*/*")
        self.assertEqual(self.req("/version", headers={"Authorization": f"Basic {good}",
                                                       "X-Forwarded-For": "203.0.113.9"},
                                  accept="*/*")[0], 401)
        self.assertEqual(self.req("/version", headers={"Authorization": f"Basic {good}"},
                                  accept="*/*")[0], 200)

    def test_the_window_passes(self):
        from viewer.auth import Throttle
        with mock.patch.dict(os.environ, {"VIEWER_LOGIN_LIMIT": "2", "VIEWER_LOGIN_WINDOW": "60"}):
            t = Throttle()
        now = [1000.0]
        with mock.patch("viewer.auth.time.time", lambda: now[0]):
            t.failed("a")
            now[0] += 10
            t.failed("a")
            self.assertEqual(t.wait("a"), 51)
            self.assertEqual(t.wait("b"), 0)
            now[0] += 51
            self.assertEqual(t.wait("a"), 0)                  # the first failure is out
        with mock.patch.dict(os.environ, {"VIEWER_LOGIN_LIMIT": "0"}):
            off = Throttle()
        for _ in range(100):
            off.failed("a")
        self.assertEqual(off.wait("a"), 0)
        with mock.patch.dict(os.environ, {"VIEWER_LOGIN_LIMIT": "x"}):
            with self.assertRaises(SystemExit):
                Throttle()

    def test_memory_is_bounded(self):
        from viewer.auth import Throttle
        t = Throttle()
        with mock.patch.object(Throttle, "MAX_KEYS", 50):
            for i in range(500):
                t.failed(f"10.0.{i // 250}.{i % 250}")
        self.assertLessEqual(len(t._fails), 50)


class BodyTest(Viewer):
    def test_bad_content_length_is_no_crash(self):
        for value in ("abc", "-5", "1e3"):
            got = raw_http(self.port, f"POST /login HTTP/1.1\r\nHost: x\r\n"
                                      f"Content-Length: {value}\r\n\r\n".encode())
            self.assertRegex(got[:12], rb"HTTP/1\.1 [1-5]\d\d", value)
            self.assertNotIn(b"500", got[:12], value)


class ShowAgainTest(Viewer):
    """Tokens and access links shown again (mcp_http/vault.py): only to
    their owner or an admin, only by a form with its CSRF token, never into
    a log, and the stored copy useless without the key."""

    def setUp(self):
        super().setUp()
        users = self.server.auth.users
        users.set_rights("boss", mcp=True)
        users.set_rights("anna", mcp=True)
        self.boss_token = users.create_token("boss", "laptop")
        self.boss_id = users.tokens("boss")[0]["id"]
        _, self.link = users.create_link("Visitor")

    def test_only_the_owner_sees_a_token(self):
        anna = self.login("anna", "anna-pass")
        token = self.csrf(anna)
        status, _, page = self.req("/account", {"action": "show", "id": self.boss_id,
                                                "csrf": token}, cookie=anna)
        self.assertEqual(status, 400)
        self.assertNotIn(self.boss_token, page)
        boss = self.login("boss", "boss-password")
        status, headers, page = self.req("/account", {"action": "show", "id": self.boss_id,
                                                      "csrf": self.csrf(boss)}, cookie=boss)
        self.assertEqual(status, 200)
        self.assertIn(self.boss_token, page)
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_links_only_for_admins_and_with_csrf(self):
        anna = self.login("anna", "anna-pass")
        status, _, page = self.req("/admin", {"action": "link_show", "name": "Visitor",
                                              "csrf": self.csrf(anna)}, cookie=anna)
        self.assertEqual(status, 403)
        self.assertNotIn(self.link, page)
        boss = self.login("boss", "boss-password")
        for data in ({"action": "link_show", "name": "Visitor"},
                     {"action": "show", "id": self.boss_id}):
            path = "/admin" if data["action"] == "link_show" else "/account"
            status, _, page = self.req(path, data, cookie=boss)          # no CSRF token
            self.assertEqual(status, 403, data)
            self.assertNotIn(self.link, page)
            self.assertNotIn(self.boss_token, page)
        status, _, page = self.req("/admin", {"action": "link_show", "name": "Visitor",
                                              "csrf": self.csrf(boss, "/admin")}, cookie=boss)
        self.assertIn(self.link, page)
        logs = self.audit_file.read_text() + sys.stderr.getvalue()
        self.assertNotIn(self.link, logs)
        self.assertNotIn(self.boss_token, logs)

    def test_the_stored_copy_is_bound_and_sealed(self):
        import hashlib
        from mcp_http import vault
        v = vault.Vault(b"k" * 32)
        a = hashlib.sha256(b"itz_secret").hexdigest()            # bound to its row's hash
        sealed = v.seal("itz_secret", a)
        self.assertEqual(v.open(sealed, a), "itz_secret")
        other = hashlib.sha256(b"itz_other").hexdigest()
        self.assertIsNone(v.open(sealed, other))                     # moved to another row
        self.assertIsNone(v.open(v.seal("itz_secret", other), other))  # not that row's token
        self.assertIsNone(vault.Vault(b"x" * 32).open(sealed, a))   # another key
        raw = bytearray(__import__("base64").urlsafe_b64decode(sealed.split("$", 1)[1]))
        raw[20] ^= 1                                                 # one bit of the cipher text
        forged = "v1$" + __import__("base64").urlsafe_b64encode(bytes(raw)).decode()
        self.assertIsNone(v.open(forged, a))
        for junk in (None, "", "v1$", "v2$" + sealed[3:], "v1$!!!", sealed[:20]):
            self.assertIsNone(v.open(junk, a), junk)
        self.assertNotEqual(v.seal("itz_secret", a), sealed)         # a fresh nonce

    def test_key_file_is_private_and_not_in_the_database(self):
        db = Path(os.environ["USERS_DB"])
        key = db.parent / "token.key"
        self.assertEqual(key.stat().st_mode & 0o077, 0)
        self.assertNotIn(key.read_text().strip().encode(), db.read_bytes())
        self.assertNotIn(self.boss_token.encode(), db.read_bytes())
        self.assertNotIn(self.link.encode(), db.read_bytes())


@unittest.skipUnless(FULL, "slow: only in the full test (FULL_TEST=1)")
class BruteForceTest(Viewer):
    def test_wrong_passwords_and_links_are_slow(self):
        for path, data in (("/login", {"user": "boss", "password": "wrong"}),
                           ("/t/itv_made-up", None)):
            t0 = time.monotonic()
            status = self.req(path, data)[0]
            self.assertGreaterEqual(time.monotonic() - t0, 0.6, path)
            self.assertIn(status, (401, 403))

    def test_parallel_guessing_is_throttled(self):
        """Parallel requests guess no faster: past VIEWER_LOGIN_LIMIT (10)
        every attempt from that address is refused."""
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(20) as pool:
            got = list(pool.map(lambda i: self.req("/login", {
                "user": "boss", "password": f"guess-{i}"})[0], range(40)))
        self.assertLessEqual(got.count(401), 10 + 20)          # in flight when it tipped
        self.assertGreaterEqual(got.count(429), 10)
        self.assertEqual(self.req("/login", {"user": "boss", "password": "boss-password"})[0],
                         429)

    def test_unknown_user_takes_as_long_as_a_wrong_password(self):
        users = self.server.auth.users

        def timed(name):
            t0 = time.perf_counter()
            for _ in range(5):
                users.authenticate(name, "wrong-password")
            return time.perf_counter() - t0
        known, unknown = timed("boss"), timed("nobody-here")
        self.assertLess(abs(known - unknown) / max(known, unknown), 0.5)


class ComposeTest(unittest.TestCase):
    """compose.yaml: the engines unreachable from outside, data read-only
    for the services, published ports on localhost by default."""

    @classmethod
    def setUpClass(cls):
        try:
            import yaml
        except ImportError:
            raise unittest.SkipTest("PyYAML not installed")
        cls.c = yaml.safe_load((ROOT / "compose.yaml").read_text())

    def test_engines_publish_nothing_and_have_no_way_out(self):
        for name in ("mcp-engine", "viewer-engine"):
            svc = self.c["services"][name]
            self.assertNotIn("ports", svc, name)
            self.assertEqual(svc["networks"], ["engine"], name)
        self.assertTrue(self.c["networks"]["engine"]["internal"])

    def test_services_bind_to_localhost_by_default(self):
        for name in ("mcp", "viewer"):
            for port in self.c["services"][name]["ports"]:
                self.assertTrue(port.startswith(("${MCP_BIND:-127.0.0.1}",
                                                 "${VIEWER_BIND:-127.0.0.1}")), port)

    def test_data_and_secrets_read_only_for_the_services(self):
        for name in ("mcp", "viewer"):
            vols = self.c["services"][name]["volumes"]
            data = [v for v in vols if v.split(":")[-2:][0] == "/data" or ":/data:" in v]
            self.assertTrue(data and all(v.endswith(":ro") for v in data), (name, vols))
            secret = [v for v in vols if ":/engine" in v]
            self.assertTrue(secret and all(v.endswith(":ro") for v in secret), (name, vols))
        render = self.c["services"]["viewer-engine"]["volumes"]
        self.assertTrue(any(v.endswith("/data:ro") for v in render), render)

    def test_no_secret_has_a_default(self):
        for name, svc in self.c["services"].items():
            for key, value in (svc.get("environment") or {}).items():
                if re.search(r"TOKEN|PASSWORD|SECRET", key) and not key.endswith("_FILE"):
                    self.assertRegex(str(value), r"^\$\{[A-Z_]+:-(\$\{[A-Z_]+:-\})?\}$",
                                     (name, key))

    def test_no_privileges(self):
        for name, svc in self.c["services"].items():
            self.assertFalse(svc.get("privileged"), name)
            self.assertNotIn("cap_add", svc, name)
            self.assertNotEqual(svc.get("network_mode"), "host", name)
            self.assertNotIn("user", svc, name)               # the images' own (uid 1000)


class DockerfileTest(unittest.TestCase):
    def test_runs_unprivileged_and_pins_its_downloads(self):
        text = (ROOT / "Dockerfile").read_text()
        self.assertRegex(text, r"(?m)^USER ingetrazo$")
        fetches = re.findall(r"fetch \S+ \S+ ([0-9a-f]*)", text)
        self.assertTrue(fetches)
        self.assertTrue(all(len(h) == 64 for h in fetches), fetches)    # SHA-256 each


if __name__ == "__main__":
    unittest.main()
