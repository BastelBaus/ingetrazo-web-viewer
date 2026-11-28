# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests of the user list (mcp_http/users.py) and the viewer's login,
admin panel and account page (no container needed):

    python -m unittest discover -s tests -p "test_*.py"
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import threading
import unittest
from unittest import mock
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp_http.users import UserError, Users, check_password, hash_password  # noqa: E402


class UsersTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.users = Users(Path(self.tmp.name) / "users.db")

    def tearDown(self):
        self.tmp.cleanup()

    def test_password_hash(self):
        h = hash_password("correct horse")
        self.assertTrue(h.startswith("scrypt$"))
        self.assertTrue(check_password("correct horse", h))
        self.assertFalse(check_password("wrong", h))
        self.assertFalse(check_password("x", None))

    def test_first_admin_once(self):
        self.assertTrue(self.users.ensure_admin("boss", "secret-pass"))
        self.assertFalse(self.users.ensure_admin("other", "secret-pass"))
        self.assertEqual([a.name for a in self.users.all()], ["boss"])
        self.assertIsNotNone(self.users.authenticate("boss", "secret-pass"))
        self.assertIsNotNone(self.users.authenticate("BOSS", "secret-pass"))  # any case
        self.assertIsNone(self.users.authenticate("boss", "nope"))

    def test_create_and_rules(self):
        self.users.ensure_admin("boss", "secret-pass")
        self.users.create("anna", "anna-pass")
        with self.assertRaises(UserError):
            self.users.create("Anna", "another-pass")             # names ignore case
        with self.assertRaises(UserError):
            self.users.create("bad name", "secret-pass")
        with self.assertRaises(UserError):
            self.users.create("short", "1234")
        # One active admin always stays.
        for change in (lambda: self.users.set_role("boss", "user"),
                       lambda: self.users.set_active("boss", False),
                       lambda: self.users.delete("boss")):
            with self.assertRaises(UserError):
                change()
        self.users.set_role("anna", "admin")
        self.users.set_active("boss", False)
        self.assertIsNone(self.users.authenticate("boss", "secret-pass"))   # switched off
        self.users.delete("boss")
        self.assertEqual(self.users.active_admins(), 1)

    def test_provider_users(self):
        acc = self.users.seen("carl", "oidc", ["staff"], None)
        self.assertEqual((acc.role, acc.source, acc.groups), ("user", "oidc", ["staff"]))
        self.users.set_role("carl", "admin")                         # the panel decides
        self.assertEqual(self.users.seen("carl", "oidc", [], None).role, "admin")
        self.assertEqual(self.users.seen("carl", "oidc", [], False).role, "user")  # the group does
        self.assertIsNone(self.users.authenticate("carl", ""))       # no password here
        with self.assertRaises(UserError):
            self.users.set_password("carl", "secret-pass")

    def test_import_users_json(self):
        old = Path(self.tmp.name) / "users.json"
        old.write_text(json.dumps({"alice": {"role": "admin", "groups": ["a"], "source": "oidc",
                                             "first_login": "2026-01-01T00:00:00+00:00"},
                                   "bob": {"role": "viewer", "source": "proxy"}}))
        self.assertEqual(self.users.import_json(old), 2)
        self.assertEqual(self.users.import_json(old), 0)
        self.assertEqual(self.users.get("alice").role, "admin")
        self.assertEqual(self.users.get("bob").source, "proxy")

    def test_settings(self):
        self.users.create("eve", "eve-password")
        self.assertEqual(self.users.settings_of(self.users.get("eve")),
                         {"nav_mode": None, "edges_3d": True})
        conf = self.users.set_settings("eve", {"nav_mode": "tree", "edges_3d": False})
        self.assertEqual(conf, {"nav_mode": "tree", "edges_3d": False})
        for bad in ({"nav_mode": "sideways"}, {"colour": "red"}, {"edges_3d": 1}):
            with self.assertRaises(UserError):
                self.users.set_settings("eve", bad)
        self.assertEqual(self.users.set_settings("eve", {"nav_mode": None})["nav_mode"], None)
        self.assertFalse(Users(self.users.path).get("eve").config["edges_3d"])

    def test_migrates_an_old_list(self):
        """A users.db of version 1 (before settings) gets the new column."""
        import sqlite3
        from mcp_http import users as mod
        path = Path(self.tmp.name) / "v1.db"
        db = sqlite3.connect(path)
        db.execute(mod.MIGRATIONS[0])
        db.execute("INSERT INTO users (name, created) VALUES ('old', 'x')")
        db.execute("PRAGMA user_version=1")
        db.commit()
        db.close()
        u = Users(path)
        self.assertEqual(u.get("old").config, {})
        u.set_settings("old", {"nav_mode": "list"})

    def test_access_link(self):
        self.users.ensure_admin("boss", "secret-pass")
        acc, token = self.users.create_link("meier")
        self.assertTrue(token.startswith("itv_"))
        self.assertEqual((acc.source, acc.role, acc.web, acc.mcp, acc.shares),
                         ("link", "user", True, False, []))       # no folders yet
        found = self.users.by_link(token)
        self.assertEqual(found[0].name, "meier")
        self.assertTrue(self.users.link_usable(found[0], found[1]))
        # Never MCP, never admin, no password, not an MCP token.
        self.assertIsNone(self.users.by_token(token))
        for change in (lambda: self.users.set_rights("meier", mcp=True),
                       lambda: self.users.set_role("meier", "admin"),
                       lambda: self.users.set_password("meier", "secret-pass"),
                       lambda: self.users.create_token("meier"),
                       lambda: self.users.seen("meier", "oidc", [], True),
                       lambda: self.users.create_link("MEIER"),
                       lambda: self.users.create_link("boss"),
                       lambda: self.users.create_link("guest"),
                       lambda: self.users.new_link("boss"),
                       lambda: self.users.set_expires("meier", "2000-01-01"),
                       lambda: self.users.set_expires("meier", "tomorrow")):
            with self.assertRaises(UserError):
                change()
        self.assertIsNone(self.users.authenticate("meier", ""))
        self.assertEqual(self.users.tokens("meier"), [])           # MCP tokens only
        # A new link: the old one stops working.
        newer = self.users.new_link("meier")
        self.assertIsNone(self.users.by_link(token))
        self.assertFalse(self.users.link_usable(self.users.get("meier"), found[1]))
        self.assertIsNotNone(self.users.by_link(newer))
        # Switched off, expired: no way in.
        self.users.set_active("meier", False)
        self.assertIsNone(self.users.by_link(newer))
        self.users.set_active("meier", True)
        self.users.set_expires("meier", "2999-12-31")
        self.assertIsNotNone(self.users.by_link(newer))
        with self.users._lock:
            self.users._db.execute("UPDATE users SET expires = '2001-01-01' WHERE name = 'meier'")
        self.assertTrue(self.users.get("meier").expired)
        self.assertIsNone(self.users.by_link(newer))
        self.assertIsNone(self.users.set_expires("meier", ""))     # no end
        self.assertIsNotNone(self.users.by_link(newer))
        # Removed: the token goes with it.
        self.users.delete("meier")
        self.assertIsNone(self.users.by_link(newer))
        self.assertIsNone(self.users.link_info("meier"))

    def test_mcp_tokens_untouched_by_links(self):
        self.users.ensure_admin("boss", "secret-pass")
        mcp = self.users.create_token("boss", "desktop")
        self.users.create_link("meier")
        self.assertEqual(self.users.by_token(mcp).name, "boss")
        self.assertEqual(len(self.users.tokens("boss")), 1)
        self.assertIsNone(self.users.by_link(mcp))

    def test_owner(self):
        self.users.ensure_admin("boss", "secret-pass")
        self.users.create("anna", "anna-pass", "admin")
        self.assertTrue(self.users.protect_owner("BOSS"))
        self.assertEqual(self.users.owner, "boss")
        for change in (lambda: self.users.set_role("boss", "user"),
                       lambda: self.users.set_active("boss", False),
                       lambda: self.users.delete("boss"),
                       lambda: self.users.set_rights("boss", web=False)):
            with self.assertRaises(UserError):
                change()
        self.users.set_role("anna", "user")                       # other admins: yes
        # Demoted behind its back (an older viewer): restored on start.
        with self.users._lock:
            self.users._db.execute("UPDATE users SET role = 'user', active = 0 WHERE name = 'boss'")
        self.assertTrue(self.users.protect_owner("boss"))
        acc = self.users.get("boss")
        self.assertEqual((acc.role, acc.active, acc.web), ("admin", True, True))
        # Unknown or not local: no owner.
        self.assertFalse(self.users.protect_owner("nobody"))
        self.assertIsNone(self.users.owner)

    def test_guest(self):
        self.users.ensure_admin("boss", "secret-pass")
        with self.assertRaises(UserError):
            self.users.create("Guest", "secret-pass")                # the name is kept
        guest = self.users.ensure_guest()
        self.assertEqual((guest.name, guest.role, guest.source), ("guest", "user", "guest"))
        self.assertIsNotNone(self.users.guest())
        self.assertIsNone(self.users.authenticate("guest", ""))
        for change in (lambda: self.users.set_role("guest", "admin"),
                       lambda: self.users.delete("guest"),
                       lambda: self.users.set_password("guest", "secret-pass"),
                       lambda: self.users.seen("guest", "oidc", [], None)):
            with self.assertRaises(UserError):
                change()
        self.users.set_active("guest", False)
        self.assertIsNone(self.users.guest())
        self.assertFalse(self.users.ensure_guest().active)          # stays off
        self.users.set_settings("guest", {"nav_mode": "tree"})

    def test_shared_file(self):
        """The viewer and the MCP server open the same file."""
        self.users.create("dora", "dora-pass")
        other = Users(self.users.path)
        self.assertIsNotNone(other.authenticate("dora", "dora-pass"))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class ViewerLoginTest(unittest.TestCase):
    """The viewer's login, admin panel and account page over HTTP, with
    VIEWER_AUTH_MODE=local and no IngeTrazo (pages that need none)."""

    def setUp(self):
        from viewer import auth as auth_mod
        from viewer import server
        self.tmp = tempfile.TemporaryDirectory()
        self.env = {"VIEWER_AUTH_MODE": "local", "ADMIN_USER": "boss",
                    "ADMIN_PASSWORD": "boss-password",
                    "USERS_DB": str(Path(self.tmp.name) / "users.db")}
        self.saved_env = {k: os.environ.get(k) for k in self.env}
        os.environ.update(self.env)
        self.saved_state = auth_mod.STATE_DIR
        auth_mod.STATE_DIR = Path(self.tmp.name)
        self.server = server
        self.saved = getattr(server, "auth", None)
        server.auth = auth_mod.Auth()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.opener = urllib.request.build_opener(NoRedirect)

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.server.auth = self.saved
        from viewer import auth as auth_mod
        auth_mod.STATE_DIR = self.saved_state
        for k, v in self.saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.tmp.cleanup()

    def req(self, path, data=None, cookie="", accept="text/html"):
        body = urlencode(data).encode() if data is not None else None
        r = urllib.request.Request(self.base + path, body,
                                   {"Accept": accept, **({"Cookie": cookie} if cookie else {})})
        try:
            with self.opener.open(r, timeout=10) as resp:
                return resp.status, dict(resp.headers), resp.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read().decode()

    def login(self, name, pw):
        status, headers, _ = self.req("/login", {"user": name, "password": pw, "next": "/admin"})
        self.assertEqual(status, 303, (name, status))
        return headers["Set-Cookie"].split(";")[0]

    @staticmethod
    def csrf(page):
        return re.search(r'name="csrf" value="([0-9a-f]+)"', page).group(1)

    def test_admin_adds_a_user_who_logs_in(self):
        boss = self.login("boss", "boss-password")
        status, _, page = self.req("/admin", cookie=boss)
        self.assertEqual(status, 200)
        self.assertIn("boss", page)
        token = self.csrf(page)
        # Without the token: refused.
        status, _, _ = self.req("/admin", {"action": "create", "name": "anna",
                                           "password": "anna-pass", "role": "user"}, boss)
        self.assertEqual(status, 403)
        status, _, page = self.req("/admin", {"action": "create", "name": "anna",
                                              "password": "anna-pass", "role": "user",
                                              "csrf": token}, boss)
        self.assertEqual(status, 200, page)
        self.assertIn("Added anna.", page)
        anna = self.login("anna", "anna-pass")
        # anna is no admin.
        self.assertEqual(self.req("/admin", cookie=anna)[0], 403)
        self.assertNotIn('href="/admin"', self.req("/account", cookie=anna)[2])
        # Switched off: her session ends at once.
        self.req("/admin", {"action": "active", "name": "anna", "on": "0", "csrf": token}, boss)
        status, _, page = self.req("/account", cookie=anna)
        self.assertEqual(status, 403)
        self.assertIn("switched off", page)
        self.assertEqual(self.req("/login", {"user": "anna", "password": "anna-pass"})[0], 401)

    def test_shares_page_with_patterns(self):
        boss = self.login("boss", "boss-password")
        token = self.csrf(self.req("/admin", cookie=boss)[2])
        self.req("/admin", {"action": "create", "name": "anna", "password": "anna-pass",
                            "role": "user", "csrf": token}, boss)
        status, _, page = self.req("/admin/shares?name=anna", cookie=boss)
        self.assertEqual(status, 200)
        self.assertIn("How folder access works", page)        # the help
        self.assertIn('name="rules"', page)
        self.assertIn('title="Hide it:', page)                 # tooltips on the choices
        # New lines with a pattern; one bad line refuses the whole save.
        status, _, page = self.req("/admin", {
            "action": "shares", "name": "anna", "csrf": token, "s:*": "r",
            "rules": "projects/a:rw\n**/private:none\nx:write"}, boss)
        self.assertEqual(status, 400)
        self.assertIn("In the new lines", page)
        status, _, page = self.req("/admin", {
            "action": "shares", "name": "anna", "csrf": token, "s:*": "r",
            "rules": "projects/a:rw\n**/private:none"}, boss)
        self.assertEqual(status, 200, page)
        self.assertEqual(self.server.auth.users.get("anna").shares, [
            {"path": "*", "access": "r"}, {"path": "**/private", "access": "none"},
            {"path": "projects/a", "access": "rw"}])
        self.assertIn("<code>**/private</code>", page)         # the patterns table
        # A pattern has a Delete button instead of "–".
        page = self.req("/admin/shares?name=anna", cookie=boss)[2]
        self.assertIn('name="del" value="**/private"', page)
        row = page[page.index('name="s:**/private"'):]
        self.assertNotIn('<option value=""', row[:row.index("</select>")])
        status, _, page = self.req("/admin", {
            "action": "shares", "name": "anna", "csrf": token, "s:*": "r",
            "s:**/private": "none", "s:projects/a": "rw", "del": "**/private"}, boss)
        self.assertEqual(status, 200, page)
        self.assertIn("Pattern **/private removed", page)
        self.assertEqual(self.server.auth.users.get("anna").shares,
                         [{"path": "*", "access": "r"}, {"path": "projects/a", "access": "rw"}])
        # "–" (an empty access) still removes a share.
        self.req("/admin", {"action": "shares", "name": "anna", "csrf": token,
                            "s:*": "r", "s:projects/a": ""}, boss)
        self.assertEqual(self.server.auth.users.get("anna").shares,
                         [{"path": "*", "access": "r"}])
        status, _, page = self.req("/admin/shares?name=anna&check=projects/x.igz", cookie=boss)
        self.assertEqual(status, 200)
        self.assertIn("<code>projects/x.igz</code>:", page)

    def test_admin_changes_the_title(self):
        from viewer import site
        with mock.patch.dict(os.environ, {"INGETRAZO_STATE": self.tmp.name}):
            site.reset()
            try:
                boss = self.login("boss", "boss-password")
                token = self.csrf(self.req("/admin", cookie=boss)[2])
                status, _, page = self.req("/admin", {"action": "title", "title": "Haus 8",
                                                      "csrf": token}, boss)
                self.assertEqual(status, 200, page)
                self.assertIn("<title>Users – Haus 8</title>", page)
                self.assertIn("<h1>Haus 8</h1>", self.req("/login")[2])
                self.req("/admin", {"action": "title", "title": "x", "reset": "1",
                                    "csrf": token}, boss)
                self.assertIn(f"<h1>{site.DEFAULT_TITLE}</h1>", self.req("/login")[2])
            finally:
                site.reset()

    def test_shares_page_with_patterns(self):
        boss = self.login("boss", "boss-password")
        token = self.csrf(self.req("/admin", cookie=boss)[2])
        self.req("/admin", {"action": "create", "name": "anna", "password": "anna-pass",
                            "role": "user", "csrf": token}, boss)
        status, _, page = self.req("/admin/shares?name=anna", cookie=boss)
        self.assertEqual(status, 200)
        self.assertIn("How folder access works", page)        # the help
        self.assertIn('name="rules"', page)
        self.assertIn('title="Hide it:', page)                 # tooltips on the choices
        # New lines with a pattern; one bad line refuses the whole save.
        status, _, page = self.req("/admin", {
            "action": "shares", "name": "anna", "csrf": token, "s:*": "r",
            "rules": "projects/a:rw\n**/private:none\nx:write"}, boss)
        self.assertEqual(status, 400)
        self.assertIn("In the new lines", page)
        status, _, page = self.req("/admin", {
            "action": "shares", "name": "anna", "csrf": token, "s:*": "r",
            "rules": "projects/a:rw\n**/private:none"}, boss)
        self.assertEqual(status, 200, page)
        self.assertEqual(self.server.auth.users.get("anna").shares, [
            {"path": "*", "access": "r"}, {"path": "**/private", "access": "none"},
            {"path": "projects/a", "access": "rw"}])
        self.assertIn("<code>**/private</code>", page)         # the patterns table
        # A pattern has a Delete button instead of "–".
        page = self.req("/admin/shares?name=anna", cookie=boss)[2]
        self.assertIn('name="del" value="**/private"', page)
        row = page[page.index('name="s:**/private"'):]
        self.assertNotIn('<option value=""', row[:row.index("</select>")])
        status, _, page = self.req("/admin", {
            "action": "shares", "name": "anna", "csrf": token, "s:*": "r",
            "s:**/private": "none", "s:projects/a": "rw", "del": "**/private"}, boss)
        self.assertEqual(status, 200, page)
        self.assertIn("Pattern **/private removed", page)
        self.assertEqual(self.server.auth.users.get("anna").shares,
                         [{"path": "*", "access": "r"}, {"path": "projects/a", "access": "rw"}])
        # "–" (an empty access) still removes a share.
        self.req("/admin", {"action": "shares", "name": "anna", "csrf": token,
                            "s:*": "r", "s:projects/a": ""}, boss)
        self.assertEqual(self.server.auth.users.get("anna").shares,
                         [{"path": "*", "access": "r"}])
        status, _, page = self.req("/admin/shares?name=anna&check=projects/x.igz", cookie=boss)
        self.assertEqual(status, 200)
        self.assertIn("<code>projects/x.igz</code>:", page)

    def test_the_last_admin_stays(self):
        boss = self.login("boss", "boss-password")
        token = self.csrf(self.req("/admin", cookie=boss)[2])
        status, _, page = self.req("/admin", {"action": "role", "name": "boss",
                                              "role": "user", "csrf": token}, boss)
        self.assertEqual(status, 400)
        self.assertIn("own admin role", page)                     # refused before that
        # The list itself still keeps one active admin.
        users = self.server.auth.users
        users.owner = None
        with self.assertRaisesRegex(UserError, "no active admin"):
            users.set_role("boss", "user")

    def test_change_own_password(self):
        boss = self.login("boss", "boss-password")
        page = self.req("/account", cookie=boss)[2]
        token = self.csrf(page)
        status, _, page = self.req("/account", {"action": "password", "old": "wrong-one",
                                                "password": "new-password", "csrf": token}, boss)
        self.assertEqual(status, 400)
        status, _, page = self.req("/account", {"action": "password", "old": "boss-password",
                                                "password": "new-password", "csrf": token}, boss)
        self.assertEqual(status, 200, page)
        self.login("boss", "new-password")

    def test_settings_follow_the_user(self):
        boss = self.login("boss", "boss-password")
        page = self.req("/account", cookie=boss)[2]
        self.assertIn('data-nav="tree"', page)                 # tree by default
        token = self.csrf(page)
        status, _, body = self.req("/account/settings", {"nav_mode": "list", "csrf": token}, boss,
                                   accept="application/json")
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["nav_mode"], "list")
        self.assertIn('data-nav="list"', self.req("/account", cookie=boss)[2])
        # Another session (another browser) gets the same.
        self.assertIn('data-nav="list"', self.req("/account", cookie=self.login("boss", "boss-password"))[2])
        status, _, _ = self.req("/account/settings", {"nav_mode": "x", "csrf": token}, boss)
        self.assertEqual(status, 400)
        status, _, _ = self.req("/account/settings", {"nav_mode": "list"}, boss)
        self.assertEqual(status, 403)                                  # no token
        # The account page's form; "" goes back to the default.
        status, _, page = self.req("/account", {"action": "settings", "nav_mode": "",
                                                "edges_3d": "0", "csrf": token}, boss)
        self.assertEqual(status, 200, page)
        self.assertIn('data-nav="tree" data-edges="0"', page)

    def test_access_link_login(self):
        boss = self.login("boss", "boss-password")
        token = self.csrf(self.req("/admin", cookie=boss)[2])
        status, _, page = self.req("/admin", {"action": "link_create", "name": "meier",
                                              "expires": "", "csrf": token}, boss)
        self.assertEqual(status, 200, page)
        secret = re.search(r"/t/(itv_[\w-]+)", page).group(1)
        self.assertIn("Choose its folders", page)
        page = self.req("/admin", cookie=boss)[2]
        self.assertIn("Access links", page)
        self.assertIn("meier", page)
        # The link logs in and drops the token from the address.
        status, headers, _ = self.req("/t/" + secret)
        self.assertEqual((status, headers["Location"]), (303, "/"))
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")
        link = headers["Set-Cookie"].split(";")[0]
        status, _, page = self.req("/account", cookie=link)
        self.assertEqual(status, 200)
        self.assertIn("access link <strong>meier</strong>", page)
        self.assertNotIn("MCP access", page)
        self.assertEqual(self.req("/admin", cookie=link)[0], 403)
        # A wrong token: refused. A script: Bearer.
        self.assertEqual(self.req("/t/itv_nope")[0], 403)
        r = urllib.request.Request(self.base + "/account",
                                   headers={"Authorization": "Bearer " + secret,
                                            "Accept": "text/plain"})
        with self.opener.open(r, timeout=10) as resp:
            self.assertEqual(resp.status, 200)
        # A new link ends the old link's sessions.
        status, _, page = self.req("/admin", {"action": "link_new", "name": "meier",
                                              "csrf": token}, boss)
        newer = re.search(r"/t/(itv_[\w-]+)", page).group(1)
        status, _, page = self.req("/account", cookie=link)
        self.assertEqual(status, 403)
        self.assertIn("access link no longer works", page)
        self.assertEqual(self.req("/t/" + secret)[0], 403)
        link = self.req("/t/" + newer)[1]["Set-Cookie"].split(";")[0]
        self.assertEqual(self.req("/account", cookie=link)[0], 200)
        # Last day and switch off.
        status, _, page = self.req("/admin", {"action": "link_expires", "name": "meier",
                                              "expires": "2999-12-31", "csrf": token}, boss)
        self.assertIn("works through 2999-12-31", page)
        self.req("/admin", {"action": "active", "name": "meier", "on": "0", "csrf": token}, boss)
        self.assertEqual(self.req("/account", cookie=link)[0], 403)
        self.assertEqual(self.req("/t/" + newer)[0], 403)
        # No MCP right, no admin role through the panel.
        page = self.req("/admin", {"action": "rights", "name": "meier", "mcp": "1",
                                   "csrf": token}, boss)[2]
        self.assertIn("web viewer only", page)
        # A link session is never taken for a password user of that name.
        self.req("/admin", {"action": "delete", "name": "meier", "csrf": token}, boss)
        self.req("/admin", {"action": "create", "name": "meier", "password": "meier-pass",
                            "role": "user", "csrf": token}, boss)
        self.assertEqual(self.req("/account", cookie=link)[0], 403)
        self.assertEqual(self.req("/account", cookie=self.login("meier", "meier-pass"))[0], 200)

    def test_access_link_logout_and_log(self):
        boss = self.login("boss", "boss-password")
        token = self.csrf(self.req("/admin", cookie=boss)[2])
        page = self.req("/admin", {"action": "link_create", "name": "meier",
                                   "csrf": token}, boss)[2]
        secret = re.search(r"/t/(itv_[\w-]+)", page).group(1)
        import io
        err = io.StringIO()
        with mock.patch("sys.stderr", err):
            link = self.req("/t/" + secret)[1]["Set-Cookie"].split(";")[0]
        self.assertNotIn(secret, err.getvalue())
        status, headers, page = self.req("/logout", cookie=link)
        self.assertEqual(status, 200)
        self.assertIn("Open your access link again", page)
        self.assertIn("Max-Age=0", headers["Set-Cookie"])

    def test_admin_cannot_lock_themself_out(self):
        boss = self.login("boss", "boss-password")
        token = self.csrf(self.req("/admin", cookie=boss)[2])
        self.req("/admin", {"action": "create", "name": "anna", "password": "anna-pass",
                            "role": "admin", "csrf": token}, boss)
        page = self.req("/admin", cookie=boss)[2]
        self.assertIn("(owner)", page)
        anna = self.login("anna", "anna-pass")
        atoken = self.csrf(self.req("/admin", cookie=anna)[2])
        # anna cannot demote herself, nor the owner.
        page = self.req("/admin", {"action": "role", "name": "anna", "role": "user",
                                   "csrf": atoken}, anna)[2]
        self.assertIn("own admin role", page)
        for data in ({"action": "role", "role": "user"}, {"action": "active", "on": "0"},
                     {"action": "delete"}):
            status, _, page = self.req("/admin", {**data, "name": "boss", "csrf": atoken}, anna)
            self.assertEqual(status, 400, data)
            self.assertIn("owner", page)
        self.assertEqual(self.req("/admin", cookie=anna)[0], 200)   # still admin
        # The owner can demote anna.
        self.req("/admin", {"action": "role", "name": "anna", "role": "user", "csrf": token}, boss)
        self.assertEqual(self.req("/admin", cookie=anna)[0], 403)

    def test_guest_login(self):
        from viewer import auth as auth_mod
        self.assertNotIn("Log in as guest", self.req("/login")[2])     # off by default
        self.assertEqual(self.req("/login/guest", {"next": "/account"})[0], 404)
        os.environ["VIEWER_GUEST"] = "true"
        try:
            self.server.auth = auth_mod.Auth()
        finally:
            os.environ.pop("VIEWER_GUEST")
        self.assertIn("Log in as guest", self.req("/login")[2])
        status, headers, _ = self.req("/login/guest", {"next": "/account"})
        self.assertEqual((status, headers["Location"]), (303, "/account"))
        guest = headers["Set-Cookie"].split(";")[0]
        status, _, page = self.req("/account", cookie=guest)
        self.assertEqual(status, 200)
        self.assertIn("Every guest shares", page)
        self.assertIn("data-csrf=", page)                              # has settings
        self.assertEqual(self.req("/admin", cookie=guest)[0], 403)
        # An admin switches the guest off: the session ends, no new one.
        boss = self.login("boss", "boss-password")
        token = self.csrf(self.req("/admin", cookie=boss)[2])
        page = self.req("/admin", cookie=boss)[2]
        self.assertIn("(guest)", page)
        self.req("/admin", {"action": "active", "name": "guest", "on": "0", "csrf": token}, boss)
        self.assertEqual(self.req("/account", cookie=guest)[0], 403)
        self.assertEqual(self.req("/login/guest", {"next": "/"})[0], 403)
        # VIEWER_GUEST off again: an old guest session no longer counts.
        self.req("/admin", {"action": "active", "name": "guest", "on": "1", "csrf": token}, boss)
        self.assertEqual(self.req("/account", cookie=guest)[0], 200)
        sessions = self.server.auth.sessions
        self.server.auth = auth_mod.Auth()
        self.server.auth.sessions = sessions                          # same sessions
        self.assertEqual(self.req("/account", cookie=guest)[0], 303)
        self.assertEqual(self.req("/account", cookie=boss)[0], 200)

    def test_avatar(self):
        from viewer import avatar
        boss = self.login("boss", "boss-password")
        page = self.req("/account", cookie=boss)[2]
        url = re.search(r'src="(/avatar/boss\.svg\?v=[^"]+)"', page).group(1)
        status, headers, svg = self.req(url.replace("&amp;", "&"), cookie=boss)
        self.assertEqual(status, 200)
        self.assertIn(">B<", svg)                                      # initials
        token = self.csrf(page)
        for style in avatar.STYLES:
            status, _, page = self.req("/account", {"action": "avatar", "style": style,
                                                    "csrf": token}, boss)
            self.assertEqual(status, 200, page)
            got = self.server.auth.users.get("boss").avatar
            self.assertEqual(avatar.valid(got)["style"], style)
            self.assertTrue(avatar.svg("boss", got).startswith("<svg"))
        self.assertNotEqual(re.search(r'src="(/avatar/boss\.svg\?v=[^"]+)"', page).group(1), url)
        self.req("/account", {"action": "avatar_reset", "csrf": token}, boss)
        self.assertIsNone(self.server.auth.users.get("boss").avatar)
        self.assertEqual(self.req("/avatar/nobody.svg", cookie=boss)[0], 404)
        self.assertEqual(self.req("/avatar/boss.svg")[0], 303)          # login first
        # Something else in the column is not drawn as is.
        self.assertIsNone(avatar.valid({"style": "pattern", "seed": "<script>", "hue": 1}))
        self.assertIn("<svg", avatar.svg("x", {"style": "evil"}))

    def test_basic_auth_for_scripts(self):
        import base64
        r = urllib.request.Request(self.base + "/account", headers={
            "Authorization": "Basic " + base64.b64encode(b"boss:boss-password").decode()})
        with self.opener.open(r, timeout=10) as resp:
            self.assertEqual(resp.status, 200)
        r = urllib.request.Request(self.base + "/account", headers={
            "Authorization": "Basic " + base64.b64encode(b"boss:nope").decode()})
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.opener.open(r, timeout=10)
        self.assertEqual(ctx.exception.code, 401)

    def test_restart_keeps_users_but_not_the_env_password(self):
        """ADMIN_PASSWORD only makes the first admin."""
        from viewer import auth as auth_mod
        boss = self.login("boss", "boss-password")
        token = self.csrf(self.req("/account", cookie=boss)[2])
        self.req("/account", {"action": "password", "old": "boss-password",
                              "password": "changed-pass", "csrf": token}, boss)
        self.server.auth = auth_mod.Auth()           # a restart
        self.assertIsNone(self.server.auth.login("boss", "boss-password"))
        self.assertIsNotNone(self.server.auth.login("boss", "changed-pass"))

    def test_first_admin_is_admin_and_old_names_still_work(self):
        """ADMIN_USER defaults to admin; VIEWER_USER / VIEWER_PASSWORD
        still make the first admin when the new names are not set."""
        from viewer import auth as auth_mod
        for k in ("ADMIN_USER", "ADMIN_PASSWORD"):
            os.environ.pop(k, None)
        os.environ["USERS_DB"] = str(Path(self.tmp.name) / "default.db")
        os.environ["VIEWER_PASSWORD"] = "old-password"
        try:
            a = auth_mod.Auth()
            self.assertEqual(a.user_name, "admin")
            self.assertIsNotNone(a.login("admin", "old-password"))
            os.environ["USERS_DB"] = str(Path(self.tmp.name) / "old.db")
            os.environ["VIEWER_USER"] = "viewer"
            a = auth_mod.Auth()
            self.assertIsNotNone(a.login("viewer", "old-password"))
        finally:
            os.environ.pop("VIEWER_PASSWORD", None)
            os.environ.pop("VIEWER_USER", None)

    def test_no_admin_no_password_refuses_to_start(self):
        from viewer import auth as auth_mod
        os.environ["USERS_DB"] = str(Path(self.tmp.name) / "empty.db")
        os.environ.pop("ADMIN_PASSWORD")
        with self.assertRaises(SystemExit) as ctx:
            auth_mod.Auth()
        self.assertIn("VIEWER_AUTH_MODE=none", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
