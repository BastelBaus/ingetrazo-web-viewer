# SPDX-License-Identifier: AGPL-3.0-or-later
"""The users of the container, in one SQLite file (``USERS_DB``, default
``/state/users.db``). compose.yaml puts it on a volume both services
mount, so the viewer and the MCP server share one list.

A user has a name, a role (``admin`` or ``user``), where they come from
(``local``: a password kept here; ``oidc`` / ``proxy``: logged in
elsewhere, recorded on first login), whether they are active, the
settings they work with (``SETTINGS``, kept as they change them), the
folders they may see and write (``shares``, see shares.py), and what they
may use: the web viewer (``web``) and the MCP server (``mcp``, with
personal access tokens). Admins
manage the list in the viewer's admin panel (``/admin``).

An *access link* (source ``link``) is a named account without a password:
whoever opens its link (``/t/<token>``) sees the viewer with that account's
folders. It may use the web viewer only, never the MCP server, and is
never an admin; it may expire on a date, and an admin can switch it off,
replace its link (the old one stops working) or remove it.

Passwords are stored as scrypt hashes. Tokens (MCP and access links) are
checked by their SHA-256 hash; an encrypted copy (mcp_http/vault.py, key
outside the database) lets their owner see them again. The schema carries its version in
``PRAGMA user_version``; newer versions add columns (``MIGRATIONS``).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import vault

ROLES = ("admin", "user")
SOURCES = ("local", "oidc", "proxy", "guest", "link")
#: Accounts without a login of their own: no password, no MCP, never admin.
SPECIAL = ("guest", "link")
#: The guest user: who uses "Log in as guest" (VIEWER_GUEST). One user for
#: every guest, with settings and rights like any other; never an admin.
GUEST = "guest"
#: A name: letters, digits and . _ - @ (e-mail addresses from a provider).
NAME = re.compile(r"^[\w.@+-]{1,64}$", re.UNICODE)
#: An access link's name: free text (spaces too), 1–64 characters, no
#: control characters; runs of white space become one space.
LINK_NAME = re.compile(r"^[^\x00-\x1f\x7f]{1,64}$")
MIN_PASSWORD = 8

#: Each entry upgrades the schema by one version.
MIGRATIONS: list[str | list[str]] = [
    """CREATE TABLE users (
         name TEXT PRIMARY KEY COLLATE NOCASE,
         role TEXT NOT NULL DEFAULT 'user',
         source TEXT NOT NULL DEFAULT 'local',
         password TEXT,
         active INTEGER NOT NULL DEFAULT 1,
         groups TEXT NOT NULL DEFAULT '[]',
         created TEXT NOT NULL,
         last_login TEXT
       )""",
    # 2: the settings a user works with (SETTINGS), as JSON.
    "ALTER TABLE users ADD COLUMN config TEXT NOT NULL DEFAULT '{}'",
    # 3: the folders a user may see and write (mcp_http/shares.py), as JSON;
    # NULL: DEFAULT_SHARES.
    "ALTER TABLE users ADD COLUMN shares TEXT",
    # 4: what a user may use: the web viewer, the MCP server. Admins had MCP.
    ["ALTER TABLE users ADD COLUMN web INTEGER NOT NULL DEFAULT 1",
     "ALTER TABLE users ADD COLUMN mcp INTEGER NOT NULL DEFAULT 0",
     "UPDATE users SET mcp = 1 WHERE role = 'admin'"],
    # 5: personal MCP access tokens (hashed).
    """CREATE TABLE tokens (
         hash TEXT PRIMARY KEY,
         user TEXT NOT NULL COLLATE NOCASE,
         label TEXT NOT NULL DEFAULT '',
         created TEXT NOT NULL,
         last_used TEXT
       )""",
    # 6: the avatar a user made themself (viewer/avatar.py), as JSON.
    "ALTER TABLE users ADD COLUMN avatar TEXT",
    # 7: access links: a token's kind (``mcp``: personal MCP token, ``web``:
    # an access link's secret), and the last day an account may log in.
    ["ALTER TABLE tokens ADD COLUMN kind TEXT NOT NULL DEFAULT 'mcp'",
     "ALTER TABLE users ADD COLUMN expires TEXT"],
    # 8: the token, encrypted (mcp_http/vault.py), so it can be shown again;
    # NULL for older tokens until their next use.
    "ALTER TABLE tokens ADD COLUMN secret TEXT",
]
#: A personal MCP token starts with this, so it is recognisable in a config.
TOKEN_PREFIX = "itz_"
#: An access link's token starts with this (viewer only, never MCP).
LINK_PREFIX = "itv_"
#: The last day of an access link: YYYY-MM-DD (valid through that day, UTC).
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

#: The settings a user keeps (the viewer's and later the MCP server's):
#: name → (allowed values, default). The default ``None`` means "as the
#: container is set up" (an environment variable).
SETTINGS: dict[str, tuple[tuple, object]] = {
    # The View / 3D / Sheet dropdowns: every folder level, or one at a time.
    "nav_mode": (("list", "tree"), None),
    # The 3D view draws the edges as lines.
    "edges_3d": ((True, False), True),
}


def _json_dict(text: str | None) -> dict | None:
    try:
        value = json.loads(text) if text else None
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _today() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def _check_date(day: str | None) -> str | None:
    """An expiry date as the form sends it: "" or None is none."""
    day = (day or "").strip()
    if not day:
        return None
    try:
        if not DATE.match(day):
            raise ValueError
        datetime.strptime(day, "%Y-%m-%d")
    except ValueError:
        raise UserError("a date is YYYY-MM-DD") from None
    if day < _today():
        raise UserError("that date is in the past")
    return day


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    n, r, p = 2 ** 14, 8, 1
    digest = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
    return "scrypt${}${}${}${}${}".format(
        n, r, p, base64.b64encode(salt).decode(), base64.b64encode(digest).decode())


def check_password(password: str, stored: str | None) -> bool:
    try:
        kind, n, r, p, salt, digest = (stored or "").split("$")
        if kind != "scrypt":
            return False
        got = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt),
                             n=int(n), r=int(r), p=int(p), dklen=32)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(got, base64.b64decode(digest))


@dataclass
class Account:
    name: str
    role: str = "user"
    source: str = "local"
    active: bool = True
    has_password: bool = False
    groups: list[str] = field(default_factory=list)
    created: str = ""
    last_login: str | None = None
    config: dict = field(default_factory=dict)
    shares: list | None = None           # None: DEFAULT_SHARES
    web: bool = True                     # may use the web viewer
    mcp: bool = False                    # may use the MCP server
    avatar: dict | None = None           # None: made from the name
    expires: str | None = None           # access links: last valid day

    @property
    def admin(self) -> bool:
        return self.role == "admin"

    @property
    def expired(self) -> bool:
        return bool(self.expires) and self.expires < _today()


class UserError(ValueError):
    """A change the list does not allow; the message says why."""


class Users:
    def __init__(self, path: Path | str | None = None) -> None:
        state = Path(os.environ.get("INGETRAZO_STATE", "/state"))
        self.path = Path(path or os.environ.get("USERS_DB", "").strip()
                         or state / "users.db")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        #: The owner (the admin from ADMIN_USER, local login): always an
        #: active admin; nobody can demote, switch off or remove them.
        self.owner: str | None = None
        self._db = sqlite3.connect(self.path, check_same_thread=False,
                                   isolation_level=None, timeout=10)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._migrate()
        self._private()
        self._vault = vault.Vault(vault.load_key(self.path))

    def _private(self) -> None:
        """The list holds password and token hashes: owner only (0600),
        also for a database an older version made with the umask. Its
        journal files (-wal, -shm) take the database's mode."""
        for f in (self.path, self.path.with_name(self.path.name + "-wal"),
                  self.path.with_name(self.path.name + "-shm")):
            try:
                if f.exists() and f.stat().st_mode & 0o077:
                    os.chmod(f, 0o600)
            except OSError:
                pass

    def _migrate(self) -> None:
        with self._lock:
            version = self._db.execute("PRAGMA user_version").fetchone()[0]
            for n, sql in enumerate(MIGRATIONS[version:], start=version + 1):
                self._db.execute("BEGIN IMMEDIATE")
                try:
                    # Another container may have migrated meanwhile.
                    if self._db.execute("PRAGMA user_version").fetchone()[0] >= n:
                        self._db.execute("ROLLBACK")
                        continue
                    for stmt in ([sql] if isinstance(sql, str) else sql):
                        self._db.execute(stmt)
                    self._db.execute(f"PRAGMA user_version={n}")
                    self._db.execute("COMMIT")
                except sqlite3.Error:
                    self._db.execute("ROLLBACK")
                    raise

    # ---- reading ---------------------------------------------------------------
    @staticmethod
    def _account(row: sqlite3.Row) -> Account:
        try:
            groups = json.loads(row["groups"] or "[]")
        except ValueError:
            groups = []
        try:
            config = json.loads(row["config"] or "{}")
        except ValueError:
            config = {}
        try:
            shares = json.loads(row["shares"]) if row["shares"] is not None else None
        except ValueError:
            shares = []                       # unreadable: nothing, not everything
        return Account(row["name"], row["role"], row["source"], bool(row["active"]),
                       bool(row["password"]), groups, row["created"], row["last_login"],
                       config if isinstance(config, dict) else {},
                       shares if isinstance(shares, list) or shares is None else [],
                       bool(row["web"]), bool(row["mcp"]), _json_dict(row["avatar"]),
                       row["expires"])

    def get(self, name: str) -> Account | None:
        with self._lock:
            row = self._db.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchone()
        return self._account(row) if row else None

    def all(self) -> list[Account]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM users ORDER BY name").fetchall()
        return [self._account(r) for r in rows]

    def active_admins(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' "
                                    "AND active = 1").fetchone()[0]

    def authenticate(self, name: str, password: str) -> Account | None:
        """A local user whose password matches, if active."""
        with self._lock:
            row = self._db.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchone()
        stored = row["password"] if row else None
        # Hash anyway, so an unknown name takes as long as a wrong password.
        ok = check_password(password, stored or "scrypt$16384$8$1$AAAA$AAAA")
        if not (row and ok and row["active"] and row["source"] == "local"):
            return None
        self._touch(row["name"])
        return self._account(row)

    # ---- changing --------------------------------------------------------------
    def _touch(self, name: str) -> None:
        with self._lock:
            self._db.execute("UPDATE users SET last_login = ? WHERE name = ?", (_now(), name))

    def create(self, name: str, password: str | None = None, role: str = "user",
               source: str = "local") -> Account:
        name = name.strip()
        if not NAME.match(name):
            raise UserError("a user name is 1–64 letters, digits or . _ - @ +")
        if role not in ROLES:
            raise UserError(f"the role is one of {', '.join(ROLES)}")
        if source not in SOURCES or source == "guest":
            raise UserError(f"the source is one of local, oidc, proxy")
        if name.lower() == GUEST:
            raise UserError(f"the name {GUEST!r} is kept for the guest user")
        if source == "local":
            self._check_password(password or "")
        with self._lock:
            try:
                self._db.execute(
                    "INSERT INTO users (name, role, source, password, created) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (name, role, source,
                     hash_password(password) if source == "local" else None, _now()))
            except sqlite3.IntegrityError:
                raise UserError(f"there is already a user {name!r}") from None
        return self.get(name)

    @staticmethod
    def _check_password(password: str) -> None:
        if len(password) < MIN_PASSWORD:
            raise UserError(f"a password has at least {MIN_PASSWORD} characters")

    def set_password(self, name: str, password: str) -> None:
        self._check_password(password)
        self._require(name, local=True)
        with self._lock:
            self._db.execute("UPDATE users SET password = ? WHERE name = ?",
                             (hash_password(password), name))

    def _require(self, name: str, local: bool = False) -> Account:
        acc = self.get(name)
        if acc is None:
            raise UserError(f"there is no user {name!r}")
        if local and acc.source != "local":
            raise UserError(f"{acc.name} logs in through {acc.source}; the password is kept there")
        return acc

    def is_owner(self, acc: Account | None) -> bool:
        return bool(acc and self.owner and acc.name.lower() == self.owner.lower())

    def _not_owner(self, acc: Account, what: str) -> None:
        if self.is_owner(acc):
            raise UserError(f"{acc.name} is the owner (ADMIN_USER) and cannot be {what}")

    def protect_owner(self, name: str) -> bool:
        """``name`` (ADMIN_USER) becomes the owner: restored to an active
        admin with the web viewer if it is a local user. True when it is."""
        acc = self.get(name)
        if acc is None or acc.source != "local":
            self.owner = None
            return False
        self.owner = acc.name
        with self._lock:
            self._db.execute("UPDATE users SET role = 'admin', active = 1, web = 1 "
                             "WHERE name = ?", (acc.name,))
        return True

    def _keeps_an_admin(self, acc: Account) -> None:
        if acc.admin and acc.active and self.active_admins() <= 1:
            raise UserError("that would leave no active admin")

    def set_role(self, name: str, role: str) -> None:
        if role not in ROLES:
            raise UserError(f"the role is one of {', '.join(ROLES)}")
        acc = self._require(name)
        if role == "admin" and acc.source in SPECIAL:
            raise UserError(f"{'the guest user' if acc.source == 'guest' else 'an access link'} "
                            "cannot be an admin")
        if role != "admin":
            self._not_owner(acc, "made a user")
            self._keeps_an_admin(acc)
        with self._lock:
            self._db.execute("UPDATE users SET role = ? WHERE name = ?", (role, acc.name))

    def set_active(self, name: str, active: bool) -> None:
        acc = self._require(name)
        if not active:
            self._not_owner(acc, "switched off")
            self._keeps_an_admin(acc)
        with self._lock:
            self._db.execute("UPDATE users SET active = ? WHERE name = ?",
                             (int(active), acc.name))

    def delete(self, name: str) -> None:
        acc = self._require(name)
        if acc.source == "guest":
            raise UserError("the guest user stays; switch it off instead")
        self._not_owner(acc, "removed")
        self._keeps_an_admin(acc)
        with self._lock:
            self._db.execute("DELETE FROM users WHERE name = ?", (acc.name,))
            self._db.execute("DELETE FROM tokens WHERE user = ?", (acc.name,))

    def seen(self, name: str, source: str, groups: list[str],
             admin_by_group: bool | None) -> Account:
        """A user logged in through ``oidc`` or ``proxy``: recorded on first
        login (role ``user``), then kept up to date. ``admin_by_group``:
        True / False when the provider's admin group decides the role,
        None when the admin panel does."""
        acc = self.get(name)
        if acc is not None and acc.source == "guest":
            raise UserError(f"the name {GUEST!r} is kept for the guest user")
        if acc is not None and acc.source == "link":
            raise UserError(f"the name {acc.name!r} is an access link")
        if acc is None:
            role = "admin" if admin_by_group else "user"
            with self._lock:
                self._db.execute(
                    "INSERT OR IGNORE INTO users (name, role, source, groups, created, "
                    "last_login) VALUES (?, ?, ?, ?, ?, ?)",
                    (name, role, source, json.dumps(groups), _now(), _now()))
            return self.get(name)
        updates = {"groups": json.dumps(groups), "last_login": _now()}
        if admin_by_group is not None:
            updates["role"] = "admin" if admin_by_group else "user"
        with self._lock:
            self._db.execute(
                "UPDATE users SET " + ", ".join(f"{k} = ?" for k in updates)
                + " WHERE name = ?", (*updates.values(), acc.name))
        return self.get(name)

    # ---- settings ----------------------------------------------------------------
    @staticmethod
    def settings_of(acc: Account | None) -> dict:
        """Every setting: the user's, else its default (None: the container's)."""
        conf = acc.config if acc else {}
        return {k: conf[k] if conf.get(k) in allowed else default
                for k, (allowed, default) in SETTINGS.items()}

    def set_settings(self, name: str, changes: dict) -> dict:
        """Changes some settings (unknown names and values are refused, None
        goes back to the default). Returns all of them."""
        acc = self._require(name)
        conf = dict(acc.config)
        for key, value in changes.items():
            if key not in SETTINGS:
                raise UserError(f"there is no setting {key!r}")
            allowed, _ = SETTINGS[key]
            if value is None:
                conf.pop(key, None)
            elif value in allowed and type(value) is type(allowed[0]):
                conf[key] = value
            else:
                raise UserError(f"{key} is one of {', '.join(map(str, allowed))}")
        with self._lock:
            self._db.execute("UPDATE users SET config = ? WHERE name = ?",
                             (json.dumps(conf), acc.name))
        return self.settings_of(self.get(acc.name))

    def ensure_guest(self) -> Account:
        """The guest user, made on first use (switched on)."""
        with self._lock:
            self._db.execute(
                "INSERT OR IGNORE INTO users (name, role, source, created) "
                "VALUES (?, 'user', 'guest', ?)", (GUEST, _now()))
            self._db.execute("UPDATE users SET role = 'user', source = 'guest', "
                             "password = NULL WHERE name = ?", (GUEST,))
        return self.get(GUEST)

    def guest(self) -> Account | None:
        """The guest user when it is switched on."""
        acc = self.get(GUEST)
        if acc is None or acc.source != "guest" or not acc.active:
            return None
        self._touch(acc.name)
        return acc

    def set_shares(self, name: str, shares: list | None) -> list | None:
        """The folders a user may see and write (mcp_http/shares.py); None:
        back to DEFAULT_SHARES."""
        from .shares import validate
        acc = self._require(name)
        try:
            value = None if shares is None else validate(shares)
        except ValueError as exc:
            raise UserError(str(exc)) from None
        with self._lock:
            self._db.execute("UPDATE users SET shares = ? WHERE name = ?",
                             (None if value is None else json.dumps(value), acc.name))
        return value

    # ---- rights ------------------------------------------------------------------
    def set_rights(self, name: str, web: bool | None = None, mcp: bool | None = None) -> None:
        """What a user may use: the web viewer, the MCP server. An admin
        keeps the web viewer (where the users are managed)."""
        acc = self._require(name)
        if web is False and acc.admin:
            raise UserError("an admin keeps the web viewer; make them a user first")
        if mcp and acc.source == "guest":
            raise UserError("the guest cannot use the MCP server")
        if mcp and acc.source == "link":
            raise UserError("an access link is for the web viewer only")
        with self._lock:
            if web is not None:
                self._db.execute("UPDATE users SET web = ? WHERE name = ?", (int(web), acc.name))
            if mcp is not None:
                self._db.execute("UPDATE users SET mcp = ? WHERE name = ?", (int(mcp), acc.name))

    # ---- personal MCP tokens ---------------------------------------------------------
    @staticmethod
    def _token_hash(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def create_token(self, name: str, label: str = "") -> str:
        """A new MCP access token for ``name``; kept hashed, and encrypted
        so its owner can see it again (``show_token``)."""
        acc = self._require(name)
        if not acc.mcp:
            raise UserError(f"{acc.name} may not use the MCP server")
        token = TOKEN_PREFIX + secrets.token_urlsafe(32)
        with self._lock:
            key = self._token_hash(token)
            self._db.execute("INSERT INTO tokens (hash, user, label, created, kind, secret) "
                             "VALUES (?, ?, ?, ?, 'mcp', ?)",
                             (key, acc.name, label.strip()[:64], _now(),
                              self._vault.seal(token, key)))
        return token

    def tokens(self, name: str) -> list[dict]:
        """A user's tokens: id (the start of the hash), label, dates."""
        with self._lock:
            rows = self._db.execute("SELECT * FROM tokens WHERE user = ? AND kind = 'mcp' "
                                    "ORDER BY created",
                                    (name,)).fetchall()
        return [{"id": r["hash"][:12], "label": r["label"], "created": r["created"],
                 "last_used": r["last_used"],
                 "shown": self._vault.open(r["secret"], r["hash"]) is not None}
                for r in rows]

    def show_token(self, name: str, token_id: str) -> str | None:
        """One of ``name``'s MCP tokens again; None when there is no such
        token or no readable copy of it (made before, or another key)."""
        if not re.fullmatch(r"[0-9a-f]{12}", token_id or ""):
            return None
        with self._lock:
            row = self._db.execute("SELECT hash, secret FROM tokens WHERE user = ? "
                                   "AND kind = 'mcp' AND hash LIKE ?",
                                   (name, token_id + "%")).fetchone()
        return None if row is None else self._vault.open(row["secret"], row["hash"])

    def _used(self, key: str, token: str) -> None:
        """A token was just used: note when, and keep a readable copy if
        there is none (an older token, or a new key). Under the lock."""
        row = self._db.execute("SELECT secret FROM tokens WHERE hash = ?", (key,)).fetchone()
        if row is not None and self._vault.open(row["secret"], key) is None:
            self._db.execute("UPDATE tokens SET last_used = ?, secret = ? WHERE hash = ?",
                             (_now(), self._vault.seal(token, key), key))
        else:
            self._db.execute("UPDATE tokens SET last_used = ? WHERE hash = ?", (_now(), key))

    def revoke_token(self, name: str, token_id: str) -> bool:
        if not re.fullmatch(r"[0-9a-f]{12}", token_id or ""):
            return False
        with self._lock:
            cur = self._db.execute("DELETE FROM tokens WHERE user = ? AND kind = 'mcp' "
                                   "AND hash LIKE ?",
                                   (name, token_id + "%"))
        return cur.rowcount > 0

    def by_token(self, token: str) -> Account | None:
        """The user a personal MCP token belongs to, if they may use MCP."""
        if not token.startswith(TOKEN_PREFIX):
            return None
        key = self._token_hash(token)
        with self._lock:
            row = self._db.execute("SELECT user FROM tokens WHERE hash = ? AND kind = 'mcp'",
                                   (key,)).fetchone()
            if row is None:
                return None
            self._used(key, token)
        acc = self.get(row["user"])
        return acc if acc and acc.active and acc.mcp and acc.source not in SPECIAL else None

    # ---- access links (viewer only) --------------------------------------------------
    def create_link(self, name: str, expires: str | None = None) -> tuple[Account, str]:
        """A new access link: an account ``name`` (web viewer only, no
        folders yet) and its token, kept hashed and encrypted (``show_link``)."""
        name = " ".join(name.split())
        if not LINK_NAME.match(name):
            raise UserError("a link's name is 1–64 characters")
        if name.lower() == GUEST:
            raise UserError(f"the name {GUEST!r} is kept for the guest user")
        day = _check_date(expires)
        with self._lock:
            try:
                self._db.execute(
                    "INSERT INTO users (name, role, source, created, web, mcp, shares, expires) "
                    "VALUES (?, 'user', 'link', ?, 1, 0, '[]', ?)", (name, _now(), day))
            except sqlite3.IntegrityError:
                raise UserError(f"there is already a user or link {name!r}") from None
        return self.get(name), self.new_link(name)

    def _link(self, name: str) -> Account:
        acc = self._require(name)
        if acc.source != "link":
            raise UserError(f"{acc.name} is not an access link")
        return acc

    def new_link(self, name: str) -> str:
        """A new token for an access link; the old one (and every session
        opened with it) stops working."""
        acc = self._link(name)
        token = LINK_PREFIX + secrets.token_urlsafe(32)
        with self._lock:
            self._db.execute("DELETE FROM tokens WHERE user = ? AND kind = 'web'", (acc.name,))
            key = self._token_hash(token)
            self._db.execute("INSERT INTO tokens (hash, user, label, created, kind, secret) "
                             "VALUES (?, ?, '', ?, 'web', ?)",
                             (key, acc.name, _now(), self._vault.seal(token, key)))
        return token

    def set_expires(self, name: str, day: str | None) -> str | None:
        """The last day an access link works; None: no end."""
        acc = self._link(name)
        value = _check_date(day)
        with self._lock:
            self._db.execute("UPDATE users SET expires = ? WHERE name = ?", (value, acc.name))
        return value

    def link_info(self, name: str) -> dict | None:
        """An access link's token: id (the start of its hash), dates."""
        with self._lock:
            row = self._db.execute("SELECT * FROM tokens WHERE user = ? AND kind = 'web'",
                                   (name,)).fetchone()
        return None if row is None else {
            "id": row["hash"][:12], "created": row["created"], "last_used": row["last_used"],
            "shown": self._vault.open(row["secret"], row["hash"]) is not None}

    def show_link(self, name: str) -> str | None:
        """An access link's current token again; None when there is none or
        no readable copy of it (made before, or another key)."""
        acc = self._link(name)
        with self._lock:
            row = self._db.execute("SELECT hash, secret FROM tokens WHERE user = ? "
                                   "AND kind = 'web'", (acc.name,)).fetchone()
        return None if row is None else self._vault.open(row["secret"], row["hash"])

    def by_link(self, token: str) -> tuple[Account, str] | None:
        """The access link a token opens, and its id, if it may in now
        (switched on, not expired)."""
        if not token.startswith(LINK_PREFIX):
            return None
        key = self._token_hash(token)
        with self._lock:
            row = self._db.execute("SELECT user FROM tokens WHERE hash = ? AND kind = 'web'",
                                   (key,)).fetchone()
            if row is None:
                return None
            self._used(key, token)
        acc = self.get(row["user"])
        if not self.link_usable(acc):
            return None
        self._touch(acc.name)
        return acc, key[:12]

    def link_usable(self, acc: Account | None, token_id: str | None = None) -> bool:
        """Whether an access link may in now; with ``token_id``: and that is
        still its token (not replaced or removed)."""
        if acc is None or acc.source != "link" or not acc.active or not acc.web or acc.expired:
            return False
        if token_id is None:
            return True
        info = self.link_info(acc.name)
        return info is not None and hmac.compare_digest(info["id"], token_id)

    def set_avatar(self, name: str, avatar: dict | None) -> None:
        """The user's avatar (viewer/avatar.py checks it); None: the default."""
        acc = self._require(name)
        with self._lock:
            self._db.execute("UPDATE users SET avatar = ? WHERE name = ?",
                             (None if avatar is None else json.dumps(avatar), acc.name))

    def ensure_admin(self, name: str, password: str) -> bool:
        """The first admin, from the environment: created when there is no
        active admin yet. True when it was."""
        if self.active_admins():
            return False
        acc = self.get(name)
        if acc is None:
            self.create(name, password, "admin")
            self.set_rights(name, mcp=True)
        else:
            with self._lock:
                self._db.execute(
                    "UPDATE users SET role = 'admin', active = 1, source = 'local', web = 1, "
                    "mcp = 1, password = ? WHERE name = ?", (hash_password(password), acc.name))
        return True

    def import_json(self, path: Path) -> int:
        """The list of an older viewer (``/state/users.json``): the users
        not known yet. Returns how many."""
        try:
            old = json.loads(path.read_text("utf-8"))
        except (OSError, ValueError):
            return 0
        added = 0
        for name, rec in (old or {}).items():
            if not isinstance(rec, dict) or self.get(name) is not None or not NAME.match(name):
                continue
            source = rec.get("source") if rec.get("source") in ("oidc", "proxy") else "oidc"
            with self._lock:
                self._db.execute(
                    "INSERT OR IGNORE INTO users (name, role, source, groups, created, "
                    "last_login) VALUES (?, ?, ?, ?, ?, ?)",
                    (name, "admin" if rec.get("role") == "admin" else "user", source,
                     json.dumps(rec.get("groups") or []),
                     rec.get("first_login") or _now(), rec.get("last_login")))
            added += 1
        return added
