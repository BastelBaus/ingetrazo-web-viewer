# SPDX-License-Identifier: AGPL-3.0-or-later
"""Encrypted copies of the access tokens, so their owner can see them again.

Tokens are checked by their SHA-256 hash (mcp_http/users.py); next to the
hash the list keeps the token encrypted with a key that is *not* in the
database, so a copy of ``users.db`` alone gives away no token.

The key: ``TOKEN_KEY`` (any string of at least 16 characters), or else the
file ``TOKEN_KEY_FILE`` names, or else ``token.key`` next to the users'
database, made on the first start (mode 0600). The viewer and the MCP
server share the database's volume, so they share that file too. A new key
makes the stored copies unreadable: the tokens keep working, they just
cannot be shown again until they are used once more (or replaced).

The cipher uses the Python standard library only: HMAC-SHA256 as a
pseudo-random function in counter mode for the key stream, then an
HMAC-SHA256 tag over nonce, cipher text and the token's hash (encrypt then
MAC), so a copy cannot be moved to another row.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from pathlib import Path

VERSION = "v1"
MIN_KEY = 16
NONCE = 16
TAG = 32


def _sub(key: bytes, what: bytes) -> bytes:
    return hmac.new(key, b"ingetrazo-token-vault:" + what, hashlib.sha256).digest()


def _stream(key: bytes, nonce: bytes, size: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < size:
        out += hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        counter += 1
    return bytes(out[:size])


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def load_key(db_path: Path) -> bytes:
    """The vault key (32 bytes): from TOKEN_KEY, TOKEN_KEY_FILE, or the file
    ``token.key`` next to the database (made when missing)."""
    text = os.environ.get("TOKEN_KEY", "").strip()
    if text:
        if len(text) < MIN_KEY:
            raise SystemExit(f"TOKEN_KEY needs at least {MIN_KEY} characters")
        return hashlib.sha256(text.encode()).digest()
    name = os.environ.get("TOKEN_KEY_FILE", "").strip()
    path = Path(name) if name else Path(db_path).parent / "token.key"
    try:
        text = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        text = ""
    if not text:
        text = secrets.token_urlsafe(32)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:            # O_EXCL: when two containers start at once, one file wins
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            text = path.read_text(encoding="utf-8").strip()
        else:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(text + "\n")
    if len(text) < MIN_KEY:
        raise SystemExit(f"{path}: the token key needs at least {MIN_KEY} characters")
    return hashlib.sha256(text.encode()).digest()


class Vault:
    def __init__(self, key: bytes) -> None:
        self._enc = _sub(key, b"enc")
        self._mac = _sub(key, b"mac")

    def _tag(self, nonce: bytes, data: bytes, bound: str) -> bytes:
        return hmac.new(self._mac, nonce + data + b"\0" + bound.encode(),
                        hashlib.sha256).digest()

    def seal(self, token: str, bound: str) -> str:
        """``token`` encrypted, bound to ``bound`` (the token's hash)."""
        nonce = secrets.token_bytes(NONCE)
        data = _xor(token.encode(), _stream(self._enc, nonce, len(token.encode())))
        blob = nonce + data + self._tag(nonce, data, bound)
        return VERSION + "$" + base64.urlsafe_b64encode(blob).decode()

    def open(self, sealed: str | None, bound: str) -> str | None:
        """The token back, or None: nothing stored, another key, or tampered."""
        try:
            version, _, text = (sealed or "").partition("$")
            if version != VERSION:
                return None
            blob = base64.urlsafe_b64decode(text.encode())
        except (ValueError, TypeError):
            return None
        if len(blob) < NONCE + TAG + 1:
            return None
        nonce, data, tag = blob[:NONCE], blob[NONCE:-TAG], blob[-TAG:]
        if not hmac.compare_digest(tag, self._tag(nonce, data, bound)):
            return None
        try:
            token = _xor(data, _stream(self._enc, nonce, len(data))).decode()
        except UnicodeDecodeError:
            return None
        # The hash still has to match: the row's token, nothing else.
        return token if hmac.compare_digest(
            hashlib.sha256(token.encode()).hexdigest(), bound) else None
