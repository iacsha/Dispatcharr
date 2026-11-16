"""Encryption at rest for provider credentials.

M3U and EPG account logins (and URLs that often carry them) are stored as
``enc:v1:<Fernet token>`` and decrypted only in memory. The key comes from,
in order:

1. ``DISPATCHARR_CREDENTIALS_KEY``: a Fernet key (32 url-safe base64 bytes).
2. ``DISPATCHARR_CREDENTIALS_KEY_FILE``: a file holding one, such as a
   Docker secret. Defaults to ``/data/credentials.key``, which is created on
   the first write that needs it.

The key is never stored in the database, so a database dump or a backup
archive (which holds only the dump) no longer carries usable provider logins.
Restoring a backup on another host needs the same key there.

Plain-text values from older releases are read as they are; migrations
encrypt them in place.
"""

from __future__ import annotations

import base64
import binascii
import logging
import os
import re
import tempfile
import threading
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

PREFIX = "enc:v1:"
KEY_ENV = "DISPATCHARR_CREDENTIALS_KEY"
KEY_FILE_ENV = "DISPATCHARR_CREDENTIALS_KEY_FILE"
DEFAULT_KEY_FILE = "/data/credentials.key"

_lock = threading.Lock()
_cached: tuple[tuple[str, str], Fernet] | None = None


class CredentialsKeyError(RuntimeError):
    """Stored credentials cannot be decrypted with the configured key."""


def is_encrypted(value: object) -> bool:
    return isinstance(value, str) and value.startswith(PREFIX)


_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")


def looks_like_token(value: object) -> bool:
    """Whether ``value`` is ``PREFIX`` followed by a well-formed Fernet token.

    Checks only the shape (version byte, minimum length, block-aligned body),
    not the signature, so it also holds for tokens made with another key.
    """
    if not is_encrypted(value):
        return False
    token = value[len(PREFIX):]
    if not _TOKEN_RE.match(token):
        return False
    try:
        raw = base64.urlsafe_b64decode(token)
    except (binascii.Error, ValueError):
        return False
    # version (1) + timestamp (8) + IV (16) + AES blocks (16n, n >= 1) + HMAC (32)
    return raw[:1] == b"\x80" and len(raw) >= 73 and (len(raw) - 57) % 16 == 0


def is_ciphertext(value: object) -> bool:
    """Whether ``value`` is stored ciphertext rather than plain text that looks like it.

    True when it decrypts with the configured key or, failing that, is still a
    well-formed token (encrypted under another key). Such values are written back
    unchanged: encrypting them again would wrap the only copy of the credential
    in a second layer that the original key cannot open.
    """
    if not is_encrypted(value):
        return False
    try:
        decrypt(value)
        return True
    except CredentialsKeyError:
        return looks_like_token(value)


def key_file_path() -> Path:
    return Path(os.environ.get(KEY_FILE_ENV, "").strip() or DEFAULT_KEY_FILE)


def _read_key(path: Path) -> str | None:
    try:
        return path.read_text().strip() or None
    except FileNotFoundError:
        return None


def _create_key_file(path: Path) -> str:
    """Write a new key so the file only ever appears complete.

    The key is written to a temporary file and hard-linked into place; the
    link fails if another process (web and Celery share the data volume) got
    there first, and that process's key wins.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    key = Fernet.generate_key().decode()
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".credentials-key-")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(key + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.link(tmp, path)
        except FileExistsError:
            existing = _read_key(path)
            if existing is None:
                raise CredentialsKeyError(f"Credentials key file {path} is empty")
            return existing
    finally:
        os.unlink(tmp)
    logger.info("Created credentials encryption key at %s", path)
    return key


def _fernet(*, create: bool) -> Fernet | None:
    """The configured key; with ``create``, generate the key file if missing."""
    global _cached
    configured = os.environ.get(KEY_ENV, "").strip()
    path = key_file_path()
    source = ("env", configured) if configured else ("file", str(path))
    with _lock:
        if _cached is not None and _cached[0] == source:
            return _cached[1]
        key = configured or _read_key(path)
        if key is None:
            if not create:
                return None
            key = _create_key_file(path)
        try:
            fernet = Fernet(key.encode())
        except ValueError as exc:
            where = KEY_ENV if configured else str(path)
            raise CredentialsKeyError(f"Invalid credentials key in {where}") from exc
        _cached = (source, fernet)
        return fernet


def encrypt(value: str) -> str:
    fernet = _fernet(create=True)
    assert fernet is not None
    return PREFIX + fernet.encrypt(value.encode()).decode()


def decrypt(value: str) -> str:
    """Decrypt a stored value; plain text from older rows is returned as is."""
    if not is_encrypted(value):
        return value
    fernet = _fernet(create=False)
    if fernet is None:
        raise CredentialsKeyError(
            f"Stored credentials are encrypted but no key was found "
            f"(set {KEY_ENV} or {KEY_FILE_ENV}, or restore {key_file_path()})"
        )
    try:
        return fernet.decrypt(value[len(PREFIX):].encode()).decode()
    except InvalidToken as exc:
        raise CredentialsKeyError(
            "Stored credentials do not decrypt with the configured key"
        ) from exc


def reset_cache() -> None:
    """Forget the loaded key (tests, key rotation)."""
    global _cached
    with _lock:
        _cached = None


# One sample per column is enough: every row is encrypted with the same key.
_CHECK_COLUMNS = (
    ("m3u_m3uaccount", "password"),
    ("m3u_m3uaccount", "server_url"),
    ("epg_epgsource", "password"),
    ("epg_epgsource", "url"),
)


def check_stored_credentials(connection) -> bool:
    """Log CRITICAL when stored credentials do not open with the configured key.

    Run once at startup. A lost or replaced key otherwise shows up only as one
    error on the first provider request, while the web UI keeps running. Returns
    False when a sampled value is a well-formed token the key cannot decrypt.
    """
    qn = connection.ops.quote_name
    with connection.cursor() as cursor:
        for table, column in _CHECK_COLUMNS:
            cursor.execute(
                f"SELECT {qn(column)} FROM {qn(table)} WHERE {qn(column)} LIKE %s LIMIT 1",
                [PREFIX + "%"],
            )
            row = cursor.fetchone()
            if row is None or not looks_like_token(row[0]):
                continue
            try:
                decrypt(row[0])
            except CredentialsKeyError as exc:
                configured = os.environ.get(KEY_ENV, "").strip()
                source = KEY_ENV if configured else str(key_file_path())
                logger.critical(
                    "%s (key source: %s). M3U and EPG refreshes and playback for "
                    "accounts saved under the previous key will fail. Restore that key "
                    "(%s, or the file named by %s, default %s) and restart; re-enter "
                    "the affected credentials only if the key is lost for good.",
                    exc, source, KEY_ENV, KEY_FILE_ENV, DEFAULT_KEY_FILE,
                )
                return False
    return True


_BATCH = 2000


def _rewrite_columns(schema_editor, table: str, columns: list[str], transform) -> None:
    """Apply ``transform`` to every non-empty value of ``columns`` by raw SQL.

    Migrations use raw SQL because the model fields would encrypt or decrypt
    on their own and hide what is actually stored. Rows are read in id order
    in batches, so large stream tables are not loaded into memory at once.
    """
    qn = schema_editor.connection.ops.quote_name
    cols = ", ".join(qn(c) for c in columns)
    select = (
        f"SELECT {qn('id')}, {cols} FROM {qn(table)} "
        f"WHERE {qn('id')} > %s ORDER BY {qn('id')} LIMIT {_BATCH}"
    )
    last_id = -1
    with schema_editor.connection.cursor() as cursor:
        while True:
            cursor.execute(select, [last_id])
            rows = cursor.fetchall()
            if not rows:
                break
            last_id = rows[-1][0]
            updates: dict[tuple[str, ...], list[list]] = {}
            for row_id, *values in rows:
                changed = {}
                for col, value in zip(columns, values):
                    if value is None or value == "":
                        continue
                    new = transform(value)
                    if new != value:
                        changed[col] = new
                if changed:
                    updates.setdefault(tuple(changed), []).append([*changed.values(), row_id])
            for changed_cols, params in updates.items():
                assignments = ", ".join(f"{qn(c)} = %s" for c in changed_cols)
                cursor.executemany(
                    f"UPDATE {qn(table)} SET {assignments} WHERE {qn('id')} = %s", params
                )


def _encrypt_stored(value: str) -> str:
    return value if is_ciphertext(value) else encrypt(value)


def encrypt_columns(table: str, columns: list[str]):
    """RunPython callables that encrypt ``columns`` in place, and undo it."""

    def forwards(apps, schema_editor):
        _rewrite_columns(schema_editor, table, columns, _encrypt_stored)

    def backwards(apps, schema_editor):
        _rewrite_columns(schema_editor, table, columns, decrypt)

    return forwards, backwards
