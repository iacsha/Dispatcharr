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

import logging
import os
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
    if is_encrypted(value):
        try:
            decrypt(value)
            return value
        except CredentialsKeyError:
            # Plain text that only looks like ciphertext.
            pass
    return encrypt(value)


def encrypt_columns(table: str, columns: list[str]):
    """RunPython callables that encrypt ``columns`` in place, and undo it."""

    def forwards(apps, schema_editor):
        _rewrite_columns(schema_editor, table, columns, _encrypt_stored)

    def backwards(apps, schema_editor):
        _rewrite_columns(schema_editor, table, columns, decrypt)

    return forwards, backwards
