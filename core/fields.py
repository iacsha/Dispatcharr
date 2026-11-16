"""Model fields that encrypt their value at rest (see core.encryption)."""

from __future__ import annotations

import logging

from django.db import models

from core import encryption

logger = logging.getLogger(__name__)

_warned = False


class UndecryptableValue(str):
    """Ciphertext that the configured key cannot open.

    It is handed to the application as is, so provider requests fail with a
    clear log error rather than using an empty login, and it is written back
    unchanged on save, so restoring the right key later still recovers it.
    """


class EncryptedFieldMixin:
    """Stores the value Fernet-encrypted in a text column.

    ``max_length`` still validates the plain value; the column is ``text``
    because ciphertext is longer than its input.
    """

    def get_internal_type(self):
        return "TextField"

    def from_db_value(self, value, expression, connection):
        if value is None or not encryption.is_encrypted(value):
            return value
        try:
            return encryption.decrypt(value)
        except encryption.CredentialsKeyError as exc:
            global _warned
            if not _warned:
                _warned = True
                logger.error("%s; affected accounts will fail until the key is restored", exc)
            return UndecryptableValue(value)

    def get_prep_value(self, value):
        value = super().get_prep_value(value)
        if value is None or value == "":
            return value
        if isinstance(value, UndecryptableValue):
            return str(value)
        return encryption.encrypt(str(value))


class EncryptedCharField(EncryptedFieldMixin, models.CharField):
    pass


class EncryptedURLField(EncryptedFieldMixin, models.URLField):
    pass
