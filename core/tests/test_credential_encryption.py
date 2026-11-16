"""Encryption at rest of provider credentials (core.encryption, core.fields)."""
import os
import stat
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from cryptography.fernet import Fernet
from django.db import connection
from django.test import SimpleTestCase, TestCase

from apps.epg.models import EPGSource
from apps.m3u.models import M3UAccount, M3UAccountProfile
from core import encryption
from core.fields import UndecryptableValue


def _key_env(key=None, key_file=None):
    env = {encryption.KEY_ENV: key or "", encryption.KEY_FILE_ENV: key_file or ""}
    return mock.patch.dict(os.environ, env)


def _raw(table, column, row_id):
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT {column} FROM {table} WHERE id = %s", [row_id])
        return cursor.fetchone()[0]


def _set_raw(table, column, row_id, value):
    with connection.cursor() as cursor:
        cursor.execute(f"UPDATE {table} SET {column} = %s WHERE id = %s", [value, row_id])


class EncryptionTests(SimpleTestCase):
    def setUp(self):
        encryption.reset_cache()
        self.addCleanup(encryption.reset_cache)
        self.tmp = Path(tempfile.mkdtemp())

    def test_round_trip_with_env_key(self):
        with _key_env(key=Fernet.generate_key().decode()):
            token = encryption.encrypt("hunter2")
            self.assertTrue(token.startswith(encryption.PREFIX))
            self.assertNotIn("hunter2", token)
            self.assertEqual(encryption.decrypt(token), "hunter2")

    def test_plain_text_passes_through(self):
        with _key_env(key=Fernet.generate_key().decode()):
            self.assertEqual(encryption.decrypt("legacy-plain"), "legacy-plain")

    def test_key_file_created_private_on_first_write(self):
        key_file = self.tmp / "sub" / "credentials.key"
        with _key_env(key_file=str(key_file)):
            token = encryption.encrypt("pw")
        self.assertTrue(key_file.exists())
        self.assertEqual(stat.S_IMODE(key_file.stat().st_mode), 0o600)
        self.assertEqual(list(key_file.parent.glob(".credentials-key-*")), [])
        encryption.reset_cache()
        with _key_env(key_file=str(key_file)):
            self.assertEqual(encryption.decrypt(token), "pw")

    def test_existing_key_file_is_kept(self):
        key = Fernet.generate_key().decode()
        key_file = self.tmp / "credentials.key"
        key_file.write_text(key + "\n")
        with _key_env(key_file=str(key_file)):
            token = encryption.encrypt("pw")
        self.assertEqual(key_file.read_text().strip(), key)
        self.assertEqual(Fernet(key.encode()).decrypt(token[len(encryption.PREFIX):].encode()), b"pw")

    def test_key_file_race_uses_the_winner(self):
        key_file = self.tmp / "credentials.key"
        winner = Fernet.generate_key().decode()
        real_link = os.link

        def link_after_other_process(src, dst):
            Path(dst).write_text(winner)
            return real_link(src, dst)

        with mock.patch("core.encryption.os.link", side_effect=link_after_other_process):
            self.assertEqual(encryption._create_key_file(key_file), winner)
        self.assertEqual(key_file.read_text(), winner)

    def test_read_without_key_does_not_create_one(self):
        key_file = self.tmp / "credentials.key"
        with _key_env(key_file=str(key_file)):
            with self.assertRaises(encryption.CredentialsKeyError):
                encryption.decrypt(encryption.PREFIX + "gAAAAA")
        self.assertFalse(key_file.exists())

    def test_wrong_key_raises(self):
        with _key_env(key=Fernet.generate_key().decode()):
            token = encryption.encrypt("pw")
        encryption.reset_cache()
        with _key_env(key=Fernet.generate_key().decode()):
            with self.assertRaises(encryption.CredentialsKeyError):
                encryption.decrypt(token)

    def test_invalid_key_raises_key_error(self):
        with _key_env(key="not-a-fernet-key"):
            with self.assertRaises(encryption.CredentialsKeyError):
                encryption.encrypt("pw")


class EncryptedFieldTests(TestCase):
    def setUp(self):
        encryption.reset_cache()
        self.addCleanup(encryption.reset_cache)

    def _account(self, **kwargs):
        fields = dict(
            name="Enc XC",
            server_url="http://provider.test:8080/get.php?username=u1&password=p1",
            account_type="XC",
            username="u1",
            password="p1-secret",
        )
        fields.update(kwargs)
        return M3UAccount.objects.create(**fields)

    def test_account_credentials_stored_encrypted(self):
        account = self._account()
        for column in ("server_url", "username", "password"):
            stored = _raw("m3u_m3uaccount", column, account.id)
            self.assertTrue(stored.startswith(encryption.PREFIX), column)
        self.assertNotIn("p1-secret", _raw("m3u_m3uaccount", "password", account.id))
        fresh = M3UAccount.objects.get(pk=account.pk)
        self.assertEqual(fresh.password, "p1-secret")
        self.assertEqual(fresh.username, "u1")
        self.assertEqual(fresh.server_url, account.server_url)
        self.assertEqual(
            M3UAccount.objects.filter(pk=account.pk).values_list("password", flat=True).get(),
            "p1-secret",
        )

    def test_empty_and_null_stay_plain(self):
        account = self._account(name="Std", account_type="STD", username="", password=None)
        self.assertEqual(_raw("m3u_m3uaccount", "username", account.id), "")
        self.assertIsNone(_raw("m3u_m3uaccount", "password", account.id))

    def test_plain_text_rows_still_read(self):
        account = self._account()
        _set_raw("m3u_m3uaccount", "password", account.id, "legacy-plain")
        self.assertEqual(M3UAccount.objects.get(pk=account.pk).password, "legacy-plain")

    def test_value_that_looks_encrypted_round_trips(self):
        account = self._account(password=encryption.PREFIX + "not-a-token")
        self.assertEqual(
            M3UAccount.objects.get(pk=account.pk).password, encryption.PREFIX + "not-a-token"
        )

    def test_profile_patterns_stored_encrypted(self):
        account = self._account()
        profile = M3UAccountProfile.objects.create(
            m3u_account=account,
            name="Alt login",
            search_pattern="/u1/p1-secret/",
            replace_pattern="/u2/p2-secret/",
        )
        for column in ("search_pattern", "replace_pattern"):
            self.assertTrue(
                _raw("m3u_m3uaccountprofile", column, profile.id).startswith(encryption.PREFIX)
            )
        fresh = M3UAccountProfile.objects.get(pk=profile.pk)
        self.assertEqual(fresh.replace_pattern, "/u2/p2-secret/")

    def test_epg_source_credentials_stored_encrypted(self):
        source = EPGSource.objects.create(
            name="SD",
            source_type="schedules_direct",
            url="http://epg.test/xmltv.php?username=u1&password=p1",
            username="sd-user",
            password="sd-pass",
        )
        for column in ("url", "username", "password"):
            self.assertTrue(_raw("epg_epgsource", column, source.id).startswith(encryption.PREFIX))
        fresh = EPGSource.objects.get(pk=source.pk)
        self.assertEqual((fresh.username, fresh.password), ("sd-user", "sd-pass"))

    def test_stream_url_stored_encrypted(self):
        from apps.channels.models import Stream

        account = self._account()
        url = "http://provider.test:8080/live/u1/p1-secret/123.ts"
        stream = Stream.objects.create(name="S", url=url, m3u_account=account)
        stored = _raw("dispatcharr_channels_stream", "url", stream.id)
        self.assertTrue(stored.startswith(encryption.PREFIX))
        self.assertNotIn("p1-secret", stored)
        self.assertEqual(Stream.objects.get(pk=stream.pk).url, url)
        self.assertEqual(Stream.objects.filter(pk=stream.pk).values_list("url", flat=True).get(), url)

        Stream.objects.bulk_update([Stream(pk=stream.pk, url=url + "?v=2")], ["url"])
        stored = _raw("dispatcharr_channels_stream", "url", stream.id)
        self.assertTrue(stored.startswith(encryption.PREFIX))
        self.assertEqual(Stream.objects.get(pk=stream.pk).url, url + "?v=2")

    def test_undecryptable_value_is_kept_on_save(self):
        account = self._account()
        stored = _raw("m3u_m3uaccount", "password", account.id)
        encryption.reset_cache()
        with _key_env(key=Fernet.generate_key().decode()):
            with self.assertLogs("core.fields", level="ERROR"):
                with mock.patch("core.fields._warned", False):
                    loaded = M3UAccount.objects.get(pk=account.pk)
            self.assertIsInstance(loaded.password, UndecryptableValue)
            loaded.max_streams = 3
            loaded.save()
        self.assertEqual(_raw("m3u_m3uaccount", "password", account.id), stored)
        encryption.reset_cache()
        self.assertEqual(M3UAccount.objects.get(pk=account.pk).password, "p1-secret")


class EncryptColumnsMigrationTests(TestCase):
    def setUp(self):
        encryption.reset_cache()
        self.addCleanup(encryption.reset_cache)
        self.editor = SimpleNamespace(connection=connection)

    def test_forwards_encrypts_plain_rows_and_backwards_restores_them(self):
        account = M3UAccount.objects.create(
            name="Legacy", server_url="http://p.test", account_type="XC",
            username="lu", password="lp",
        )
        plain = {"server_url": "http://p.test", "username": "lu", "password": encryption.PREFIX + "lookalike"}
        for column, value in plain.items():
            _set_raw("m3u_m3uaccount", column, account.id, value)
        _set_raw("m3u_m3uaccount", "username", account.id, "lu")
        forwards, backwards = encryption.encrypt_columns(
            "m3u_m3uaccount", ["server_url", "username", "password"]
        )

        forwards(None, self.editor)
        once = {c: _raw("m3u_m3uaccount", c, account.id) for c in plain}
        for column, value in once.items():
            self.assertTrue(value.startswith(encryption.PREFIX), column)
            self.assertEqual(encryption.decrypt(value), plain[column])

        forwards(None, self.editor)
        self.assertEqual({c: _raw("m3u_m3uaccount", c, account.id) for c in plain}, once)

        backwards(None, self.editor)
        self.assertEqual({c: _raw("m3u_m3uaccount", c, account.id) for c in plain}, plain)

    def test_forwards_walks_every_batch(self):
        names = [f"Batch {i}" for i in range(5)]
        ids = [
            M3UAccount.objects.create(name=n, server_url="http://p.test", account_type="XC").id
            for n in names
        ]
        for row_id in ids:
            _set_raw("m3u_m3uaccount", "password", row_id, f"plain-{row_id}")
        forwards, _ = encryption.encrypt_columns("m3u_m3uaccount", ["password"])
        with mock.patch("core.encryption._BATCH", 2):
            forwards(None, self.editor)
        for row_id in ids:
            stored = _raw("m3u_m3uaccount", "password", row_id)
            self.assertTrue(encryption.is_encrypted(stored), row_id)
            self.assertEqual(encryption.decrypt(stored), f"plain-{row_id}")


class XtreamAccountInfoTests(SimpleTestCase):
    def test_account_info_does_not_keep_the_password(self):
        from core.xtream_codes import Client

        client = Client.__new__(Client)
        client.server_info = {
            "user_info": {"username": "u1", "password": "p1-secret", "status": "Active"},
            "server_info": {},
        }
        info = client.get_account_info()
        self.assertEqual(info["user_info"]["username"], "u1")
        self.assertNotIn("password", info["user_info"])
        self.assertNotIn("p1-secret", repr(info))


class DropStoredXcPasswordsMigrationTests(TestCase):
    def test_removes_only_the_echoed_password(self):
        from importlib import import_module

        from django.apps import apps as django_apps

        migration = import_module("apps.m3u.migrations.0020_encrypt_credentials")
        account = M3UAccount.objects.create(name="XC info", server_url="http://p.test", account_type="XC")
        profile = M3UAccountProfile.objects.get(m3u_account=account, is_default=True)
        profile.custom_properties = {
            "user_info": {"username": "u1", "password": "p1-secret", "status": "Active"},
            "server_info": {"url": "p.test"},
        }
        profile.save(update_fields=["custom_properties"])

        migration.drop_stored_xc_passwords(django_apps, None)

        profile.refresh_from_db()
        self.assertEqual(
            profile.custom_properties,
            {"user_info": {"username": "u1", "status": "Active"}, "server_info": {"url": "p.test"}},
        )
