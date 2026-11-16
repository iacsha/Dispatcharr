import core.fields
from core.encryption import encrypt_columns
from django.db import migrations

encrypt_accounts, decrypt_accounts = encrypt_columns(
    "m3u_m3uaccount", ["server_url", "username", "password"]
)
encrypt_profiles, decrypt_profiles = encrypt_columns(
    "m3u_m3uaccountprofile", ["search_pattern", "replace_pattern"]
)


def drop_stored_xc_passwords(apps, schema_editor):
    """Remove the provider-echoed login from saved XC account info.

    The account already holds the username and password (now encrypted); this
    JSON copy is plain text. The profile API fills the username in for display.
    """
    M3UAccountProfile = apps.get_model("m3u", "M3UAccountProfile")
    for profile in M3UAccountProfile.objects.exclude(custom_properties=None).iterator():
        props = profile.custom_properties
        user_info = props.get("user_info") if isinstance(props, dict) else None
        if isinstance(user_info, dict) and ("password" in user_info or "username" in user_info):
            user_info.pop("password", None)
            user_info.pop("username", None)
            profile.save(update_fields=["custom_properties"])


class Migration(migrations.Migration):

    dependencies = [
        ("m3u", "0019_m3uaccountprofile_exp_date"),
    ]

    operations = [
        migrations.AlterField(
            model_name="m3uaccount",
            name="password",
            field=core.fields.EncryptedCharField(blank=True, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name="m3uaccount",
            name="server_url",
            field=core.fields.EncryptedURLField(
                blank=True,
                help_text="The base URL of the M3U server (optional if a file is uploaded)",
                max_length=1000,
                null=True,
            ),
        ),
        migrations.AlterField(
            model_name="m3uaccount",
            name="username",
            field=core.fields.EncryptedCharField(blank=True, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name="m3uaccountprofile",
            name="replace_pattern",
            field=core.fields.EncryptedCharField(max_length=255),
        ),
        migrations.AlterField(
            model_name="m3uaccountprofile",
            name="search_pattern",
            field=core.fields.EncryptedCharField(max_length=255),
        ),
        migrations.RunPython(encrypt_accounts, decrypt_accounts),
        migrations.RunPython(encrypt_profiles, decrypt_profiles),
        migrations.RunPython(drop_stored_xc_passwords, migrations.RunPython.noop),
    ]
