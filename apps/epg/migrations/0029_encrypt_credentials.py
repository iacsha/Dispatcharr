import core.fields
from core.encryption import encrypt_columns
from django.db import migrations

encrypt_sources, decrypt_sources = encrypt_columns(
    "epg_epgsource", ["url", "username", "password"]
)


class Migration(migrations.Migration):

    dependencies = [
        ("epg", "0028_programdata_epg_end_index"),
    ]

    operations = [
        migrations.AlterField(
            model_name="epgsource",
            name="password",
            field=core.fields.EncryptedCharField(
                blank=True,
                help_text="Password for credential-based EPG sources (e.g. Schedules Direct)",
                max_length=255,
                null=True,
            ),
        ),
        migrations.AlterField(
            model_name="epgsource",
            name="url",
            field=core.fields.EncryptedURLField(blank=True, max_length=1000, null=True),
        ),
        migrations.AlterField(
            model_name="epgsource",
            name="username",
            field=core.fields.EncryptedCharField(
                blank=True,
                help_text="Username for credential-based EPG sources (e.g. Schedules Direct)",
                max_length=255,
                null=True,
            ),
        ),
        migrations.RunPython(encrypt_sources, decrypt_sources),
    ]
