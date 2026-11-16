import core.fields
from core.encryption import encrypt_columns
from django.db import migrations

encrypt_urls, decrypt_urls = encrypt_columns("dispatcharr_channels_stream", ["url"])


class Migration(migrations.Migration):

    dependencies = [
        ("dispatcharr_channels", "0041_alter_stream_url_max_length"),
    ]

    operations = [
        migrations.AlterField(
            model_name="stream",
            name="url",
            field=core.fields.EncryptedURLField(blank=True, max_length=8192, null=True),
        ),
        migrations.RunPython(encrypt_urls, decrypt_urls),
    ]
