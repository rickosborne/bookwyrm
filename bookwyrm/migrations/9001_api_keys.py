from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("bookwyrm", "0017_auto_20201130_1819"),
    ]

    operations = [
        migrations.AddField(
            model_name="user",
            name="api_key",
            field=models.CharField(
                blank=True,
                max_length=82,
                null=True,
                default=None,
            ),
        ),
    ]
