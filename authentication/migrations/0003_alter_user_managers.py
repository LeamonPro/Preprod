# Generated by Django 5.0.3 on 2024-03-19 11:16

import authentication.models
from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("authentication", "0002_alter_user_managers"),
    ]

    operations = [
        migrations.AlterModelManagers(
            name="user",
            managers=[
                ("objects", authentication.models.UserManager()),
            ],
        ),
    ]
