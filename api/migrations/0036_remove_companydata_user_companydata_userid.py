# Generated by Django 4.2.10 on 2024-05-12 22:26

import api.models
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0035_alter_emailcode_userid'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='companydata',
            name='user',
        ),
        migrations.AddField(
            model_name='companydata',
            name='userid',
            field=models.IntegerField(default=0, unique=True, verbose_name=api.models.User),
        ),
    ]
