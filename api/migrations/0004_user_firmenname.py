# Generated by Django 4.2.6 on 2023-10-19 13:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0003_rename_firstname_userprofile_first_name_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='firmenname',
            field=models.CharField(default='', max_length=255),
        ),
    ]
