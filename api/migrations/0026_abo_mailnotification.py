# Generated by Django 4.2.6 on 2024-01-03 10:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0025_abo_imageid'),
    ]

    operations = [
        migrations.AddField(
            model_name='abo',
            name='mailnotification',
            field=models.BooleanField(default=True),
        ),
    ]
