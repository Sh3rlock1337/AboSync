# Generated by Django 4.2.6 on 2023-10-20 09:06

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0008_companydata'),
    ]

    operations = [
        migrations.CreateModel(
            name='registrationModelData',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('userid', models.PositiveIntegerField()),
                ('emailverification', models.PositiveIntegerField()),
                ('endofdemo', models.PositiveIntegerField()),
            ],
        ),
    ]
