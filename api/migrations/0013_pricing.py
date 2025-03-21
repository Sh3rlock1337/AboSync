# Generated by Django 4.2.6 on 2023-10-25 17:05

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0012_billingintervalls'),
    ]

    operations = [
        migrations.CreateModel(
            name='Pricing',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('preis', models.IntegerField()),
                ('besitzer', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.user')),
                ('kategories', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.item')),
                ('rechnungsintervall', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.billingintervalls')),
            ],
        ),
    ]
