# Generated by Django 3.2.4 on 2021-06-27 19:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0002_scanner_vulners'),
    ]

    operations = [
        migrations.AddField(
            model_name='scanner',
            name='os_name',
            field=models.CharField(default=None, max_length=100),
        ),
    ]