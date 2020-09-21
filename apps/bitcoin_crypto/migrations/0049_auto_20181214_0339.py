# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2018-12-14 03:39
from __future__ import unicode_literals

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('bitcoin_crypto', '0048_auto_20181214_0332'),
    ]

    operations = [
        migrations.AlterField(
            model_name='confirmfiattransaction',
            name='receiver',
            field=models.CharField(max_length=128),
        ),
        migrations.AlterField(
            model_name='confirmfiattransaction',
            name='sender',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
    ]
