# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2018-02-22 11:06
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0004_user_google_2fa_key'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='change_password_date',
            field=models.DateField(blank=True, default=None, null=True),
        ),
    ]
