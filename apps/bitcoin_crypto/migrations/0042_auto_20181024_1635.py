# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2018-10-24 16:35
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('bitcoin_crypto', '0041_auto_20181024_1634'),
    ]

    operations = [
        migrations.RenameField(
            model_name='tradingpair',
            old_name='tradingpairs',
            new_name='tradingpair',
        ),
    ]
