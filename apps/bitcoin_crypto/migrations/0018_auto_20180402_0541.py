# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2018-04-02 05:41
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('bitcoin_crypto', '0017_auto_20180326_1357'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='orderbook',
            unique_together=set([]),
        ),
    ]
