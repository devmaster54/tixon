# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2018-12-14 14:28
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('bitcoin_crypto', '0050_confirmfiattransaction_crypt_amount'),
    ]

    operations = [
        migrations.RenameField(
            model_name='confirmfiattransaction',
            old_name='crypt_amount',
            new_name='crypto_amount',
        ),
    ]
