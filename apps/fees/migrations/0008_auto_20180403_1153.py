# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2018-04-03 11:53
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('fees', '0007_auto_20180403_1149'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='transactionfeerange',
            unique_together=set([('transaction_fee', 'limit', 'value')]),
        ),
    ]
