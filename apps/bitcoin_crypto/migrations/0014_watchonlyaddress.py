# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2018-03-20 09:40
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('bitcoin_crypto', '0013_vaulttransaction_date'),
    ]

    operations = [
        migrations.CreateModel(
            name='WatchOnlyAddress',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('address', models.CharField(max_length=200)),
            ],
        ),
    ]
