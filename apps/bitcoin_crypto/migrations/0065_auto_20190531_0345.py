# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2019-05-31 03:45
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('bitcoin_crypto', '0064_disputeupload'),
    ]

    operations = [
        migrations.AddField(
            model_name='disputeupload',
            name='user_email',
            field=models.CharField(blank=True, default='', max_length=50),
        ),
        migrations.AddField(
            model_name='disputeupload',
            name='user_phonenumber',
            field=models.CharField(blank=True, default='', max_length=20),
        ),
    ]
