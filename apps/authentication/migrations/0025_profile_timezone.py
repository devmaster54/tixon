# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2018-05-07 09:29
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0024_auto_20180502_1506'),
    ]

    operations = [
        migrations.AddField(
            model_name='profile',
            name='timezone',
            field=models.CharField(default='UTC', max_length=200),
            preserve_default=False,
        ),
    ]
