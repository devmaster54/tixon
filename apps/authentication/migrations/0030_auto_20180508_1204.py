# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2018-05-08 12:04
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0029_auto_20180508_1158'),
    ]

    operations = [
        migrations.RenameField(
            model_name='bankaccount',
            old_name='swif_number',
            new_name='swift_number',
        ),
    ]
