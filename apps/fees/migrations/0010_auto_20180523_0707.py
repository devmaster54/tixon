# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2018-05-23 07:07
from __future__ import unicode_literals

import apps.fees.models
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('fees', '0009_auto_20180404_1401'),
    ]

    operations = [
        migrations.AlterField(
            model_name='miningfees',
            name='mining_fees',
            field=models.CharField(default='0.00', max_length=200, validators=[apps.fees.models.validate_decimal]),
        ),
    ]