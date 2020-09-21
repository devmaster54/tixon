# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2019-06-11 13:59
from __future__ import unicode_literals

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('bitcoin_crypto', '0067_disputeupload_dispute_status'),
    ]

    operations = [
        migrations.CreateModel(
            name='PendingOrder',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('pending_amount', models.FloatField()),
                ('order_time', models.DateTimeField(auto_now_add=True)),
                ('order', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='bitcoin_crypto.OrderBook')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='pending_order_user', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
