# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2018-05-24 11:47
from __future__ import unicode_literals

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0032_bankaccount_bank_name'),
    ]

    operations = [
        migrations.CreateModel(
            name='ComplaintsAndRequest',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('subject', models.CharField(max_length=255)),
                ('descrption', models.CharField(max_length=1000)),
                ('is_fixed', models.BooleanField(default=False)),
                ('fixed_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='get_admin_fixed_complaints', to=settings.AUTH_USER_MODEL)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='get_the_user_requests', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
