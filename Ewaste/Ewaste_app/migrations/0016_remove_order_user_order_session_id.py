# Generated by Django 5.1.4 on 2025-01-12 04:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Ewaste_app', '0015_order_orderitem'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='order',
            name='user',
        ),
        migrations.AddField(
            model_name='order',
            name='session_id',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]
