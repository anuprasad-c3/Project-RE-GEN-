# Generated by Django 5.1.4 on 2025-02-22 03:10

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Ewaste_app', '0025_delete_otpverification2'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='email_verification_token',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='is_email_verified',
            field=models.BooleanField(default=False),
        ),
    ]
