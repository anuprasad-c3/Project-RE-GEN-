# Generated by Django 5.1.4 on 2025-01-01 05:11

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Ewaste_app', '0007_delete_product'),
    ]

    operations = [
        migrations.CreateModel(
            name='Product',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('description', models.CharField(max_length=100)),
                ('price', models.IntegerField(default=100)),
                ('category', models.CharField(max_length=100)),
                ('image', models.CharField(max_length=100)),
            ],
        ),
    ]
