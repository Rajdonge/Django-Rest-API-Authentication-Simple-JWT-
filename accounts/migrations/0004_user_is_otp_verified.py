# Generated by Django 5.2 on 2025-04-12 09:06

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0003_alter_user_middle_name'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='is_otp_verified',
            field=models.BooleanField(default=False),
        ),
    ]
