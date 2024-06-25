# Generated by Django 4.2.5 on 2024-06-19 14:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('repoapp', '0003_alter_pullrequest_total_pull_requests'),
    ]

    operations = [
        migrations.AddField(
            model_name='pullrequest',
            name='pr_status',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='pullrequest',
            name='repo',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='pullrequest',
            name='total_pull_requests',
            field=models.PositiveIntegerField(default=0),
        ),
    ]
