from django.db import models
from django.utils import timezone

class PullRequest(models.Model):
    id = models.IntegerField(primary_key=True)
    title = models.CharField(max_length=200)
    html_url = models.URLField(max_length=255)
    base_html_url = models.URLField(max_length=255)
    requester_name = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    total_pull_requests = models.PositiveIntegerField(default=0)
    pr_status = models.CharField(max_length=50, null=True, blank=True)
    repo = models.CharField(max_length=255, null=True, blank=True)

    def __str__(self):
        return self.title