from django.db import models
from django.utils import timezone

class PullRequest(models.Model):
    prId = models.IntegerField(primary_key=True)
    title = models.CharField(max_length=200)
    html_url = models.URLField(max_length=255)
    base_html_url = models.URLField(max_length=255)
    requesterName = models.CharField(max_length=100, blank=True)
    requestedTime = models.DateTimeField(auto_now_add=True)
    mergedTime = models.DateTimeField(auto_now_add=True)
    prStatus = models.CharField(max_length=50, null=True, blank=True)
    repoName = models.CharField(max_length=255, null=True, blank=True)

    def __str__(self):
        return self.title +' by '+self.requesterName
    
class Repositories(models.Model):
    repoName = models.CharField(max_length=255,default='')
    creatorName = models.CharField(max_length=255,default='')
    url = models.URLField(max_length=200)
    def __str__(self):
        return self.repoName
    
class RegisteredUser(models.Model):
    email = models.EmailField(primary_key=True)
    userName = models.CharField(max_length=50,blank=True, null=True)
    
    def __str__(self):
        return self.email
    
class Point(models.Model):
    userName =models.CharField(max_length=50,primary_key=True)
    point = models.IntegerField(default=0)
    
    def __str__(self):
        return self.userName