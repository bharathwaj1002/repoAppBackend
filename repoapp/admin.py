from django.contrib import admin
from .models import *
# Register your models here.
admin.site.register(PullRequest)
admin.site.register(Repositories)
admin.site.register(RegisteredUser)
admin.site.register(Point)