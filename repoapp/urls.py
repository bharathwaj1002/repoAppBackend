from django.urls import path
from .import views

urlpatterns = [
    path('webhook/github/', views.github_webhook, name='github_webhook'),
    path('pullrequests/', views.pull_requests_list, name='pull_requests_list'),
    path('repositories/', views.repositories_list, name='repositories_list'),
    
    path('callback', views.github_callback, name='github_callback'),
    
]
