from django.urls import path
from .import views

urlpatterns = [
    path('webhook/', views.github_webhook, name='github_webhook'),
    path('pullrequests/', views.pull_requests_list, name='pull_requests_list'),
    path('repositories/', views.repositories_list, name='repositories_list'),
    path('points/', views.points_list, name='point_list'),
    


    path('callback/', views.google_callback, name='google_callback'),
    
    path('callback', views.github_callback, name='github_callback'),
    
]
