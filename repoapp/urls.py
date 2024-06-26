from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('',include('repoapp.urls')),
    path('github/',include('repoapp.urls'))
]
