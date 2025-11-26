from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('HuginnWatch.urls')),  # Adjust if your app folder name is different
]
