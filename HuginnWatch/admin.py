from django.contrib import admin
from .models import Server, ScanResult

admin.site.register(Server)
admin.site.register(ScanResult)
