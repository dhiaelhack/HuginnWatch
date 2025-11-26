from rest_framework import serializers
from .models import Server, ScanResult

class ServerSerializer(serializers.ModelSerializer):
    latest_scan = serializers.SerializerMethodField()

    class Meta:
        model = Server
        fields = ['id', 'ip_address', 'latest_scan']

    def get_latest_scan(self, obj):
        latest = obj.scanresult_set.order_by('-timestamp').first()
        return latest.result if latest else "No scan result yet."
