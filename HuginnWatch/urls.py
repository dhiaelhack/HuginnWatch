from django.urls import path
from . import views
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

urlpatterns = [
    # Auth
    path('api/v1/signup/', views.api_signup, name='api_signup'),
    path('api/v1/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/v1/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # Servers
    path('api/v1/servers/', views.api_list_servers, name='api_list_servers'),
    path('api/v1/servers/add/', views.api_add_server, name='api_add_server'),
    path('api/v1/servers/delete/', views.api_delete_servers, name='api_delete_servers'),

    # Scan
    path('api/v1/servers/<int:server_id>/scan/', views.api_trigger_scan, name='api_trigger_scan'),

    # AI
    path('api/v1/servers/<int:server_id>/ai/analyze/', views.api_ai_analyze_scan, name='api_ai_analyze_scan'),
]
