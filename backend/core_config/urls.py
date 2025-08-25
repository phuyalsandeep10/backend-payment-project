"""
URL configuration for backend project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from drf_yasg.generators import OpenAPISchemaGenerator
from django.conf import settings
from django.conf.urls.static import static
from django.http import JsonResponse

def health(request):
    return JsonResponse({"status": "ok"})

def root_view(request):
    """Root view for the API"""
    return JsonResponse({
        "message": "PRS Backend API",
        "version": "1.0",
        "endpoints": {
            "swagger": "/swagger/",
            "redoc": "/redoc/", 
            "api": "/api/",
            "admin": "/admin/",
            "health": "/api/health/"
        }
    })

def api_root_view(request):
    """API root view showing available endpoints"""
    return JsonResponse({
        "message": "PRS Backend API Root",
        "version": "1.0",
        "available_endpoints": {
            "clients": "/api/clients/",
            "deals": "/api/deals/",
            "commission": "/api/commission/",
            "organizations": "/api/organizations/",
            "team": "/api/team/",
            "project": "/api/project/",
            "permissions": "/api/permissions/",
            "notifications": "/api/notifications/",
            "dashboard": "/api/dashboard/",
            "verifier": "/api/verifier/",
            "auth": "/api/auth/"
        }
    })

from .enhanced_swagger_config import (
    get_enhanced_swagger_info, 
    get_security_schemes,
    EnhancedAutoSchema,
    EnhancedFieldInspector
)

# Create the schema view with proper configuration
schema_view = get_schema_view(
    get_enhanced_swagger_info(),
    public=True,
    permission_classes=(permissions.AllowAny,),
    authentication_classes=[],  # Remove authentication for schema view
)

# API URL patterns for business logic
api_urlpatterns = [
    # API Root
    path('', api_root_view, name='api-root'),
    
    # Core Business Logic
    path('clients/', include('apps.clients.urls')),
    path('deals/', include('apps.deals.urls')),
    path('commission/', include('apps.commission.urls')),
    path('organizations/', include('apps.organization.urls')),
    
    # Team & Project Management  
    path('team/', include('apps.team.urls')),
    path('project/', include('apps.project.urls')),
    
    # System Management
    path('permissions/', include('apps.permissions.urls')),
    path('notifications/', include('apps.notifications.urls')),
    
    # Background Task Processing & File Upload
    path('background-tasks/', include('core.performance.background_tasks.background_task_urls')),
    path('file-upload/', include('core.security.enhanced_file_upload_urls')),
    
    # Security Management
    path('quarantine/', include('core.security.quarantine_urls')),
    
    # Monitoring & Alerting
    path('monitoring/', include('core.monitoring.urls')),
    path('alerting/', include('core.monitoring.alerting_urls')),
    path('response-monitoring/', include('core.monitoring.response_monitoring_urls')),
    
    # Analytics & Dashboard
    path('dashboard/', include('apps.Sales_dashboard.urls')),
    path('verifier/', include('apps.Verifier_dashboard.urls')),
]

urlpatterns = [
    # Root endpoint
    path('', root_view, name='root'),
    
    path('admin/', admin.site.urls),
    
    # Authentication endpoints
    path('api/auth/', include('apps.authentication.urls', namespace='authentication')),
    
    # Main API endpoints
    path('api/', include((api_urlpatterns, 'api'))),
    # path('api/v1/', include((api_urlpatterns, 'api-v1'))),

    # API documentation
    path('swagger<format>/', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    path('docs/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-docs'),
    path('api/health/', health, name='health'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
