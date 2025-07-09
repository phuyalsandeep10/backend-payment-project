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
from django.conf import settings
from django.conf.urls.static import static

schema_view = get_schema_view(
    openapi.Info(
        title="Payment Receiving System API",
        default_version='v1',
        description="API documentation for the PRS project.",
        contact=openapi.Contact(email="contact@prs.local"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
    authentication_classes=[],  # Remove authentication for schema view
)

# API URL patterns matching frontend expectations
api_urlpatterns = [
    # Authentication & User Management
    path('auth/', include('authentication.urls')),
    path('organizations/', include('organization.urls')),
    
    # Core Business Logic
    path('clients/', include('clients.urls')),  # Includes nested deals
    path('deals/', include('deals.urls')),      # Standalone deals access
    path('commission/', include('commission.urls')),
    
    # Team & Project Management  
    path('teams/', include('team.urls')),
    path('projects/', include('project.urls')),
    
    # System Management
    path('permissions/', include('permissions.urls')),
    path('notifications/', include('notifications.urls')),
    
    # Analytics & Dashboard
    path('dashboard/', include('Sales_dashboard.urls')),
    path('verifier/', include('Verifier_dashboard.urls')),
]

# All endpoints are now organized through app-specific URL includes

urlpatterns = [
    path('admin/', admin.site.urls),
    # Direct /api/ routes to match frontend expectations
    path('api/', include(api_urlpatterns)),
    # Keep v1 for backward compatibility if needed
    path('api/v1/', include(api_urlpatterns)),

    # API documentation
    path('swagger<format>/', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
