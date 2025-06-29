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
from organization.views import OrganizationRegistrationView
from deals.views import DealViewSet
from rest_framework.routers import DefaultRouter

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
)

# Centralized API URL patterns
api_urlpatterns = [
    path('auth/', include('authentication.urls')),
    path('register/', OrganizationRegistrationView.as_view(), name='register-organization'),
    path('organizations/', include('organization.urls')),
    path('permissions/', include('permissions.urls')),
    path('commissions/', include('commission.urls')),
    path('projects/', include('project.urls')),
    path('teams/', include('team.urls')),
    path('clients/', include('clients.urls')),
]

router = DefaultRouter()
# The 'deals' router is now nested under 'clients' and should not be registered here directly
# router.register(r'deals', DealViewSet, basename='deal')

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/v1/', include(api_urlpatterns)),

    # API documentation
    path('swagger<format>/', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]
