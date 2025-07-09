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
from commission.views import UserCommissionView
# from deals.views import PaymentVerificationView

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

# API URL patterns matching frontend expectations
api_urlpatterns = [
    # Authentication endpoints (includes /users)
    path('auth/', include('authentication.urls')),
    # Direct endpoints as expected by frontend
    path('users/', include('authentication.user_urls')),  # Original with trailing slash
    path('clients/', include('clients.urls')),
    path('clients', include('clients.urls')),  # No-slash variant for forms without trailing /
    path('deals/', include('deals.urls')),
    path('teams/', include('team.urls')),
    path('commission/', include('commission.urls')),  # Singular to match frontend
    # Admin-only endpoints
    path('organizations/', include('organization.urls')),
    path('permissions/', include('permissions.urls')),
    path('projects/', include('project.urls')),
    # Dashboard endpoints
    # path('dashboard/', include('authentication.dashboard_urls')),  # Original dashboard routes
    # path('notifications/', include('notifications.urls')),  # New notification system
    # path('sales-dashboard/', include('Sales_dashboard.urls')),  # Sales analytics
    # path('verifier/', include('Verifier_dashboard.urls')),  # Verifier dashboard
    # No-slash variants for frontend routes without trailing slash
    path('users', include('authentication.user_urls')),  # No-slash variant for list/detail endpoints
    path('deals', include('deals.urls')),  # No-slash variant
    path('teams', include('team.urls')),  # No-slash variant
    path('commission', include('commission.urls')),  # No-slash variant
    path('organizations', include('organization.urls')),  # No-slash variant
    path('permissions', include('permissions.urls')),  # No-slash variant
    path('projects', include('project.urls')),  # No-slash variant
    # path('dashboard', include('authentication.dashboard_urls')),  # No-slash variant
    # path('notifications', include('notifications.urls')),  # No-slash variant
    # path('sales-dashboard', include('Sales_dashboard.urls')),  # No-slash variant
    # path('verifier', include('Verifier_dashboard.urls')),  # No-slash variant
    path('users/<int:user_id>/commission/', UserCommissionView.as_view(), name='user-commission'),
    path('users/<int:user_id>/commission', UserCommissionView.as_view(), name='user-commission-noslash'),
    # Payment verification (top-level) routes
    # path('payments/<str:payment_id>/verify/', PaymentVerificationView.as_view(), name='payment-verify'),
    # path('payments/<str:payment_id>/verify', PaymentVerificationView.as_view(), name='payment-verify-noslash'),
]

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
