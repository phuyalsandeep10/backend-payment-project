from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import OrganizationViewSet, OrganizationRegistrationView, get_innovate_organization_id, OrganizationWithAdminCreateView, organizations_alias

router = DefaultRouter()
router.register(r'organizations', OrganizationViewSet, basename='organizations')

urlpatterns = [
    # Include router URLs first to ensure ViewSet routes are available
    path('', include(router.urls)),
    
    # Frontend compatibility: allow POST /api/organizations/ to create org + admin
    path('alias/', organizations_alias, name='organizations-alias'),
    path('register/', OrganizationRegistrationView.as_view(), name='organization-register'),
    path('create_with_admin/', OrganizationWithAdminCreateView.as_view(), name='organization-create-with-admin'),
    path('get-innovate-id/', get_innovate_organization_id, name='get-innovate-id'),
] 