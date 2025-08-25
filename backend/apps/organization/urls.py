from django.urls import path, include
from rest_framework.routers import DefaultRouter
from apps.organization.views import OrganizationViewSet, OrganizationRegistrationView, get_innovate_organization_id, OrganizationWithAdminCreateView, organizations_alias
from django.views.decorators.csrf import csrf_exempt

# Create a custom router with CSRF exemption
class CSRFExemptRouter(DefaultRouter):
    def get_urls(self):
        urls = super().get_urls()
        # Apply CSRF exemption to all router URLs
        exempt_urls = []
        for url in urls:
            if url.callback:
                url.callback = csrf_exempt(url.callback)
            exempt_urls.append(url)
        return exempt_urls

router = CSRFExemptRouter()
router.register(r'', OrganizationViewSet, basename='organization')

urlpatterns = [
    path('register/', csrf_exempt(OrganizationRegistrationView.as_view()), name='organization-register'),
    path('create_with_admin/', csrf_exempt(OrganizationWithAdminCreateView.as_view()), name='organization-create-with-admin'),
    path('get-innovate-id/', get_innovate_organization_id, name='get-innovate-id'),
    path('alias/', organizations_alias, name='organizations-alias'),  # Add explicit alias endpoint
    path('', include(router.urls)),
] 