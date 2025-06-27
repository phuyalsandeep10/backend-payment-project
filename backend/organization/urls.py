from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import OrganizationViewSet, OrgAdminViewSet, OrganizationRegistrationView

router = DefaultRouter()
router.register(r'organizations', OrganizationViewSet)
router.register(r'admins', OrgAdminViewSet, basename='org-admin')

urlpatterns = [
    path('', include(router.urls)),
    path('register-organization/', OrganizationRegistrationView.as_view(), name='register-organization'),
] 