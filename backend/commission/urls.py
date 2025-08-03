from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import CommissionViewSet, UserCommissionView, OrgAdminCommissionView, CurrencyListView, CountryCodesView, NationalityView

router = DefaultRouter()
router.register(r'commissions', CommissionViewSet, basename='commission')

urlpatterns = [
    # Specific patterns must come BEFORE the router include
    path('commissions/bulk/', CommissionViewSet.as_view({'put': 'bulk_update'}), name='commission-bulk-update'),
    path('commissions/<int:pk>/calculate/', CommissionViewSet.as_view({'post': 'calculate'}), name='commission-calculate'),
    path('commissions/export/<str:format>/', CommissionViewSet.as_view({'get': 'export'}), name='commission-export'),
    path('commissions/export-selected/', CommissionViewSet.as_view({'post': 'export_selected'}), name='commission-export-selected'),
    path('commissions/user/<int:user_id>/', UserCommissionView.as_view(), name='user-commission'),
    path('commissions/org-admin/', OrgAdminCommissionView.as_view(), name='org-admin-commission'),
    path('currencies/', CurrencyListView.as_view(), name='currency-list'),
    path('country-codes/', CountryCodesView.as_view(), name='country-codes-list'),
    path('nationalities/', NationalityView.as_view(), name='nationality-list'),
    # Router include comes last
    path('', include(router.urls)),
] 