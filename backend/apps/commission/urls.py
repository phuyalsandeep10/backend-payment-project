from django.urls import path, include
from rest_framework.routers import DefaultRouter
from apps.commission.views import CommissionViewSet, UserCommissionView, OrgAdminCommissionView, CurrencyListView, NationalityView, CountryCodesView

router = DefaultRouter()
router.register(r'commissions', CommissionViewSet, basename='commission')

urlpatterns = [
    # Specific patterns must come BEFORE the router include
    path('commissions/bulk/', CommissionViewSet.as_view({'put': 'bulk_update'}), name='commission-bulk-update'),
    path('commissions/<int:pk>/calculate/', CommissionViewSet.as_view({'post': 'calculate'}), name='commission-calculate'),
    path('commissions/export/<str:format>/', CommissionViewSet.as_view({'get': 'export'}), name='commission-export'),
    path('commissions/export-selected/', CommissionViewSet.as_view({'post': 'export_selected'}), name='commission-export-selected'),
    
    # Optimization endpoints
    path('commissions/bulk-calculate/', CommissionViewSet.as_view({'post': 'bulk_calculate'}), name='commission-bulk-calculate'),
    path('commissions/reconciliation/', CommissionViewSet.as_view({'get': 'reconciliation'}), name='commission-reconciliation'),
    path('commissions/fix-discrepancies/', CommissionViewSet.as_view({'post': 'fix_discrepancies'}), name='commission-fix-discrepancies'),
    path('commissions/analytics/', CommissionViewSet.as_view({'get': 'analytics'}), name='commission-analytics'),
    path('commissions/<int:pk>/audit-history/', CommissionViewSet.as_view({'get': 'audit_history'}), name='commission-audit-history'),
    path('commissions/invalidate-cache/', CommissionViewSet.as_view({'post': 'invalidate_cache'}), name='commission-invalidate-cache'),
    
    path('commissions/user/<int:user_id>/', UserCommissionView.as_view(), name='user-commission'),
    path('commissions/org-admin/', OrgAdminCommissionView.as_view(), name='org-admin-commission'),
    path('currencies/', CurrencyListView.as_view(), name='currency-list'),
    path('nationalities/', NationalityView.as_view(), name='nationality-list'),
    path('country-codes/', CountryCodesView.as_view(), name='country-codes'),
    # Router include comes last
    path('', include(router.urls)),
] 