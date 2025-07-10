from django.urls import path, include
from .views import (payment_stats,verifier_invoice, VerifierDealViewSet,PaymentApprovalViewSet,verifier_invoice_delete
                    ,payment_failure_reasons,payment_methods,recent_refund_or_bad_debt,verification_queue,
                    invoice_status_overview,audit_logs,payment_status_distribution,payment_verifier_form,
                    payments_view)  
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register(r'deals', VerifierDealViewSet, basename='verifier-deal')
router.register(r'payment-approvals', PaymentApprovalViewSet, basename='payment-approval')

app_name = 'verifier_dashboard'

urlpatterns = [
    # ==================== ROUTER ENDPOINTS ====================
    path('', include(router.urls)), 
    
    # ==================== DASHBOARD ENDPOINTS ====================
    path('dashboard/', payment_stats, name='verifier_dashboard'),
    path('dashboard/invoice-status/', invoice_status_overview, name='invoice-status-overview'),
    path('dashboard/payment-methods/', payment_methods, name='payment-methods'),
    path('dashboard/verification-queue/', verification_queue, name='verification-queue'),
    path('dashboard/payment-status-distribution/', payment_status_distribution, name='payment-status-distribution'),
    path('dashboard/audit-logs/', audit_logs, name='audit-logs'),
    path('dashboard/payment-failure-reasons/', payment_failure_reasons, name='payment-failure-reasons'),
    path('dashboard/recent-refunds-or-bad-debts/', recent_refund_or_bad_debt, name='recent-refund-or-bad-debt-list'),
    
    # ==================== INVOICE MANAGEMENT ====================
    path('invoices/', verifier_invoice, name='verifier-invoice-list'),
    path('invoice/<str:invoice_id>/', verifier_invoice_delete, name='verifier-invoice-delete'),
    path('verifier-form/<int:payment_id>/', payment_verifier_form, name='verifier-form'),

    # ==================== FRONTEND COMPATIBILITY ALIASES ====================
    path('overview/', payment_stats, name='overview'),
    path('payments/', payments_view, name='payments-list'),
    path('refunds/', recent_refund_or_bad_debt, name='refunds'),
    path('audits/', audit_logs, name='audits'),
    path('payment-distribution/', payment_status_distribution, name='payment-distribution'),
]
