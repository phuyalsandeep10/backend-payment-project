from django.urls import path, include
from .views import (payment_stats,verifier_invoice,verifier_pending, VerifierDealViewSet,PaymentApprovalViewSet,verifier_invoice_delete
                    ,verifier_verified,verifier_rejected,payment_failure_reasons,payment_methods,
                    refunded_invoice,bad_debt_invoice,recent_refund_or_bad_debt,verification_queue,
                    invoice_status_overview,audit_logs,payment_status_distribution,payment_verifier_form)  
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register(r'deals', VerifierDealViewSet, basename='verifier-deal')
router.register(r'payment-approvals', PaymentApprovalViewSet, basename='payment-approval')

app_name = 'verifier_dashboard'
urlpatterns = [
    #main dashboard for verifiers
    # This will be the main entry point for verifiers to access their dashboard
    path('', include(router.urls)), 
    path('dashboard/', payment_stats, name='verifier_dashboard'),
    path('dashboard/invoice-status/',invoice_status_overview, name='invoice-status-overview'),
    path('dashboard/payment-methods/', payment_methods, name='payment-methods'),
    path('dashboard/verification-queue/', verification_queue, name='verification-queue'),
    path('dashboard/payment-status-distribution/',payment_status_distribution, name='payment-status-distribution'),
    path('dashboard/audit-logs/',audit_logs, name='audit-logs'),
    path('dashboard/payment-failure-reasons/', payment_failure_reasons, name='payment-failure-reasons'),
    path('dashboard/recent-refunds-or-bad-debts/', recent_refund_or_bad_debt, name='recent-refund-or-bad-debt-list'),
    path('invoices/', verifier_invoice, name='verifier-invoice-list'),
    path('invoice/<str:invoice_id>/', verifier_invoice_delete, name='verifier-invoice-delete'),
    path('invoices/pending/', verifier_pending, name='verifier-invoice-pending-list'),
    path('invoices/verified/', verifier_verified, name='verifier-invoice-verified-list'),
    path('invoices/rejected/', verifier_rejected, name='verifier-invoice-rejected-list'),
    path('invoices/refunded/', refunded_invoice, name='refunded-invoice-list'),
    path('invoices/bad-debt/',bad_debt_invoice,name='bad-debt-invoice-list'),
    path('verifier-form/<int:payment_id>/', payment_verifier_form, name='verifier-form'),
]
