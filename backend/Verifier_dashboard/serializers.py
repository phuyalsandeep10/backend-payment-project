from rest_framework import serializers
from deals.serializers import PaymentSerializer, PaymentInvoiceSerializer, PaymentApprovalSerializer,DealSerializer
from deals.models import Deal, Payment, PaymentApproval, PaymentInvoice
from .models import AuditLogs
from authentication.models import User
from organization.models import Organization

class PaymentStatusSerializer(serializers.Serializer):
    
    total_payments = serializers.IntegerField()
    total_successful_payments = serializers.IntegerField()
    total_unsuccess_payments = serializers.IntegerField()
    total_verification_pending_payments = serializers.IntegerField()
    total_revenue = serializers.DecimalField(max_digits=20, decimal_places=2)
    total_refunds = serializers.IntegerField()
    total_refunded_amount = serializers.DecimalField(max_digits=20, decimal_places=2, default=0)
    avg_transactional_value = serializers.DecimalField(max_digits=15, decimal_places=2, default=0.00)
    chart_data = serializers.DictField(child=serializers.ListField(child=serializers.DictField()))
    
    
class VerifierInvoiceSerializer(serializers.Serializer):
    payment_id = serializers.IntegerField()
    invoice_id = serializers.CharField(max_length=50)
    client_name = serializers.CharField(max_length=255)
    deal_name =  serializers.CharField(max_length=255)
    invoice_date = serializers.DateField()
    due_date = serializers.DateField()
    amount = serializers.DecimalField(max_digits=15, decimal_places=2)
    status = serializers.CharField(max_length=50)
    receipt_file = serializers.FileField(required=False)
    invoice_status = serializers.CharField(max_length=50, required=False)
    
    
class VerifierDealSerializer(serializers.ModelSerializer):
    class Meta:
        model = DealSerializer.Meta.model
        fields = DealSerializer.Meta.fields
    
    
class PaymentFailureReasonSerializer(serializers.Serializer):
    insufficient_funds = serializers.IntegerField()
    invalid_card = serializers.IntegerField()
    bank_decline = serializers.IntegerField()
    technical_error = serializers.IntegerField()
    check_bounce = serializers.IntegerField()
    payment_received_but_not_reflected = serializers.IntegerField()
    
    
    
class PaymentMethodSerializer(serializers.Serializer):
    credit_card = serializers.IntegerField()
    bank_transfer = serializers.IntegerField()
    mobile_wallet = serializers.IntegerField()
    cheque = serializers.IntegerField()
    qr_payment = serializers.IntegerField()
    
    
    
class Refund_or_BadDebtSerializer(serializers.Serializer):
    """
    Serializer for refund or bad debt reasons.
    """
    invoice_id = serializers.CharField(max_length=50)
    client = serializers.CharField(max_length=255)
    amount = serializers.DecimalField(max_digits=10, decimal_places=2)
    status = serializers.ChoiceField(choices=[
        ('refunded', 'Refunded'),
        ('bad_debt', 'Bad Debt')
    ])
    reasons = serializers.CharField(max_length=500, required=False, allow_blank=True)
    date = serializers.DateField(required=False)
    
    
class InvoiceStatusSerializer(serializers.Serializer):
    """
    Serializer for invoice status.
    """
    pending_invoices = serializers.FloatField()
    paid_invoices = serializers.FloatField()
    rejected_invoices = serializers.FloatField()
    refunded_invoices = serializers.FloatField()
    bad_debt_invoices = serializers.FloatField()

    
class AuditLogSerializer(serializers.ModelSerializer):
    """
    Serializer for audit logs.
    """ 
    user = serializers.StringRelatedField()
    class Meta:
        model = AuditLogs
        fields = ['action', 'timestamp', 'user', 'details']

class PaymentApprovalSerializer(serializers.ModelSerializer):
    class Meta:
        model = PaymentApproval
        fields = '__all__'