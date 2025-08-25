from rest_framework import serializers
from apps.deals.serializers import PaymentSerializer, PaymentInvoiceSerializer, PaymentApprovalSerializer,DealSerializer
from apps.deals.models import Deal, Payment, PaymentApproval, PaymentInvoice
from .models import AuditLogs
from apps.authentication.models import User
from apps.organization.models import Organization

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
    
    
class VerifierInvoiceSerializer(serializers.ModelSerializer):
    payment_id = serializers.IntegerField(source='payment.id')
    client_name = serializers.CharField(source='deal.client.client_name', read_only=True)
    deal_name = serializers.CharField(source='deal.deal_name', read_only=True)
    amount = serializers.DecimalField(source='payment.received_amount', max_digits=15, decimal_places=2, read_only=True)
    status = serializers.CharField(source='invoice_status', read_only=True)
    
    class Meta:
        model = PaymentInvoice
        fields = [
            'payment_id', 'invoice_id', 'client_name', 'deal_name',
            'invoice_date', 'due_date', 'amount', 'status', 'receipt_file', 'invoice_status'
        ]
        read_only_fields = ['payment_id', 'invoice_id', 'client_name', 'deal_name', 'amount', 'status']
    
    
class VerifierDealSerializer(serializers.ModelSerializer):
    client_name = serializers.CharField(source='client.client_name', read_only=True)
    pay_status = serializers.CharField(source='payment_status', read_only=True)
    payments_read = serializers.SerializerMethodField()
    
    class Meta:
        model = Deal
        fields = [
            'id', 'deal_id', 'organization', 'client', 'created_by', 
            'updated_by', 'payment_status', 'verification_status', 'client_status', 'source_type', 
            'deal_value', 'deal_date', 'due_date', 'payment_method', 'deal_remarks', 
            'version', 'deal_name', 'currency', 'created_at', 'updated_at',
            # Aliases
            'client_name', 'pay_status',
            # Payment details
            'payments_read'
        ]
        read_only_fields = [
            'id', 'deal_id', 'organization', 'created_by', 'updated_by', 
            'payment_status', 'verification_status', 'client_status', 'created_at', 'updated_at',
            'client_name', 'pay_status', 'payments_read'
        ]
    
    def get_payments_read(self, obj):
        from apps.deals.serializers import PaymentSerializer
        return PaymentSerializer(obj.payments.all(), many=True).data
    
    
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
    pending_invoices = serializers.DecimalField(max_digits=15, decimal_places=2)
    paid_invoices = serializers.DecimalField(max_digits=15, decimal_places=2)
    rejected_invoices = serializers.DecimalField(max_digits=15, decimal_places=2)
    refunded_invoices = serializers.DecimalField(max_digits=15, decimal_places=2)
    bad_debt_invoices = serializers.DecimalField(max_digits=15, decimal_places=2)

    
class AuditLogSerializer(serializers.ModelSerializer):
    """
    Serializer for audit logs.
    """ 
    user = serializers.StringRelatedField()
    class Meta:
        model = AuditLogs
        fields = ['action', 'timestamp', 'user', 'details']

class PaymentApprovalSerializer(serializers.ModelSerializer):
    payment = serializers.PrimaryKeyRelatedField(read_only=True)
    class Meta:
        model = PaymentApproval
        fields = '__all__'