from rest_framework import serializers
from clients.models import Client
from .models import Payment
from authentication.models import User
from datetime import timedelta
from django.utils import timezone

class PaymentSimpleSerializer(serializers.ModelSerializer):
    """Simple payment serializer for nested display in deals"""
    payment_date = serializers.DateTimeField(source='created_at')
    received_amount = serializers.DecimalField(source='amount', max_digits=12, decimal_places=2)
    payment_remarks = serializers.CharField(allow_null=True, default="")
    cheque_number = serializers.SerializerMethodField()
    verified_by = serializers.SerializerMethodField()
    verification_remarks = serializers.CharField(allow_null=True, default="")
    receipt_file = serializers.URLField(allow_null=True)
    version = serializers.SerializerMethodField()
    
    class Meta:
        model = Payment
        fields = [
            'id', 'payment_date', 'receipt_file', 'payment_remarks', 
            'received_amount', 'cheque_number', 'payment_method', 'status',
            'verified_by', 'verification_remarks', 'version'
        ]
    
    def get_version(self, obj):
        """Return version 1 for all payments"""
        return 1
    
    def get_cheque_number(self, obj):
        """Generate a cheque number based on payment info"""
        return f"CHQ-{obj.client.id}-{obj.sequence_number}"
    
    def get_verified_by(self, obj):
        if obj.verified_by:
            return {
                'id': str(obj.verified_by.id),
                'full_name': f"{obj.verified_by.first_name} {obj.verified_by.last_name}".strip() or obj.verified_by.username,
                'email': obj.verified_by.email
            }
        return None

class DealSerializer(serializers.ModelSerializer):
    """
    Enhanced serializer mapping Client fields to Deal-like structure expected by the
    frontend. Includes all fields that the DealsTable component expects.
    """
    # Basic client info mapped to deal fields
    name = serializers.CharField(source='client_name')
    deal_name = serializers.SerializerMethodField()
    client_name = serializers.CharField()
    deal_value = serializers.DecimalField(source='value', max_digits=12, decimal_places=2)
    deal_date = serializers.DateTimeField(source='created_at')
    due_date = serializers.SerializerMethodField()
    deal_remarks = serializers.CharField(source='remarks', allow_null=True)
    
    # Payment status and related info
    pay_status = serializers.SerializerMethodField()
    payments = PaymentSimpleSerializer(many=True, read_only=True)
    
    # Organization and user info
    organization = serializers.SerializerMethodField()
    created_by = serializers.SerializerMethodField()
    
    # Deal metadata
    deal_id = serializers.SerializerMethodField()
    source_type = serializers.CharField(default="direct")
    version = serializers.IntegerField(default=1)
    activity_logs = serializers.ListField(child=serializers.DictField(), default=list)

    class Meta:
        model = Client
        fields = [
            # Original client fields
            'id', 'name', 'email', 'value', 'status', 'satisfaction', 'created_at', 'updated_at',
            # Deal-specific fields for frontend compatibility
            'deal_id', 'organization', 'client_name', 'deal_name', 'created_by', 'pay_status',
            'source_type', 'deal_value', 'deal_date', 'due_date', 'deal_remarks', 'payments',
            'activity_logs', 'version'
        ]
        read_only_fields = fields

    def get_deal_name(self, obj):
        """Generate a deal name based on client name and value"""
        return f"{obj.client_name} - Deal (${obj.value:,.0f})"
    
    def get_deal_id(self, obj):
        """Generate a deal ID"""
        return f"DL-{obj.id:04d}"
    
    def get_organization(self, obj):
        """Get organization name"""
        return obj.organization.name if obj.organization else "Unknown"
    
    def get_created_by(self, obj):
        """Get salesperson info"""
        if obj.salesperson:
            return {
                'id': str(obj.salesperson.id),
                'full_name': f"{obj.salesperson.first_name} {obj.salesperson.last_name}".strip() or obj.salesperson.username,
                'email': obj.salesperson.email
            }
        elif obj.created_by:
            return {
                'id': str(obj.created_by.id),
                'full_name': f"{obj.created_by.first_name} {obj.created_by.last_name}".strip() or obj.created_by.username,
                'email': obj.created_by.email
            }
        return {
            'id': 'unknown',
            'full_name': 'Unknown User',
            'email': 'unknown@example.com'
        }
    
    def get_pay_status(self, obj):
        """Calculate payment status based on payments vs deal value"""
        payments = obj.payments.filter(status='verified')
        if not payments.exists():
            return 'partial_payment'
        
        total_paid = sum(payment.amount for payment in payments)
        if total_paid >= obj.value:
            return 'full_payment'
        return 'partial_payment'
    
    def get_due_date(self, obj):
        """Calculate due date (30 days from creation by default)"""
        return obj.created_at + timedelta(days=30)

# ==================== PAYMENT SERIALIZER ====================

class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = [
            'id',
            'client',
            'sequence_number',
            'amount',
            'currency',
            'payment_method',
            'receipt_file',
            'status',
            'verified_at',
            'verified_by',
            'created_at',
            'updated_at',
        ]
        read_only_fields = ['status', 'verified_at', 'verified_by', 'created_at', 'updated_at'] 