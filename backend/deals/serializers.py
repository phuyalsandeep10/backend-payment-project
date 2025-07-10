from rest_framework import serializers
from .models import Deal, Payment, ActivityLog, PaymentInvoice, PaymentApproval
from authentication.serializers import UserLiteSerializer
from clients.serializers import ClientLiteSerializer
from clients.models import Client

class ActivityLogSerializer(serializers.ModelSerializer):
    """
    Serializer for the ActivityLog model.
    """
    class Meta:
        model = ActivityLog
        fields = '__all__'

class PaymentSerializer(serializers.ModelSerializer):
    """
    Serializer for the Payment model.
    """
    deal_id = serializers.CharField(source='deal.deal_id')
    class Meta:
        model = Payment
        fields = [
            'id', 'deal','deal_id', 'payment_date', 'receipt_file', 'payment_remarks',
            'received_amount', 'cheque_number', 'payment_type'
        ]
        read_only_fields = ['deal']

    def create(self, validated_data):
        deal_info = validated_data.pop('deal', {})
        deal_id = deal_info.get('deal_id')
        
        if not deal_id:
            raise serializers.ValidationError("deal_id is required.")

        request = self.context.get('request')
        if not request or not hasattr(request, 'user'):
             raise serializers.ValidationError("Request context is missing or user is not available.")

        organization = request.user.organization
        if not organization:
            raise serializers.ValidationError("User is not associated with an organization.")

        try:
            deal = Deal.objects.get(deal_id=deal_id, organization=organization)
        except Deal.DoesNotExist:
            raise serializers.ValidationError(f"Deal with deal_id {deal_id} not found in your organization.")
        
        payment = Payment.objects.create(deal=deal, **validated_data)
        return payment

class DealSerializer(serializers.ModelSerializer):
    """
    Serializer for the Deal model, used for both read and write operations.
    """
    created_by = UserLiteSerializer(read_only=True)
    updated_by = UserLiteSerializer(read_only=True)
    client = ClientLiteSerializer(read_only=True)
    client_id = serializers.PrimaryKeyRelatedField(
        queryset=Client.objects.all(), source='client', write_only=True
    )
    payments = PaymentSerializer(many=True, read_only=True)
    activity_logs = ActivityLogSerializer(many=True, read_only=True)

    class Meta:
        model = Deal
        fields = [
            'id', 'deal_id', 'organization', 'client', 'client_id', 'created_by', 
            'updated_by', 'payment_status', 'verification_status', 'client_status', 'source_type', 
            'deal_value', 'deal_date', 'due_date', 'payment_method', 'deal_remarks', 
            'payments', 'activity_logs', 'version', 'deal_name', 'currency', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'organization', 'deal_id', 'created_by', 'updated_by'
        ]

class DealPaymentHistorySerializer(serializers.ModelSerializer):
    """
    A serializer to represent a single payment record for the deal's expanded history view.
    """
    payment_serial = serializers.SerializerMethodField()
    payment_value = serializers.DecimalField(source='received_amount', max_digits=15, decimal_places=2)
    receipt_link = serializers.FileField(source='receipt_file', read_only=True)

    class Meta:
        model = Payment
        fields = [
            'payment_serial', 'payment_date', 'created_at', 'payment_value',
            'receipt_link'
        ]

    def get_payment_serial(self, obj):
        # The serial number is passed via context from the parent serializer
        return self.context.get('serial_number', 0)

class DealExpandedViewSerializer(serializers.ModelSerializer):
    """
    A serializer for the expanded deal view, providing detailed verification and payment history.
    """
    payment_history = serializers.SerializerMethodField()
    verified_by = serializers.CharField(source='updated_by.get_full_name', default=None, read_only=True)
    verifier_remark_status = serializers.SerializerMethodField()
    payment_version = serializers.CharField(source='version', read_only=True)

    class Meta:
        model = Deal
        fields = [
            'payment_history', 'verified_by', 'deal_remarks',
            'verifier_remark_status', 'payment_version','verification_status'
        ]

    def get_payment_history(self, obj):
        payments = obj.payments.all().order_by('created_at')
        # Pass the serial number to the child serializer via context
        return [
            DealPaymentHistorySerializer(p, context={'serial_number': i + 1}).data
            for i, p in enumerate(payments)
        ]

    def get_verifier_remark_status(self, obj):
        return "yes" if obj.verification_status == 'verified' else "no"

class DealUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Deal
        fields = [
            'id',
            'deal_id',
            'organization',
            'client',
            'project',
            'deal_name',
            'deal_value',
            'currency',
            'deal_date',
            'due_date',
            'payment_status',
            'payment_method',
            'source_type',
            'verification_status',
            'version',
            'created_by',
            'updated_by',
            'created_at',
            'updated_at',
        ]

class PaymentInvoiceSerializer(serializers.ModelSerializer):
    client_name = serializers.CharField(source='payment.deal.client.client_name', read_only=True)
    payment_amount = serializers.DecimalField(source='payment.received_amount', max_digits=15, decimal_places=2, read_only=True)

    
    class Meta:
        model = PaymentInvoice
        fields =        fields = [
            'id', 'payment', 'payment_amount','client_name',
            'invoice_id', 'invoice_date', 'due_date',
            'invoice_status', 'deal', 'receipt_file'
        ]

class PaymentApprovalSerializer(serializers.ModelSerializer):
    client_name = serializers.CharField(source='payment.invoice.deal.client.client_name', read_only=True)
    deal_id = serializers.CharField(source='payment.invoice.deal.deal_id', read_only=True)
    invoice_status = serializers.CharField(source='payment.invoice.invoice_status')
    payment_amount = serializers.DecimalField(source='payment.received_amount', max_digits=15, decimal_places=2, read_only=True)
    invoice_file = serializers.FileField(required=False, allow_null=True)
    invoice_id = serializers.CharField(source = 'payment.invoice.invoice_id', read_only=True)
    transaction_id = serializers.CharField(source='payment.transaction_id', read_only=True)
    
    class Meta:
        model = PaymentApproval
       
        fields = [
            'id',
            'payment_id',
            'deal',
            'deal_id',
            'client_name',
            'invoice_id',
            'invoice_status',
            'payment_amount',
            'invoice_file',
            'approved_by',
            'approval_date',
            'verifier_remarks',
            'failure_remarks',
            'amount_in_invoice',
            'transaction_id',
        ]
        
        read_only_fields = [
            'deal',
            'deal_id',
            'client_name',
            'invoice_status',
            'payment',
            'payment_amount',
            'approval_date',
            'approved_by',
        ]