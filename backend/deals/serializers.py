from rest_framework import serializers
from .models import Deal, Payment, ActivityLog
from authentication.serializers import UserLiteSerializer

class ActivityLogSerializer(serializers.ModelSerializer):
    """
    Serializer for the ActivityLog model.
    """
    class Meta:
        model = ActivityLog
        fields = ['id', 'message', 'timestamp']

class PaymentSerializer(serializers.ModelSerializer):
    """
    Serializer for the Payment model.
    """
    class Meta:
        model = Payment
        fields = [
            'id', 'deal', 'payment_date', 'receipt_file', 'payment_remarks',
            'received_amount', 'cheque_number', 'payment_type'
        ]
        read_only_fields = ['deal']  # Deal is set automatically from URL

class DealSerializer(serializers.ModelSerializer):
    """
    Serializer for the Deal model.
    """
    created_by = UserLiteSerializer(read_only=True)
    payments = PaymentSerializer(many=True, read_only=True)
    activity_logs = ActivityLogSerializer(many=True, read_only=True)

    class Meta:
        model = Deal
        fields = [
            'id', 'deal_id', 'organization', 'client_name', 'created_by', 'pay_status',
            'source_type', 'deal_value', 'deal_date', 'due_date', 'payment_method',
            'deal_remarks', 'payments', 'activity_logs'
        ]
        read_only_fields = ['organization', 'deal_id']

class DealCreateUpdateSerializer(serializers.ModelSerializer):
    """
    A specific serializer for creating and updating deals to handle writable fields.
    """
    class Meta:
        model = Deal
        fields = [
            'client_name', 'pay_status', 'source_type', 'deal_value',
            'deal_date', 'due_date', 'payment_method', 'deal_remarks'
        ]