from rest_framework import serializers
from .models import Deal, Payment, ActivityLog
from authentication.serializers import UserLiteSerializer
from clients.serializers import ClientLiteSerializer
from clients.models import Client

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
        read_only_fields = ['deal']

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
            'payments', 'activity_logs'
        ]
        read_only_fields = [
            'organization', 'deal_id', 'created_by', 'updated_by'
        ]