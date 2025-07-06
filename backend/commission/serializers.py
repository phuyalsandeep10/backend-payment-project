from rest_framework import serializers
from .models import Commission
from authentication.serializers import UserDetailSerializer
from authentication.models import User


class CommissionSerializer(serializers.ModelSerializer):
    """
    Serializer for the Commission model. Handles creation, listing, and updates.
    """
    user = UserDetailSerializer(read_only=True)
    user_id = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(), source='user', write_only=True
    )
    created_by = UserDetailSerializer(read_only=True)
    updated_by = UserDetailSerializer(read_only=True)

    class Meta:
        model = Commission
        fields = [
            'id', 'user', 'user_id', 'organization', 'total_sales',
            'commission_rate', 'converted_amount', 'currency', 'exchange_rate', 'bonus', 'penalty',
            'commission_amount', 'total_commission', 'total_receivable',
            'start_date', 'end_date', 'created_at', 'updated_at',
            'created_by', 'updated_by'
        ]
        read_only_fields = [
            'id', 'organization', 'total_sales', 'commission_amount',
            'total_commission', 'total_receivable', 'created_at', 'updated_at',
            'created_by', 'updated_by', 'user'
        ]

    def create(self, validated_data):
        requesting_user = self.context['request'].user
        validated_data['created_by'] = requesting_user

        # Organization is based on the user for whom the commission is created
        validated_data['organization'] = validated_data['user'].organization

        return super().create(validated_data)

    def update(self, instance, validated_data):
        requesting_user = self.context['request'].user
        validated_data['updated_by'] = requesting_user
        return super().update(instance, validated_data) 