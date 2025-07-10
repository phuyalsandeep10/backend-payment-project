from rest_framework import serializers
from .models import Commission
from authentication.models import User
from authentication.serializers import UserLiteSerializer


class CommissionSerializer(serializers.ModelSerializer):
    """
    Serializer for the Commission model.
    Handles creation, listing, and updates of commissions.
    The backend automatically calculates total_sales and commission amounts.
    """
    # Use a lightweight serializer for nested user objects for readability
    user = UserLiteSerializer(read_only=True)
    created_by = UserLiteSerializer(read_only=True)
    updated_by = UserLiteSerializer(read_only=True)

    # Use a write-only field to specify the user by ID during creation
    user_id = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(), source='user', write_only=True
    )

    class Meta:
        model = Commission
        fields = [
            'id', 
            # Relational fields
            'user', 'user_id', 'organization', 
            # Input fields
            'start_date', 'end_date', 'commission_rate', 'currency', 
            'exchange_rate', 'bonus', 'penalty',
            # Read-only calculated fields
            'total_sales', 'commission_amount', 
            'total_commission', 'total_receivable',
            # Audit fields
            'created_at', 'updated_at', 'created_by', 'updated_by'
        ]
        read_only_fields = [
            'organization', 
            'total_sales', 'commission_amount', 'total_commission', 'total_receivable',
            'created_at', 'updated_at', 'created_by', 'updated_by', 'user'
        ]

    def create(self, validated_data):
        # Set created_by from the request context
        requesting_user = self.context['request'].user
        validated_data['created_by'] = requesting_user

        # Organization is set based on the user for whom the commission is created
        user = validated_data.get('user')
        if user and hasattr(user, 'organization') and user.organization:
            validated_data['organization'] = user.organization

        return super().create(validated_data)

    def update(self, instance, validated_data):
        # Set updated_by from the request context
        requesting_user = self.context['request'].user
        validated_data['updated_by'] = requesting_user
        return super().update(instance, validated_data) 