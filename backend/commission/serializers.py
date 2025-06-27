from rest_framework import serializers
from .models import Commission

class CommissionSerializer(serializers.ModelSerializer):
    """
    Serializer for the Commission model. Handles creation and updates.
    """
    class Meta:
        model = Commission
        fields = [
            'id', 'user', 'organization', 'total_sales', 
            'commission_percentage', 'converted_amount',
            'start_date', 'end_date', 'created_at', 'updated_at'
        ]
        read_only_fields = ['converted_amount']

    def create(self, validated_data):
        user = self.context['request'].user
        # Super Admins can create commissions for any organization
        if user.is_superuser:
            # For super admins, organization should be in validated_data
            if 'organization' not in validated_data:
                raise serializers.ValidationError({'organization': 'This field is required for super admins.'})
        else:
            # For other users, automatically set their organization
            validated_data['organization'] = user.organization
        return super().create(validated_data)

    def update(self, instance, validated_data):
        # The parent's update will set the new values on the instance
        instance = super().update(instance, validated_data)
        # The instance.save() method, which we overrode in the model, 
        # will then trigger the recalculation before saving.
        instance.save()
        return instance 