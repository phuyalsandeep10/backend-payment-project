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
        read_only_fields = ['organization', 'converted_amount']

    def create(self, validated_data):
        # Automatically set the organization from the logged-in user's organization
        user = self.context['request'].user
        validated_data['organization'] = user.organization
        return super().create(validated_data)

    def update(self, instance, validated_data):
        # The parent's update will set the new values on the instance
        instance = super().update(instance, validated_data)
        # The instance.save() method, which we overrode in the model, 
        # will then trigger the recalculation before saving.
        instance.save()
        return instance 