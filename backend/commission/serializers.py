from rest_framework import serializers
from .models import Commission

class CommissionSerializer(serializers.ModelSerializer):
    """
    Serializer for the Commission model to match frontend expectations.
    """
    fullName = serializers.ReadOnlyField(source='full_name')
    totalSales = serializers.DecimalField(source='total_sales', max_digits=12, decimal_places=2)
    convertedAmt = serializers.ReadOnlyField(source='converted_amt')
    totalReceivable = serializers.ReadOnlyField(source='total_receivable')

    class Meta:
        model = Commission
        fields = [
            'id', 'fullName', 'totalSales', 'currency', 'rate', 'percentage', 
            'bonus', 'penalty', 'convertedAmt', 'total', 'totalReceivable',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['organization']

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['createdAt'] = instance.created_at.isoformat()
        representation['updatedAt'] = instance.updated_at.isoformat()
        return representation

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