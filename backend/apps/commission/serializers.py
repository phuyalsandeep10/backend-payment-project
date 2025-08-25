from rest_framework import serializers
from django.db import models
from .models import Commission
from apps.authentication.models import User
from apps.authentication.serializers import UserLiteSerializer


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
    
    # Frontend compatibility fields
    percentage = serializers.DecimalField(
        source='commission_rate', 
        max_digits=5, 
        decimal_places=2, 
        required=False
    )
    rate = serializers.DecimalField(
        source='exchange_rate', 
        max_digits=10, 
        decimal_places=2, 
        required=False
    )
    totalSales = serializers.DecimalField(
        source='total_sales', 
        max_digits=15, 
        decimal_places=2, 
        required=False
    )
    
    # Performance and audit fields
    calculation_accuracy = serializers.SerializerMethodField()
    last_reconciled = serializers.SerializerMethodField()
    performance_metrics = serializers.SerializerMethodField()

    class Meta:
        model = Commission
        fields = [
            'id', 
            # Relational fields
            'user', 'user_id', 'organization', 
            # Input fields
            'start_date', 'end_date', 'commission_rate', 'currency', 
            'exchange_rate', 'bonus', 'penalty',
            # Frontend compatibility fields
            'percentage', 'rate', 'totalSales',
            # Read-only calculated fields
            'total_sales', 'commission_amount', 
            'total_commission', 'total_receivable',
            # Audit fields
            'created_at', 'updated_at', 'created_by', 'updated_by',
            # Performance and audit fields
            'calculation_accuracy', 'last_reconciled', 'performance_metrics'
        ]
        read_only_fields = [
            'organization', 
            'total_sales', 'commission_amount', 'total_commission', 'total_receivable',
            'created_at', 'updated_at', 'created_by', 'updated_by', 'user',
            'calculation_accuracy', 'last_reconciled', 'performance_metrics'
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
        
        # Set current user for audit logging
        instance.set_current_user(requesting_user)
        
        return super().update(instance, validated_data)
    
    def get_calculation_accuracy(self, obj):
        """Check if commission calculation matches actual sales data"""
        try:
            from apps.deals.models import Deal
            from decimal import Decimal
            
            # Get actual verified sales for the period
            actual_sales = Deal.objects.filter(
                created_by=obj.user,
                organization=obj.organization,
                verification_status='verified',
                deal_date__gte=obj.start_date,
                deal_date__lte=obj.end_date
            ).aggregate(total=models.Sum('deal_value'))['total'] or Decimal('0.00')
            
            # Calculate accuracy percentage
            if obj.total_sales > 0:
                accuracy = min(100.0, (float(actual_sales) / float(obj.total_sales)) * 100)
            else:
                accuracy = 100.0 if actual_sales == 0 else 0.0
            
            return {
                'accuracy_percentage': round(accuracy, 2),
                'recorded_sales': float(obj.total_sales),
                'actual_sales': float(actual_sales),
                'discrepancy': float(abs(actual_sales - obj.total_sales))
            }
        except Exception:
            return None
    
    def get_last_reconciled(self, obj):
        """Get the last reconciliation timestamp"""
        try:
            from core_config.models import AuditTrail
            
            last_audit = AuditTrail.objects.filter(
                table_name='commission_commission',
                record_id=str(obj.id),
                action='CALCULATE'
            ).order_by('-timestamp').first()
            
            if last_audit:
                return last_audit.timestamp.isoformat()
            return obj.updated_at.isoformat()
        except Exception:
            return obj.updated_at.isoformat()
    
    def get_performance_metrics(self, obj):
        """Get performance metrics for this commission"""
        try:
            from apps.deals.models import Deal
            from django.db.models import Count, Avg
            
            # Get deal metrics for the period
            deal_metrics = Deal.objects.filter(
                created_by=obj.user,
                organization=obj.organization,
                verification_status='verified',
                deal_date__gte=obj.start_date,
                deal_date__lte=obj.end_date
            ).aggregate(
                deal_count=Count('id'),
                avg_deal_value=Avg('deal_value')
            )
            
            return {
                'deal_count': deal_metrics['deal_count'] or 0,
                'avg_deal_value': float(deal_metrics['avg_deal_value'] or 0),
                'commission_per_deal': float(obj.commission_amount / deal_metrics['deal_count']) if deal_metrics['deal_count'] else 0,
                'effective_commission_rate': float((obj.commission_amount / obj.total_sales) * 100) if obj.total_sales > 0 else 0
            }
        except Exception:
            return None 