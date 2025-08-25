"""
Deal Serializers - Task 2.4.1

Focused serializers for deal operations, broken down from the massive DealSerializer.
Uses composition patterns and service-oriented approach.
"""

from rest_framework import serializers
from decimal import Decimal
from django.core.exceptions import ValidationError
from django.db import transaction
from apps.deals.models import Deal
from .base_serializers import (
    DealsBaseSerializer, DealStatusMixin, DealValidationMixin,
    CalculatedFieldsMixin
)
from .payment_serializers import NestedPaymentSerializer
from core.serializers import MoneyField, DateTimeField, NestedSerializerMixin, CompositeValidationMixin
from apps.authentication.serializers import UserLiteSerializer
from apps.clients.serializers import ClientLiteSerializer
from apps.clients.models import Client
import logging

logger = logging.getLogger(__name__)


class BaseDealSerializer(DealsBaseSerializer, DealStatusMixin, DealValidationMixin):
    """
    Base deal serializer with common functionality.
    Task 2.4.1: Foundation for all deal serializers.
    """
    
    # Enhanced fields using core library
    deal_value = MoneyField(currency_field='currency')
    deal_date = serializers.DateField()
    due_date = serializers.DateField()
    
    # Related object references
    created_by = UserLiteSerializer(read_only=True)
    updated_by = UserLiteSerializer(read_only=True)
    client = ClientLiteSerializer(read_only=True)
    
    # Frontend compatibility
    client_name = serializers.CharField(source='client.client_name', read_only=True)
    pay_status = serializers.CharField(source='payment_status', read_only=True)
    
    class Meta:
        model = Deal
        fields = [
            'id', 'deal_id', 'organization', 'client', 'client_name',
            'created_by', 'updated_by', 'deal_name', 'deal_value',
            'deal_date', 'due_date', 'payment_status', 'pay_status',
            'verification_status', 'payment_method', 'deal_remarks',
            'currency', 'source_type', 'version', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'deal_id', 'organization', 'client', 'client_name',
            'created_by', 'updated_by', 'verification_status', 
            'pay_status', 'created_at', 'updated_at'
        ]


class DealSerializer(BaseDealSerializer, CalculatedFieldsMixin, 
                    NestedSerializerMixin, CompositeValidationMixin):
    """
    Main deal serializer for CRUD operations.
    Task 2.4.1: Simplified from original 302-line monster using composition patterns.
    """
    
    # Client relationship handling
    client_id = serializers.PrimaryKeyRelatedField(
        queryset=Client.objects.all(), 
        source='client', 
        write_only=True
    )
    
    # Nested payments handling
    payments = NestedPaymentSerializer(many=True, required=False, write_only=True)
    payments_read = serializers.SerializerMethodField()
    
    # Activity logging
    activity_logs = serializers.SerializerMethodField()
    
    # Calculated fields - explicitly defined for schema generation
    total_paid = serializers.SerializerMethodField()
    remaining_balance = serializers.SerializerMethodField()
    payment_progress = serializers.SerializerMethodField()
    
    # Enhanced nested serializer configuration
    nested_serializers = {
        'payments': NestedPaymentSerializer
    }
    nested_write_fields = ['payments']
    composite_validators = ['validate_amount_consistency', 'validate_date_range']
    
    class Meta(BaseDealSerializer.Meta):
        fields = BaseDealSerializer.Meta.fields + [
            'client_id', 'payments', 'payments_read', 'activity_logs',
            'total_paid', 'remaining_balance', 'payment_progress'
        ]
    
    def __init__(self, *args, **kwargs):
        """Enhanced initialization with FormData parsing"""
        super().__init__(*args, **kwargs)
        
        # Handle FormData parsing for nested payment fields only if not already parsed
        if hasattr(self, 'initial_data') and self.initial_data:
            logger.info(f"DealSerializer.__init__ - initial_data type: {type(self.initial_data)}")
            logger.info(f"DealSerializer.__init__ - initial_data keys: {list(self.initial_data.keys()) if hasattr(self.initial_data, 'keys') else 'No keys method'}")
            
            # Only parse if payments key doesn't exist but FormData payment keys do
            if ('payments' not in self.initial_data and 
                hasattr(self.initial_data, 'keys') and 
                any(key.startswith('payments[') for key in self.initial_data.keys())):
                self._parse_formdata_payments()
    
    def to_internal_value(self, data):
        """Override to handle FormData parsing before validation"""
        # Only parse FormData if payments are not already parsed and FormData keys exist
        if (hasattr(data, 'keys') and 
            any(key.startswith('payments[') for key in data.keys()) and 
            'payments' not in data):
            
            # Create a mutable copy of the data
            if hasattr(data, '_mutable'):
                data._mutable = True
            
            # Parse the FormData
            self._parse_formdata_from_data(data)
        
        return super().to_internal_value(data)
    
    def _parse_formdata_from_data(self, data):
        """Parse FormData from data parameter"""
        try:
            # Extract payment fields from FormData
            payment_data = []
            payment_indices = set()
            
            # Find all payment field indices
            for key in data.keys():
                if key.startswith('payments[') and '][' in key:
                    try:
                        index = int(key.split('[')[1].split(']')[0])
                        payment_indices.add(index)
                    except (ValueError, IndexError):
                        continue
            
            # Group fields by payment index
            for index in payment_indices:
                payment_item = {}
                prefix = f'payments[{index}]'
                
                for key in data.keys():
                    if key.startswith(prefix):
                        field_name = key.replace(f'{prefix}[', '').replace(']', '')
                        
                        # Get the actual value
                        if hasattr(data, 'get'):
                            actual_value = data.get(key)
                        else:
                            actual_value = data[key]
                        
                        if field_name and actual_value is not None:
                            if actual_value == '' and field_name in ['cheque_number', 'payment_remarks']:
                                payment_item[field_name] = None
                            else:
                                payment_item[field_name] = actual_value
                
                if payment_item:
                    payment_data.append(payment_item)
            
            if payment_data:
                # Set the payments data
                if hasattr(data, 'setlist'):
                    data.setlist('payments', payment_data)
                else:
                    data['payments'] = payment_data
                
                logger.info(f"Parsed payments in to_internal_value: {payment_data}")
                
        except Exception as e:
            logger.error(f"Error parsing FormData in to_internal_value: {e}", exc_info=True)
    
    def _parse_formdata_payments(self):
        """Parse FormData with nested payment fields"""
        try:
            if not isinstance(self.initial_data, dict):
                return
            
            # Debug: Log the initial data keys
            logger.info(f"Initial data keys: {list(self.initial_data.keys())}")
            
            # Extract payment fields from FormData
            payment_data = []
            payment_indices = set()
            
            # Find all payment field indices - handle both formats
            for key in self.initial_data.keys():
                if key.startswith('payments[') and '][' in key:
                    try:
                        # Extract index from payments[0][field_name] format
                        index = int(key.split('[')[1].split(']')[0])
                        payment_indices.add(index)
                    except (ValueError, IndexError):
                        continue
            
            logger.info(f"Found payment indices: {payment_indices}")
            
            # Group fields by payment index
            for index in payment_indices:
                payment_item = {}
                prefix = f'payments[{index}]'
                
                for key, value in self.initial_data.items():
                    if key.startswith(prefix):
                        # Extract field name from payments[0][field_name] format
                        field_name = key.replace(f'{prefix}[', '').replace(']', '')
                        
                        # Handle QueryDict values (which are lists) vs regular dict values
                        if hasattr(self.initial_data, 'getlist'):
                            # This is a QueryDict, get the first value
                            actual_value = self.initial_data.get(key)
                        else:
                            # This is a regular dict
                            actual_value = value
                        
                        # Handle empty values properly
                        if field_name and actual_value is not None:
                            # Convert empty strings to None for optional fields
                            if actual_value == '' and field_name in ['cheque_number', 'payment_remarks']:
                                payment_item[field_name] = None
                            else:
                                payment_item[field_name] = actual_value
                
                if payment_item:
                    payment_data.append(payment_item)
                    logger.info(f"Payment item {index}: {payment_item}")
            
            if payment_data:
                # Convert to mutable dict if needed
                if hasattr(self.initial_data, '_mutable'):
                    self.initial_data._mutable = True
                
                # For QueryDict, we need to set the value properly
                if hasattr(self.initial_data, 'setlist'):
                    # QueryDict needs the list to be set properly
                    self.initial_data.setlist('payments', payment_data)
                else:
                    # Regular dict
                    self.initial_data['payments'] = payment_data
                
                logger.info(f"Final payments data: {payment_data}")
            else:
                logger.warning("No payment data found in FormData")
                
        except Exception as e:
            logger.error(f"Error parsing FormData payments: {e}", exc_info=True)
    
    def get_payments_read(self, obj):
        """Get payments for read operations"""
        try:
            if not obj.pk:
                return []
            
            payments = obj.payments.select_related('deal').order_by('-created_at')
            return NestedPaymentSerializer(payments, many=True, context=self.context).data
            
        except Exception as e:
            logger.error(f"Error getting payments: {e}")
            return []
    
    def get_activity_logs(self, obj):
        """Get activity logs"""
        try:
            if not obj.pk:
                return []
            
            # Get recent activity logs
            logs = obj.activity_logs.select_related('user').order_by('-created_at')[:10]
            
            return [
                {
                    'id': log.id,
                    'action': log.action,
                    'description': log.description,
                    'user': log.user.get_full_name() if log.user else 'System',
                    'created_at': log.created_at
                }
                for log in logs
            ]
            
        except Exception as e:
            logger.error(f"Error getting activity logs: {e}")
            return []
    
    def validate(self, attrs):
        """Enhanced validation with business rules"""
        logger.info(f"DealSerializer.validate called with attrs: {attrs}")
        
        attrs = super().validate(attrs)
        
        # Deal-specific validation
        self._validate_client_relationship(attrs)
        self._validate_payment_consistency(attrs)
        
        logger.info(f"DealSerializer.validate returning attrs: {attrs}")
        return attrs
    
    def _validate_client_relationship(self, attrs):
        """Validate client relationship and permissions"""
        client = attrs.get('client')
        if client:
            # Check organization access
            request = self.context.get('request')
            if request and request.user and hasattr(request.user, 'organization'):
                if client.organization != request.user.organization:
                    raise serializers.ValidationError({
                        'client_id': 'You cannot create deals for clients from other organizations.'
                    })
    
    def _validate_payment_consistency(self, attrs):
        """Validate payment data consistency"""
        payments = attrs.get('payments', [])
        deal_value = attrs.get('deal_value')
        
        if payments and deal_value:
            total_payments = sum(
                Decimal(str(payment.get('received_amount', 0))) 
                for payment in payments
            )
            
            if total_payments > deal_value:
                raise serializers.ValidationError({
                    'payments': 'Total payment amount cannot exceed deal value.'
                })
    
    def validate_amount_consistency(self, attrs):
        """Composite validator for amount consistency"""
        deal_value = attrs.get('deal_value')
        payments = attrs.get('payments', [])
        
        if deal_value and payments:
            total_payments = sum(
                Decimal(str(p.get('received_amount', 0))) for p in payments
            )
            
            if total_payments > deal_value:
                raise serializers.ValidationError(
                    "Total payment amount cannot exceed deal value."
                )
        
        return attrs
    
    def validate_date_range(self, attrs):
        """Composite validator for date range"""
        deal_date = attrs.get('deal_date')
        due_date = attrs.get('due_date')
        
        if deal_date and due_date:
            # Convert to date objects if needed
            if hasattr(deal_date, 'date'):
                deal_date = deal_date.date()
            if hasattr(due_date, 'date'):
                due_date = due_date.date()
            
            if deal_date > due_date:
                raise serializers.ValidationError(
                    "Due date must be after deal date."
                )
        
        return attrs
    
    @transaction.atomic
    def create(self, validated_data):
        """Create deal with nested payments and proper setup"""
        try:
            # Extract nested data
            payments_data = validated_data.pop('payments', [])
            
            # Set organization and created_by
            request = self.context.get('request')
            if request and request.user:
                validated_data['created_by'] = request.user
                if hasattr(request.user, 'organization') and request.user.organization:
                    validated_data['organization'] = request.user.organization
            
            # Create deal
            deal = super().create(validated_data)
            
            # Auto-generate deal_id if not provided
            if not deal.deal_id:
                deal.deal_id = self._generate_deal_id(deal)
                deal.save(update_fields=['deal_id'])
            
            # Create nested payments
            self._create_payments(deal, payments_data)
            
            # Log activity
            self._log_deal_activity(deal, 'created', 'Deal created successfully')
            
            return deal
            
        except ValidationError as e:
            logger.error(f"Validation error creating deal: {e}")
            # Extract the actual validation error message
            if hasattr(e, 'message_dict'):
                error_messages = []
                for field, messages in e.message_dict.items():
                    if isinstance(messages, list):
                        error_messages.extend(messages)
                    else:
                        error_messages.append(str(messages))
                raise serializers.ValidationError(error_messages[0] if error_messages else str(e))
            elif hasattr(e, 'messages'):
                raise serializers.ValidationError(e.messages[0] if e.messages else str(e))
            else:
                raise serializers.ValidationError(str(e))
        except Exception as e:
            logger.error(f"Error creating deal: {e}")
            raise serializers.ValidationError("Failed to create deal. Please try again.")
    
    def update(self, instance, validated_data):
        """Update deal with change tracking"""
        try:
            # Extract nested data
            payments_data = validated_data.pop('payments', [])
            
            # Track changes
            old_values = {
                'deal_value': instance.deal_value,
                'deal_name': instance.deal_name,
                'payment_status': instance.payment_status
            }
            
            # Set updated_by
            request = self.context.get('request')
            if request and request.user:
                validated_data['updated_by'] = request.user
            
            # Update deal
            deal = super().update(instance, validated_data)
            
            # Update nested payments if provided
            if payments_data:
                self._update_payments(deal, payments_data)
            
            # Log significant changes
            self._log_deal_changes(deal, old_values, validated_data)
            
            return deal
            
        except Exception as e:
            logger.error(f"Error updating deal: {e}")
            raise serializers.ValidationError("Failed to update deal. Please try again.")
    
    def _generate_deal_id(self, deal):
        """Generate unique deal ID"""
        from datetime import datetime
        import uuid
        
        org_prefix = deal.organization.name[:3].upper() if deal.organization else 'DEL'
        date_part = datetime.now().strftime('%Y%m%d')
        unique_part = str(uuid.uuid4())[:8].upper()
        
        return f"{org_prefix}_{date_part}_{unique_part}"
    
    def _create_payments(self, deal, payments_data):
        """Create payments for the deal"""
        from apps.deals.models import Payment
        
        for payment_data in payments_data:
            payment_data['deal'] = deal
            payment_data['payment_type'] = payment_data.get('payment_method', 'other')
            
            # Create payment
            Payment.objects.create(**payment_data)
    
    def _update_payments(self, deal, payments_data):
        """Update payments for the deal"""
        # This is a simplified update - in a full implementation,
        # you might want more sophisticated payment update logic
        existing_payment_ids = set(deal.payments.values_list('id', flat=True))
        updated_payment_ids = set()
        
        for payment_data in payments_data:
            payment_id = payment_data.get('id')
            if payment_id and payment_id in existing_payment_ids:
                # Update existing payment
                payment = deal.payments.get(id=payment_id)
                for field, value in payment_data.items():
                    if field != 'id' and hasattr(payment, field):
                        setattr(payment, field, value)
                payment.save()
                updated_payment_ids.add(payment_id)
    
    def _log_deal_activity(self, deal, action, description):
        """Log deal activity"""
        try:
            from apps.deals.models import ActivityLog
            
            request = self.context.get('request')
            user = request.user if request else None
            
            ActivityLog.objects.create(
                deal=deal,
                user=user,
                action=action,
                description=description
            )
            
        except Exception as e:
            logger.error(f"Error logging deal activity: {e}")
    
    def _log_deal_changes(self, deal, old_values, new_values):
        """Log significant deal changes"""
        changes = []
        
        for field, old_value in old_values.items():
            new_value = new_values.get(field)
            if new_value and new_value != old_value:
                changes.append(f"{field}: {old_value} -> {new_value}")
        
        if changes:
            description = f"Deal updated: {', '.join(changes)}"
            self._log_deal_activity(deal, 'updated', description)


class DealListSerializer(BaseDealSerializer, CalculatedFieldsMixin):
    """
    Lightweight serializer for deal listings.
    Task 2.4.1: Optimized for list views.
    """
    
    payment_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Deal
        fields = [
            'id', 'deal_id', 'client_name', 'deal_name', 'deal_value',
            'deal_date', 'payment_status', 'verification_status',
            'total_paid', 'remaining_balance', 'payment_progress',
            'payment_count', 'created_at'
        ]
    
    def get_payment_count(self, obj):
        """Get payment count"""
        try:
            return obj.payments.count()
        except Exception:
            return 0


class DealUpdateSerializer(BaseDealSerializer):
    """
    Focused serializer for deal updates.
    Task 2.4.1: Simplified update operations.
    """
    
    class Meta:
        model = Deal
        fields = [
            'deal_name', 'deal_value', 'deal_date', 'due_date',
            'payment_method', 'deal_remarks', 'source_type'
        ]


class SalespersonDealSerializer(DealSerializer):
    """
    Extended deal serializer for salesperson dashboard.
    Task 2.4.1: Inherits full functionality with additional fields.
    """
    
    commission_info = serializers.SerializerMethodField()
    
    class Meta(DealSerializer.Meta):
        fields = DealSerializer.Meta.fields + ['commission_info']
    
    def get_commission_info(self, obj):
        """Get commission information for salesperson"""
        try:
            # This would integrate with commission calculations
            return {
                'estimated_commission': 0,
                'commission_rate': 0,
                'commission_status': 'pending'
            }
        except Exception:
            return None
