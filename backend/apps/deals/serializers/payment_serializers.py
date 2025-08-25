"""
Payment Serializers - Task 2.4.1

Focused serializers for payment operations, broken down from the massive PaymentSerializer.
Uses reusable components and clean separation of concerns.
"""

from rest_framework import serializers
from decimal import Decimal
from apps.deals.models import Payment
from .base_serializers import (
    DealsBaseSerializer, PaymentStatusMixin, PaymentValidationMixin, 
    FileUploadMixin
)
from core.serializers import MoneyField, DateTimeField
import logging

logger = logging.getLogger(__name__)


class BasePaymentSerializer(DealsBaseSerializer, PaymentStatusMixin, PaymentValidationMixin):
    """
    Base payment serializer with common payment functionality.
    Task 2.4.1: Foundation for all payment serializers.
    """
    
    # Enhanced fields using core library
    received_amount = MoneyField(currency_field='currency')
    payment_date = DateTimeField()
    
    # Status and verification fields
    verified_amount = serializers.SerializerMethodField()
    verified_by = serializers.SerializerMethodField()
    verification_remarks = serializers.SerializerMethodField()
    
    class Meta:
        model = Payment
        fields = [
            'id', 'transaction_id', 'payment_date', 'received_amount',
            'cheque_number', 'payment_type', 'payment_remarks',
            'created_at', 'updated_at', 'status', 'verified_amount',
            'verified_by', 'verification_remarks'
        ]
        read_only_fields = [
            'id', 'transaction_id', 'created_at', 'updated_at',
            'payment_type', 'status', 'verified_amount', 'verified_by',
            'verification_remarks'
        ]
    
    def get_verified_amount(self, obj):
        """Get verified amount from latest approval"""
        try:
            if not obj.pk:
                return None
            
            # Get from latest approval
            try:
                latest_approval = obj.approvals.filter(
                    approval_status='approved'
                ).latest('created_at')
                return latest_approval.verified_amount
            except Exception:
                pass
            
            # Fallback to received amount if approved
            if self.get_status(obj) in ['approved', 'completed']:
                return obj.received_amount
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting verified amount: {e}")
            return None
    
    def get_verified_by(self, obj):
        """Get who verified the payment"""
        try:
            if not obj.pk:
                return None
            
            # Get from latest approval
            try:
                latest_approval = obj.approvals.filter(
                    approval_status='approved'
                ).latest('created_at')
                
                if latest_approval.approved_by:
                    return {
                        'id': latest_approval.approved_by.id,
                        'name': latest_approval.approved_by.get_full_name(),
                        'email': latest_approval.approved_by.email
                    }
            except Exception:
                pass
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting verified by: {e}")
            return None
    
    def get_verification_remarks(self, obj):
        """Get verification remarks"""
        try:
            if not obj.pk:
                return None
            
            # Get from latest approval
            try:
                latest_approval = obj.approvals.latest('created_at')
                return latest_approval.approval_remarks
            except Exception:
                pass
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting verification remarks: {e}")
            return None


class PaymentSerializer(BasePaymentSerializer, FileUploadMixin):
    """
    Full payment serializer for CRUD operations.
    Task 2.4.1: Simplified from original 276-line monster.
    """
    
    # Deal reference handling
    deal = serializers.PrimaryKeyRelatedField(read_only=True)
    deal_id = serializers.CharField(write_only=True)
    
    # Frontend compatibility
    payment_method = serializers.CharField(source='payment_type', read_only=True)
    payment_category = serializers.CharField(write_only=True, required=False)
    
    class Meta(BasePaymentSerializer.Meta):
        fields = BasePaymentSerializer.Meta.fields + [
            'deal', 'deal_id', 'payment_method', 'payment_category',
            'receipt_file', 'version'
        ]
    
    def validate(self, attrs):
        """Enhanced validation with business rules"""
        attrs = super().validate(attrs)
        
        # Validate deal relationship
        self._validate_deal_relationship(attrs)
        
        # Validate payment category
        self._validate_payment_category(attrs)
        
        return attrs
    
    def _validate_deal_relationship(self, attrs):
        """Validate deal relationship and permissions"""
        deal_id = attrs.get('deal_id')
        if not deal_id:
            if not self.instance:  # Create operation must have deal_id
                raise serializers.ValidationError({
                    'deal_id': 'Deal ID is required for new payments.'
                })
            return
        
        # Validate deal exists and user has access
        try:
            from apps.deals.models import Deal
            deal = Deal.objects.get(deal_id=deal_id)
            
            # Check organization access
            request = self.context.get('request')
            if request and request.user and hasattr(request.user, 'organization'):
                if deal.organization != request.user.organization:
                    raise serializers.ValidationError({
                        'deal_id': 'You cannot add payments to deals from other organizations.'
                    })
            
            attrs['deal'] = deal
            
        except Deal.DoesNotExist:
            raise serializers.ValidationError({
                'deal_id': f'Deal with ID "{deal_id}" does not exist.'
            })
    
    def _validate_payment_category(self, attrs):
        """Validate payment category based on payment type"""
        payment_category = attrs.get('payment_category')
        if payment_category:
            # Determine payment type based on category
            payment_type_mapping = {
                'cash': 'cash',
                'bank_transfer': 'online',
                'cheque': 'cheque',
                'credit_card': 'online',
                'debit_card': 'online'
            }
            
            payment_type = payment_type_mapping.get(payment_category, 'other')
            attrs['payment_type'] = payment_type
    
    def create(self, validated_data):
        """Create payment with proper setup"""
        try:
            # Remove write-only fields that shouldn't be saved
            validated_data.pop('deal_id', None)
            validated_data.pop('payment_category', None)
            
            # Create payment
            payment = super().create(validated_data)
            
            # Auto-generate transaction ID if not provided
            if not payment.transaction_id:
                payment.transaction_id = self._generate_transaction_id(payment)
                payment.save(update_fields=['transaction_id'])
            
            return payment
            
        except Exception as e:
            logger.error(f"Error creating payment: {e}")
            raise serializers.ValidationError("Failed to create payment. Please try again.")
    
    def _generate_transaction_id(self, payment):
        """Generate unique transaction ID"""
        from datetime import datetime
        import uuid
        
        prefix = f"PAY_{payment.deal.deal_id}_{datetime.now().strftime('%Y%m%d')}"
        suffix = str(uuid.uuid4())[:8].upper()
        return f"{prefix}_{suffix}"


class NestedPaymentSerializer(serializers.ModelSerializer):
    """
    Simplified payment serializer for nested use in DealSerializer.
    Task 2.4.1: Focused on essential fields only.
    """
    
    # Simplified fields for nested use - make them not required for nested creation
    payment_date = serializers.DateField(required=True)
    received_amount = serializers.DecimalField(max_digits=15, decimal_places=2, required=True)
    cheque_number = serializers.CharField(required=False, allow_blank=True)
    payment_method = serializers.CharField(source='payment_type', required=False)
    payment_remarks = serializers.CharField(required=False, allow_blank=True)
    receipt_file = serializers.FileField(required=False)
    
    class Meta:
        model = Payment
        fields = [
            'id', 'payment_date', 'received_amount', 'cheque_number',
            'payment_method', 'payment_remarks', 'receipt_file', 'status'
        ]
    
    def validate(self, attrs):
        """Debug validation for nested payment"""
        logger.info(f"NestedPaymentSerializer.validate called with attrs: {attrs}")
        validated_attrs = super().validate(attrs)
        logger.info(f"NestedPaymentSerializer.validate returning: {validated_attrs}")
        return validated_attrs
    
    def validate_cheque_number(self, value):
        """Simplified cheque validation for nested serializer"""
        if not value:
            return value
        
        cleaned_value = str(value).strip()
        
        if len(cleaned_value) < 6 or len(cleaned_value) > 20:
            raise serializers.ValidationError(
                "Cheque number must be between 6 and 20 characters."
            )
        
        return cleaned_value


class PaymentDetailSerializer(PaymentSerializer):
    """
    Detailed payment serializer with enhanced information.
    Task 2.4.1: Extended view for payment details.
    """
    
    deal_info = serializers.SerializerMethodField()
    approval_history = serializers.SerializerMethodField()
    
    class Meta(PaymentSerializer.Meta):
        fields = PaymentSerializer.Meta.fields + [
            'deal_info', 'approval_history'
        ]
    
    def get_deal_info(self, obj):
        """Get basic deal information"""
        try:
            if obj.deal:
                return {
                    'deal_id': obj.deal.deal_id,
                    'deal_name': obj.deal.deal_name,
                    'client_name': obj.deal.client.client_name if obj.deal.client else None,
                    'deal_value': str(obj.deal.deal_value)
                }
        except Exception as e:
            logger.error(f"Error getting deal info: {e}")
        
        return None
    
    def get_approval_history(self, obj):
        """Get payment approval history"""
        try:
            if not obj.pk:
                return []
            
            approvals = obj.approvals.select_related('approved_by').order_by('-created_at')
            return [
                {
                    'id': approval.id,
                    'status': approval.approval_status,
                    'verified_amount': str(approval.verified_amount) if approval.verified_amount else None,
                    'remarks': approval.approval_remarks,
                    'approved_by': approval.approved_by.get_full_name() if approval.approved_by else None,
                    'approved_at': approval.created_at
                }
                for approval in approvals[:5]  # Last 5 approvals
            ]
            
        except Exception as e:
            logger.error(f"Error getting approval history: {e}")
            return []


class PaymentUpdateSerializer(BasePaymentSerializer):
    """
    Focused serializer for payment updates.
    Task 2.4.1: Simplified update operations.
    """
    
    class Meta:
        model = Payment
        fields = [
            'payment_date', 'received_amount', 'cheque_number',
            'payment_remarks', 'receipt_file'
        ]
    
    def validate(self, attrs):
        """Validate update permissions and data"""
        attrs = super().validate(attrs)
        
        # Check if payment can be updated
        if self.instance:
            status = self.get_status(self.instance)
            if status in ['approved', 'completed']:
                raise serializers.ValidationError(
                    "Cannot update payment that has been approved or completed."
                )
        
        return attrs


class PaymentListSerializer(BasePaymentSerializer):
    """
    Lightweight serializer for payment listings.
    Task 2.4.1: Optimized for list views.
    """
    
    deal_id = serializers.CharField(source='deal.deal_id', read_only=True)
    client_name = serializers.CharField(source='deal.client.client_name', read_only=True)
    
    class Meta:
        model = Payment
        fields = [
            'id', 'transaction_id', 'deal_id', 'client_name',
            'payment_date', 'received_amount', 'payment_type',
            'status', 'created_at'
        ]
