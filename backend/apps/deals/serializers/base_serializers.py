"""
Base Deals Serializers - Task 2.4.1

Foundation serializers for deals app using the reusable core serializer library.
Reduces code duplication and provides consistent patterns.
"""

from core.serializers import (
    BaseModelSerializer, TimestampMixin, UserTrackingMixin, 
    OrganizationFilterMixin
)
from core.serializers import MoneyField, StatusChoiceField, FileField
from core.serializers import DecimalValidationMixin, DateValidationMixin, FileValidationMixin
from rest_framework import serializers
from decimal import Decimal
import logging

logger = logging.getLogger(__name__)


class DealsBaseSerializer(BaseModelSerializer, TimestampMixin, UserTrackingMixin, OrganizationFilterMixin):
    """
    Base serializer for all deals-related models.
    Task 2.4.1: Foundation using reusable components.
    """
    
    def _validate_business_rules(self, attrs):
        """Deals-specific business rule validation"""
        super()._validate_business_rules(attrs)
        
        # Add deals-specific validation
        self._validate_organization_access(attrs)
        
    def _validate_organization_access(self, attrs):
        """Ensure user can access organization-related data"""
        request = self.context.get('request')
        if request and request.user and hasattr(request.user, 'organization'):
            # Add organization-specific validation logic here
            pass


class PaymentStatusMixin:
    """
    Mixin for payment status handling.
    Task 2.4.1: Specialized status logic for payments.
    """
    
    PAYMENT_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('verified', 'Verified'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('completed', 'Completed')
    ]
    
    status = serializers.SerializerMethodField()
    status_display = serializers.SerializerMethodField()
    can_change_status = serializers.SerializerMethodField()
    
    def get_status(self, obj):
        """Get payment status from related models"""
        try:
            # Check if payment has been saved to database yet
            if not obj.pk:
                return 'pending'
            
            # Get status from invoice if available
            if hasattr(obj, 'invoice') and obj.invoice:
                return obj.invoice.invoice_status
            
            # Get status from latest approval
            try:
                latest_approval = obj.approvals.latest('created_at')
                return latest_approval.approval_status
            except Exception:
                pass
            
            # Default status based on verification
            if hasattr(obj, 'verified_amount') and obj.verified_amount:
                return 'verified'
            
            return 'pending'
            
        except Exception as e:
            logger.error(f"Error getting payment status: {e}")
            return 'pending'
    
    def _check_status_change_permission(self, user, obj) -> bool:
        """Check if user can change payment status"""
        if not user or not user.is_authenticated:
            return False
        
        # Superuser can change any status
        if user.is_superuser:
            return True
        
        # Check role-based permissions
        if hasattr(user, 'role') and user.role:
            role_name = user.role.name.lower()
            
            # Verifiers can change verification status
            if 'verifier' in role_name:
                return True
            
            # Organization admins can change statuses within their org
            if 'admin' in role_name and hasattr(obj, 'deal'):
                return user.organization == obj.deal.organization
        
        return False


class DealStatusMixin:
    """
    Mixin for deal status handling.
    Task 2.4.1: Specialized status logic for deals.
    """
    
    DEAL_STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('pending', 'Pending'),
        ('verified', 'Verified'),
        ('approved', 'Approved'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled')
    ]
    
    payment_status = StatusChoiceField(
        choices=DEAL_STATUS_CHOICES,
        display_map={
            'pending': 'Pending Verification',
            'verified': 'Verified',
            'approved': 'Approved',
            'completed': 'Payment Complete'
        }
    )
    
    verification_status = StatusChoiceField(
        choices=[
            ('unverified', 'Unverified'),
            ('verified', 'Verified'),
            ('rejected', 'Rejected')
        ]
    )
    
    def _check_status_change_permission(self, user, obj) -> bool:
        """Check if user can change deal status"""
        if not user or not user.is_authenticated:
            return False
        
        # Superuser can change any status
        if user.is_superuser:
            return True
        
        # Check role-based permissions
        if hasattr(user, 'role') and user.role:
            role_name = user.role.name.lower()
            
            # Salesperson can modify their own deals
            if 'salesperson' in role_name:
                return hasattr(obj, 'created_by') and obj.created_by == user
            
            # Verifiers can change verification status
            if 'verifier' in role_name:
                return True
            
            # Organization admins can change deals in their org
            if 'admin' in role_name:
                return user.organization == obj.organization
        
        return False


class PaymentValidationMixin(DecimalValidationMixin, DateValidationMixin):
    """
    Mixin for payment-specific validation.
    Task 2.4.1: Centralized payment validation logic.
    """
    
    def validate_received_amount(self, value):
        """Validate payment amount"""
        validated_amount = self._validate_decimal_field(
            value, 'received_amount', 
            min_value=Decimal('0.01')
        )
        
        # Additional business rules for payment amounts
        if validated_amount and validated_amount > Decimal('10000000'):  # 10 million
            raise serializers.ValidationError(
                "Payment amount exceeds maximum allowed limit."
            )
        
        return validated_amount
    
    def validate_cheque_number(self, value):
        """Validate cheque number format and uniqueness"""
        if not value:
            return value
        
        # Clean cheque number
        cleaned_value = str(value).strip()
        
        # Basic format validation
        if len(cleaned_value) < 6 or len(cleaned_value) > 20:
            raise serializers.ValidationError(
                "Cheque number must be between 6 and 20 characters."
            )
        
        # Check for uniqueness if this is a create operation
        if not self.instance:
            from apps.deals.models import Payment
            existing_payment = Payment.objects.filter(
                cheque_number=cleaned_value
            ).first()
            
            if existing_payment:
                raise serializers.ValidationError(
                    f"Payment with cheque number '{cleaned_value}' already exists."
                )
        
        return cleaned_value
    
    def validate_payment_date(self, value):
        """Validate payment date"""
        return self._validate_date_field(value, 'payment_date', allow_future=False)


class DealValidationMixin(DecimalValidationMixin, DateValidationMixin):
    """
    Mixin for deal-specific validation.
    Task 2.4.1: Centralized deal validation logic.
    """
    
    def validate_deal_value(self, value):
        """Validate deal value"""
        return self._validate_decimal_field(
            value, 'deal_value',
            min_value=Decimal('0.01')
        )
    
    def validate_deal_date(self, value):
        """Validate deal date"""
        return self._validate_date_field(value, 'deal_date', allow_future=True)
    
    def validate_due_date(self, value):
        """Validate due date"""
        validated_date = self._validate_date_field(value, 'due_date', allow_future=True, allow_past=False)
        
        # Ensure due date is after deal date if both are present
        if hasattr(self, 'initial_data'):
            deal_date = self.initial_data.get('deal_date')
            if deal_date and validated_date:
                from datetime import datetime
                if isinstance(deal_date, str):
                    try:
                        deal_date = datetime.strptime(deal_date, '%Y-%m-%d').date()
                    except ValueError:
                        # Skip cross-validation if date format is invalid
                        return validated_date
                
                if deal_date > validated_date:
                    raise serializers.ValidationError(
                        "Due date must be after deal date."
                    )
        
        return validated_date


class FileUploadMixin(FileValidationMixin):
    """
    Mixin for file upload handling in deals.
    Task 2.4.1: Centralized file validation.
    """
    
    receipt_file = FileField(
        allowed_extensions=['pdf', 'jpg', 'jpeg', 'png'],
        max_size=5 * 1024 * 1024,  # 5MB
        required=False
    )
    
    def validate_receipt_file(self, value):
        """Validate receipt file"""
        return self._validate_file(
            value, 'receipt_file',
            max_size=5 * 1024 * 1024,
            allowed_types=['application/pdf', 'image/jpeg', 'image/png']
        )


class CalculatedFieldsMixin:
    """
    Mixin for calculated fields in deals.
    Task 2.4.1: Centralized calculation logic.
    """
    
    total_paid = serializers.SerializerMethodField()
    remaining_balance = serializers.SerializerMethodField()
    payment_progress = serializers.SerializerMethodField()
    
    def get_total_paid(self, obj):
        """Calculate total amount paid for deal"""
        try:
            if hasattr(obj, 'payments'):
                return sum(
                    payment.received_amount or Decimal('0') 
                    for payment in obj.payments.all()
                )
            return Decimal('0')
        except Exception as e:
            logger.error(f"Error calculating total paid: {e}")
            return Decimal('0')
    
    def get_remaining_balance(self, obj):
        """Calculate remaining balance"""
        try:
            total_paid = self.get_total_paid(obj)
            deal_value = getattr(obj, 'deal_value', Decimal('0'))
            return max(deal_value - total_paid, Decimal('0'))
        except Exception as e:
            logger.error(f"Error calculating remaining balance: {e}")
            return Decimal('0')
    
    def get_payment_progress(self, obj):
        """Calculate payment progress percentage"""
        try:
            deal_value = getattr(obj, 'deal_value', Decimal('0'))
            if deal_value <= 0:
                return 0
            
            total_paid = self.get_total_paid(obj)
            progress = (total_paid / deal_value) * 100
            return min(float(progress), 100.0)  # Cap at 100%
            
        except Exception as e:
            logger.error(f"Error calculating payment progress: {e}")
            return 0
