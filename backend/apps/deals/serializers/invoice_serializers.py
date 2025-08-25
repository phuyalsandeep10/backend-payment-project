"""
Invoice and Approval Serializers - Task 2.4.1

Focused serializers for payment invoices and approvals.
Extracted from the original monolithic serializer file.
"""

from rest_framework import serializers
from apps.deals.models import PaymentInvoice, PaymentApproval
from .base_serializers import DealsBaseSerializer, PaymentStatusMixin
from core.serializers import MoneyField, FileField, DateTimeField, StatusChoiceField
from apps.authentication.serializers import UserLiteSerializer
import logging

logger = logging.getLogger(__name__)


class PaymentInvoiceSerializer(DealsBaseSerializer):
    """
    Serializer for payment invoices.
    Task 2.4.1: Focused invoice management.
    """
    
    # Related information
    client_name = serializers.CharField(source='payment.deal.client.client_name', read_only=True)
    deal_id = serializers.CharField(source='payment.deal.deal_id', read_only=True)
    payment_amount = MoneyField(source='payment.received_amount', read_only=True)
    
    # Enhanced fields - using invoice_date since PaymentInvoice doesn't have created_at/updated_at
    # Note: PaymentInvoice model only has invoice_date field, not created_at/updated_at
    
    # Status handling
    invoice_status = StatusChoiceField(
        choices=[
            ('pending', 'Pending'),
            ('processing', 'Processing'),
            ('approved', 'Approved'),
            ('rejected', 'Rejected'),
            ('paid', 'Paid')
        ],
        display_map={
            'pending': 'Awaiting Review',
            'processing': 'Under Review',
            'approved': 'Approved for Payment',
            'rejected': 'Rejected',
            'paid': 'Payment Completed'
        }
    )
    
    class Meta:
        model = PaymentInvoice
        fields = [
            'id', 'payment', 'deal_id', 'client_name', 'payment_amount',
            'invoice_number', 'invoice_date', 'invoice_amount',
            'invoice_file', 'invoice_status', 'invoice_remarks'
        ]
        read_only_fields = [
            'id', 'deal_id', 'client_name', 'payment_amount',
            'invoice_date'
        ]
    
    def validate_invoice_amount(self, value):
        """Validate invoice amount"""
        from decimal import Decimal
        
        if value is not None and value <= Decimal('0'):
            raise serializers.ValidationError(
                "Invoice amount must be greater than zero."
            )
        
        return value
    
    def validate_invoice_number(self, value):
        """Validate invoice number uniqueness"""
        if value:
            # Check for uniqueness within organization
            request = self.context.get('request')
            if request and request.user and hasattr(request.user, 'organization'):
                existing_invoice = PaymentInvoice.objects.filter(
                    invoice_number=value,
                    payment__deal__organization=request.user.organization
                ).first()
                
                if existing_invoice and (not self.instance or existing_invoice.id != self.instance.id):
                    raise serializers.ValidationError(
                        f"Invoice number '{value}' already exists in your organization."
                    )
        
        return value
    
    def validate(self, attrs):
        """Enhanced validation for invoice data"""
        attrs = super().validate(attrs)
        
        # Validate invoice amount against payment amount
        payment = attrs.get('payment') or (self.instance.payment if self.instance else None)
        invoice_amount = attrs.get('invoice_amount')
        
        if payment and invoice_amount:
            if invoice_amount > payment.received_amount:
                raise serializers.ValidationError({
                    'invoice_amount': 'Invoice amount cannot exceed payment amount.'
                })
        
        return attrs


class PaymentApprovalSerializer(DealsBaseSerializer, PaymentStatusMixin):
    """
    Serializer for payment approvals.
    Task 2.4.1: Focused approval management.
    """
    
    # Related information
    client_name = serializers.CharField(source='payment.invoice.deal.client.client_name', read_only=True)
    deal_id = serializers.CharField(source='payment.invoice.deal.deal_id', read_only=True)
    payment_amount = MoneyField(source='payment.received_amount', read_only=True)
    
    # Approval details
    approved_by = UserLiteSerializer(read_only=True)
    verified_amount = MoneyField()
    
    # Status and file handling
    approval_status = StatusChoiceField(
        choices=[
            ('pending', 'Pending Review'),
            ('under_review', 'Under Review'),
            ('approved', 'Approved'),
            ('rejected', 'Rejected'),
            ('requires_info', 'Requires Additional Information')
        ]
    )
    
    invoice_file = FileField(
        allowed_extensions=['pdf', 'jpg', 'jpeg', 'png'],
        max_size=10 * 1024 * 1024,  # 10MB
        required=False
    )
    
    # Enhanced fields - using approval_date since PaymentApproval doesn't have created_at/updated_at
    # Note: PaymentApproval model only has approval_date field, not created_at/updated_at
    
    class Meta:
        model = PaymentApproval
        fields = [
            'id', 'payment', 'deal_id', 'client_name', 'payment_amount',
            'approved_by', 'approval_status', 'verified_amount',
            'approval_remarks', 'invoice_file', 'invoice_status',
            'approval_date'
        ]
        read_only_fields = [
            'id', 'payment', 'deal_id', 'client_name', 'payment_amount',
            'approved_by', 'approval_date'
        ]
    
    def validate_verified_amount(self, value):
        """Validate verified amount"""
        from decimal import Decimal
        
        if value is not None:
            if value <= Decimal('0'):
                raise serializers.ValidationError(
                    "Verified amount must be greater than zero."
                )
            
            # Check against payment amount if available
            if self.instance and self.instance.payment:
                if value > self.instance.payment.received_amount:
                    raise serializers.ValidationError(
                        "Verified amount cannot exceed payment amount."
                    )
        
        return value
    
    def validate_approval_status(self, value):
        """Validate approval status transitions"""
        if self.instance:
            old_status = self.instance.approval_status
            
            # Define valid status transitions
            valid_transitions = {
                'pending': ['under_review', 'approved', 'rejected', 'requires_info'],
                'under_review': ['approved', 'rejected', 'requires_info'],
                'requires_info': ['under_review', 'approved', 'rejected'],
                'approved': [],  # Cannot change from approved
                'rejected': ['under_review']  # Can only go back to review
            }
            
            if old_status in valid_transitions:
                if value not in valid_transitions[old_status]:
                    raise serializers.ValidationError(
                        f"Cannot change status from '{old_status}' to '{value}'."
                    )
        
        return value
    
    def validate(self, attrs):
        """Enhanced validation for approval data"""
        attrs = super().validate(attrs)
        
        # Require verified amount for approved status
        approval_status = attrs.get('approval_status')
        verified_amount = attrs.get('verified_amount')
        
        if approval_status == 'approved' and not verified_amount:
            raise serializers.ValidationError({
                'verified_amount': 'Verified amount is required for approved status.'
            })
        
        # Require remarks for rejection
        if approval_status == 'rejected':
            remarks = attrs.get('approval_remarks')
            if not remarks or not remarks.strip():
                raise serializers.ValidationError({
                    'approval_remarks': 'Remarks are required when rejecting a payment.'
                })
        
        return attrs
    
    def create(self, validated_data):
        """Create approval with proper user assignment"""
        request = self.context.get('request')
        if request and request.user:
            validated_data['approved_by'] = request.user
        
        return super().create(validated_data)
    
    def update(self, instance, validated_data):
        """Update approval with change tracking"""
        old_status = instance.approval_status
        
        # Update the instance
        updated_instance = super().update(instance, validated_data)
        
        # Log status change
        new_status = updated_instance.approval_status
        if old_status != new_status:
            self._log_approval_change(updated_instance, old_status, new_status)
        
        return updated_instance
    
    def _log_approval_change(self, approval, old_status, new_status):
        """Log approval status changes"""
        try:
            from apps.deals.models import ActivityLog
            
            request = self.context.get('request')
            user = request.user if request else approval.approved_by
            
            description = f"Payment approval status changed from '{old_status}' to '{new_status}'"
            
            ActivityLog.objects.create(
                deal=approval.payment.deal if approval.payment else None,
                user=user,
                action='approval_status_changed',
                description=description,
                metadata={
                    'approval_id': approval.id,
                    'old_status': old_status,
                    'new_status': new_status,
                    'verified_amount': str(approval.verified_amount) if approval.verified_amount else None
                }
            )
            
        except Exception as e:
            logger.error(f"Error logging approval change: {e}")


class ApprovalSummarySerializer(serializers.Serializer):
    """
    Serializer for approval summary information.
    Task 2.4.1: Summary view for approvals.
    """
    
    total_approvals = serializers.IntegerField()
    pending_approvals = serializers.IntegerField()
    approved_count = serializers.IntegerField()
    rejected_count = serializers.IntegerField()
    total_amount = MoneyField()
    verified_amount = MoneyField()
    approval_rate = serializers.FloatField()
    
    def to_representation(self, instance):
        """Enhanced representation with calculated fields"""
        data = super().to_representation(instance)
        
        # Calculate additional metrics
        total = data.get('total_approvals', 0)
        approved = data.get('approved_count', 0)
        
        if total > 0:
            data['approval_rate'] = (approved / total) * 100
        else:
            data['approval_rate'] = 0
        
        # Add status distribution
        data['status_distribution'] = {
            'pending': data.get('pending_approvals', 0),
            'approved': data.get('approved_count', 0),
            'rejected': data.get('rejected_count', 0),
            'other': total - data.get('pending_approvals', 0) - approved - data.get('rejected_count', 0)
        }
        
        return data


class InvoiceListSerializer(DealsBaseSerializer):
    """
    Lightweight serializer for invoice listings.
    Task 2.4.1: Optimized for list views.
    """
    
    client_name = serializers.CharField(source='payment.deal.client.client_name', read_only=True)
    deal_id = serializers.CharField(source='payment.deal.deal_id', read_only=True)
    payment_amount = MoneyField(source='payment.received_amount', read_only=True)
    
    class Meta:
        model = PaymentInvoice
        fields = [
            'id', 'deal_id', 'client_name', 'invoice_number',
            'invoice_date', 'payment_amount', 'invoice_status'
        ]


class ApprovalListSerializer(DealsBaseSerializer):
    """
    Lightweight serializer for approval listings.
    Task 2.4.1: Optimized for list views.
    """
    
    client_name = serializers.CharField(source='payment.invoice.deal.client.client_name', read_only=True)
    deal_id = serializers.CharField(source='payment.invoice.deal.deal_id', read_only=True)
    payment_amount = MoneyField(source='payment.received_amount', read_only=True)
    approved_by_name = serializers.CharField(source='approved_by.get_full_name', read_only=True)
    
    class Meta:
        model = PaymentApproval
        fields = [
            'id', 'deal_id', 'client_name', 'payment_amount',
            'approval_status', 'verified_amount', 'approved_by_name',
            'approval_date'
        ]
