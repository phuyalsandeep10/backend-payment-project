"""
Activity and History Serializers - Task 2.4.1

Focused serializers for activity logging, payment history, and audit trails.
Extracted from the original monolithic serializer file.
"""

from rest_framework import serializers
from apps.deals.models import ActivityLog
from .base_serializers import DealsBaseSerializer, CalculatedFieldsMixin
from core.serializers import DateTimeField
from apps.authentication.serializers import UserLiteSerializer
import logging

logger = logging.getLogger(__name__)


class ActivityLogSerializer(DealsBaseSerializer):
    """
    Simple serializer for activity logs.
    Task 2.4.1: Clean and focused activity logging.
    """
    
    user = UserLiteSerializer(read_only=True)
    created_at = DateTimeField()
    
    class Meta:
        model = ActivityLog
        fields = [
            'id', 'deal', 'user', 'action', 'description',
            'created_at', 'metadata'
        ]
        read_only_fields = ['id', 'created_at']


class DealPaymentHistorySerializer(DealsBaseSerializer):
    """
    Serializer for deal payment history view.
    Task 2.4.1: Focused on payment history presentation.
    """
    
    payment_serial = serializers.SerializerMethodField()
    payment_value = serializers.DecimalField(source='received_amount', max_digits=15, decimal_places=2)
    payment_version = serializers.IntegerField(source='version', read_only=True)
    verification_status = serializers.SerializerMethodField()
    verified_by = serializers.SerializerMethodField()
    verifier_remarks = serializers.SerializerMethodField()
    receipt_link = serializers.SerializerMethodField()
    invoice_details = serializers.SerializerMethodField()
    client_name = serializers.CharField(source='deal.client.client_name', read_only=True)
    deal_id = serializers.CharField(source='deal.deal_id', read_only=True)
    
    class Meta:
        model = None  # This will be set dynamically based on Payment model
        fields = [
            'id', 'deal_id', 'client_name', 'payment_serial',
            'payment_date', 'payment_value', 'payment_version', 'payment_type',
            'cheque_number', 'verification_status', 'verified_by',
            'verifier_remarks', 'receipt_link', 'invoice_details',
            'payment_remarks', 'version', 'created_at'
        ]
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Set the model dynamically
        from apps.deals.models import Payment
        self.Meta.model = Payment
    
    def get_payment_serial(self, obj):
        """Get payment serial number within the deal"""
        try:
            if obj.deal:
                # Get position of this payment within deal's payments
                payments = obj.deal.payments.order_by('created_at')
                for index, payment in enumerate(payments, 1):
                    if payment.id == obj.id:
                        return index
            return 1
        except Exception:
            return 1
    
    def get_verification_status(self, obj):
        """Get verification status"""
        try:
            # Check payment status first
            if obj.status:
                return obj.status
            
            # Check latest approval
            if hasattr(obj, 'approvals') and obj.approvals.exists():
                latest_approval = obj.approvals.latest('approval_date')
                if latest_approval.failure_remarks:
                    return 'rejected'
                elif latest_approval.verifier_remarks or latest_approval.approval_remarks:
                    return 'approved'
                return 'pending'
            
            # Check invoice status
            if hasattr(obj, 'invoice') and obj.invoice:
                return obj.invoice.invoice_status
                
        except Exception as e:
            logger.error(f"Error getting verification status: {e}")
        
        return 'pending'
    
    def get_verified_by(self, obj):
        """Get who verified the payment"""
        try:
            if hasattr(obj, 'approvals') and obj.approvals.exists():
                # Get the latest approval that has an approved_by user
                latest_approval = obj.approvals.filter(
                    approved_by__isnull=False
                ).latest('approval_date')
                
                if latest_approval and latest_approval.approved_by:
                    return {
                        'id': latest_approval.approved_by.id,
                        'name': latest_approval.approved_by.get_full_name(),
                        'email': latest_approval.approved_by.email,
                        'date': latest_approval.approval_date
                    }
        except Exception as e:
            logger.error(f"Error getting verified_by: {e}")
        
        return None
    
    def get_verifier_remarks(self, obj):
        """Get verifier remarks"""
        try:
            if hasattr(obj, 'approvals') and obj.approvals.exists():
                latest_approval = obj.approvals.latest('approval_date')
                return {
                    'verifier_remarks': latest_approval.verifier_remarks or '',
                    'approval_remarks': latest_approval.approval_remarks or '',
                    'failure_remarks': latest_approval.failure_remarks or '',
                    'amount_in_invoice': str(latest_approval.amount_in_invoice) if latest_approval.amount_in_invoice else None
                }
        except Exception as e:
            logger.error(f"Error getting verifier remarks: {e}")
        
        return {
            'verifier_remarks': '',
            'approval_remarks': '',
            'failure_remarks': '',
            'amount_in_invoice': None
        }
    
    def get_receipt_link(self, obj):
        """Get receipt file link"""
        try:
            # Check payment receipt file
            if obj.receipt_file:
                request = self.context.get('request')
                if request:
                    return request.build_absolute_uri(obj.receipt_file.url)
                return obj.receipt_file.url
            
            # Check invoice receipt file
            if hasattr(obj, 'invoice') and obj.invoice and obj.invoice.receipt_file:
                request = self.context.get('request')
                if request:
                    return request.build_absolute_uri(obj.invoice.receipt_file.url)
                return obj.invoice.receipt_file.url
                
        except Exception as e:
            logger.error(f"Error getting receipt link: {e}")
        
        return None
    
    def get_invoice_details(self, obj):
        """Get invoice details"""
        try:
            if hasattr(obj, 'invoice') and obj.invoice:
                invoice = obj.invoice
                invoice_file_url = None
                if invoice.invoice_file:
                    request = self.context.get('request')
                    if request:
                        invoice_file_url = request.build_absolute_uri(invoice.invoice_file.url)
                    else:
                        invoice_file_url = invoice.invoice_file.url
                
                return {
                    'invoice_id': invoice.invoice_id,
                    'invoice_number': invoice.invoice_number,
                    'invoice_amount': str(invoice.invoice_amount),
                    'invoice_date': invoice.invoice_date,
                    'due_date': invoice.due_date,
                    'invoice_status': invoice.invoice_status,
                    'invoice_file_url': invoice_file_url,
                    'invoice_remarks': invoice.invoice_remarks or ''
                }
        except Exception as e:
            logger.error(f"Error getting invoice details: {e}")
        
        return None


class DealExpandedViewSerializer(DealsBaseSerializer, CalculatedFieldsMixin):
    """
    Serializer for expanded deal view with comprehensive information.
    Task 2.4.1: Focused on detailed deal presentation.
    """
    
    payment_history = serializers.SerializerMethodField()
    verification_details = serializers.SerializerMethodField()
    client_info = serializers.SerializerMethodField()
    activity_summary = serializers.SerializerMethodField()
    
    # Financial calculation fields
    total_paid = serializers.SerializerMethodField()
    remaining_balance = serializers.SerializerMethodField()
    payment_progress = serializers.SerializerMethodField()
    
    # Status fields
    verifier_remark_status = serializers.SerializerMethodField()
    verified_by = serializers.CharField(source='updated_by.get_full_name', default=None, read_only=True)
    
    class Meta:
        model = None  # Will be set to Deal model
        fields = [
            'id', 'deal_id', 'deal_name', 'deal_value', 'currency',
            'deal_date', 'due_date', 'payment_status', 'verification_status',
            'client_info', 'payment_history', 'verification_details',
            'activity_summary', 'total_paid', 'remaining_balance',
            'payment_progress', 'verified_by', 'verifier_remark_status',
            'created_at', 'updated_at'
        ]
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Set the model dynamically
        from apps.deals.models import Deal
        self.Meta.model = Deal
    
    def get_payment_history(self, obj):
        """Get comprehensive payment history"""
        try:
            payments = obj.payments.select_related(
                'deal__client',
                'invoice'
            ).prefetch_related(
                'approvals__approved_by',
                'approvals'
            ).order_by('-created_at')
            
            return DealPaymentHistorySerializer(
                payments, 
                many=True, 
                context=self.context
            ).data
        except Exception as e:
            logger.error(f"Error getting payment history: {e}")
            return []
    
    def get_verification_details(self, obj):
        """Get verification details"""
        try:
            return {
                'status': obj.verification_status,
                'verified_by': self.get_verified_by_info(obj),
                'verification_date': obj.updated_at,
                'remarks': getattr(obj, 'verification_remarks', ''),
                'verification_count': self._get_verification_count(obj)
            }
        except Exception as e:
            logger.error(f"Error getting verification details: {e}")
            return {}
    
    def get_client_info(self, obj):
        """Get comprehensive client information"""
        try:
            if obj.client:
                return {
                    'id': obj.client.id,
                    'name': obj.client.client_name,
                    'contact': getattr(obj.client, 'contact_number', ''),
                    'email': getattr(obj.client, 'email', ''),
                    'address': getattr(obj.client, 'address', ''),
                    'total_deals': self._get_client_deal_count(obj.client),
                    'total_value': self._get_client_total_value(obj.client)
                }
        except Exception as e:
            logger.error(f"Error getting client info: {e}")
        
        return None
    
    def get_activity_summary(self, obj):
        """Get activity summary"""
        try:
            # Get recent activities
            activities = obj.activity_logs.select_related('user').order_by('-created_at')[:10]
            
            return {
                'total_activities': obj.activity_logs.count(),
                'recent_activities': [
                    {
                        'action': activity.action,
                        'description': activity.description,
                        'user': activity.user.get_full_name() if activity.user else 'System',
                        'date': activity.created_at
                    }
                    for activity in activities
                ],
                'last_activity': activities.first().created_at if activities.exists() else None
            }
            
        except Exception as e:
            logger.error(f"Error getting activity summary: {e}")
            return {
                'total_activities': 0,
                'recent_activities': [],
                'last_activity': None
            }
    
    def get_total_paid(self, obj):
        """Calculate total amount paid for this deal"""
        try:
            from decimal import Decimal
            total = sum(payment.received_amount for payment in obj.payments.all())
            return str(total) if total else "0.00"
        except Exception as e:
            logger.error(f"Error calculating total paid: {e}")
            return "0.00"
    
    def get_remaining_balance(self, obj):
        """Calculate remaining balance for this deal"""
        try:
            from decimal import Decimal
            total_paid = sum(payment.received_amount for payment in obj.payments.all())
            remaining = obj.deal_value - total_paid
            return str(remaining) if remaining > 0 else "0.00"
        except Exception as e:
            logger.error(f"Error calculating remaining balance: {e}")
            return "0.00"
    
    def get_payment_progress(self, obj):
        """Calculate payment progress percentage"""
        try:
            if obj.deal_value and obj.deal_value > 0:
                total_paid = sum(payment.received_amount for payment in obj.payments.all())
                progress = (total_paid / obj.deal_value) * 100
                return min(round(progress, 2), 100.0)  # Cap at 100%
            return 0.0
        except Exception as e:
            logger.error(f"Error calculating payment progress: {e}")
            return 0.0
    
    def get_verifier_remark_status(self, obj):
        """Get verifier remark status"""
        return "yes" if obj.verification_status == 'verified' else "no"
    
    def get_verified_by_info(self, obj):
        """Get detailed verifier information"""
        try:
            if obj.updated_by:
                return {
                    'id': obj.updated_by.id,
                    'name': obj.updated_by.get_full_name(),
                    'email': obj.updated_by.email,
                    'role': obj.updated_by.role.name if hasattr(obj.updated_by, 'role') and obj.updated_by.role else None
                }
        except Exception:
            pass
        
        return None
    
    def _get_verification_count(self, obj):
        """Get number of times deal was verified"""
        try:
            # Count activity logs related to verification
            return obj.activity_logs.filter(action__icontains='verify').count()
        except Exception:
            return 0
    
    def _get_client_deal_count(self, client):
        """Get total deals count for client"""
        try:
            return client.deals.count()
        except Exception:
            return 0
    
    def _get_client_total_value(self, client):
        """Get total deal value for client"""
        try:
            from django.db.models import Sum
            result = client.deals.aggregate(total=Sum('deal_value'))
            return result['total'] or 0
        except Exception:
            return 0


class ActivityLogCreateSerializer(serializers.ModelSerializer):
    """
    Serializer for creating activity logs.
    Task 2.4.1: Focused on activity log creation.
    """
    
    class Meta:
        model = ActivityLog
        fields = ['deal', 'action', 'description', 'metadata']
    
    def create(self, validated_data):
        """Create activity log with user context"""
        request = self.context.get('request')
        if request and request.user:
            validated_data['user'] = request.user
        
        return super().create(validated_data)


class DealAuditSerializer(DealsBaseSerializer):
    """
    Serializer for deal audit information.
    Task 2.4.1: Focused on audit trails and compliance.
    """
    
    audit_trail = serializers.SerializerMethodField()
    change_summary = serializers.SerializerMethodField()
    compliance_status = serializers.SerializerMethodField()
    
    class Meta:
        model = None  # Will be set to Deal model
        fields = [
            'id', 'deal_id', 'audit_trail', 'change_summary',
            'compliance_status', 'created_at', 'updated_at'
        ]
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        from apps.deals.models import Deal
        self.Meta.model = Deal
    
    def get_audit_trail(self, obj):
        """Get complete audit trail"""
        try:
            activities = obj.activity_logs.select_related('user').order_by('-created_at')
            
            return [
                {
                    'timestamp': activity.created_at,
                    'action': activity.action,
                    'description': activity.description,
                    'user': {
                        'id': activity.user.id,
                        'name': activity.user.get_full_name(),
                        'email': activity.user.email
                    } if activity.user else None,
                    'metadata': activity.metadata or {}
                }
                for activity in activities
            ]
            
        except Exception as e:
            logger.error(f"Error getting audit trail: {e}")
            return []
    
    def get_change_summary(self, obj):
        """Get summary of changes made to the deal"""
        try:
            activities = obj.activity_logs.filter(action='updated').order_by('-created_at')
            
            return {
                'total_changes': activities.count(),
                'last_changed': activities.first().created_at if activities.exists() else obj.updated_at,
                'change_frequency': self._calculate_change_frequency(obj),
                'major_changes': self._get_major_changes(activities)
            }
            
        except Exception as e:
            logger.error(f"Error getting change summary: {e}")
            return {}
    
    def get_compliance_status(self, obj):
        """Get compliance status"""
        try:
            # Basic compliance checks
            compliance_checks = {
                'has_required_approvals': self._check_required_approvals(obj),
                'payment_verification_complete': self._check_payment_verification(obj),
                'documentation_complete': self._check_documentation(obj),
                'within_compliance_timeline': self._check_timeline_compliance(obj)
            }
            
            passed_checks = sum(1 for check in compliance_checks.values() if check)
            total_checks = len(compliance_checks)
            
            return {
                'overall_status': 'compliant' if passed_checks == total_checks else 'non_compliant',
                'compliance_score': (passed_checks / total_checks) * 100,
                'checks': compliance_checks,
                'last_compliance_check': timezone.now()
            }
            
        except Exception as e:
            logger.error(f"Error getting compliance status: {e}")
            return {'overall_status': 'unknown', 'compliance_score': 0}
    
    def _calculate_change_frequency(self, obj):
        """Calculate how frequently the deal is modified"""
        try:
            from datetime import datetime, timedelta
            from django.utils import timezone
            
            # Get changes in last 30 days
            thirty_days_ago = timezone.now() - timedelta(days=30)
            recent_changes = obj.activity_logs.filter(
                action='updated',
                created_at__gte=thirty_days_ago
            ).count()
            
            return recent_changes / 30  # Changes per day
            
        except Exception:
            return 0
    
    def _get_major_changes(self, activities):
        """Get list of major changes"""
        # This would analyze activity metadata to identify major changes
        return []
    
    def _check_required_approvals(self, obj):
        """Check if required approvals are in place"""
        # Implementation would depend on business rules
        return obj.verification_status == 'verified'
    
    def _check_payment_verification(self, obj):
        """Check if payments are properly verified"""
        try:
            total_payments = obj.payments.count()
            verified_payments = obj.payments.filter(
                approvals__approval_status='approved'
            ).distinct().count()
            
            return total_payments == 0 or verified_payments == total_payments
        except Exception:
            return False
    
    def _check_documentation(self, obj):
        """Check if required documentation is complete"""
        # This would check for required documents
        return True  # Placeholder
    
    def _check_timeline_compliance(self, obj):
        """Check if deal is within compliance timelines"""
        try:
            from django.utils import timezone
            
            # Check if deal is overdue
            if obj.due_date and obj.due_date < timezone.now().date():
                return obj.payment_status == 'completed'
            
            return True
        except Exception:
            return False
