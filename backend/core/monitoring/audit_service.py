"""
Audit Trail Service
Comprehensive audit logging for data changes and user actions
"""

import json
import logging
from typing import Dict, List, Optional, Any, Type
from datetime import datetime, timedelta
from django.db import models
from django.db.models import Count, Q, Sum
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.utils import timezone
from django.core.serializers.json import DjangoJSONEncoder
from django.db.models.signals import post_save, post_delete, pre_save
from django.dispatch import receiver
from .models import AuditTrail, ComplianceReport
from .error_response import SecureLogger

User = get_user_model()
logger = SecureLogger(__name__)


class AuditService:
    """
    Service for comprehensive audit trail management
    """
    
    # Sensitive fields that should be masked in audit logs
    SENSITIVE_FIELDS = {
        'password', 'password_hash', 'token', 'secret', 'api_key', 
        'private_key', 'credit_card', 'ssn', 'bank_account'
    }
    
    # Models that require special audit handling
    FINANCIAL_MODELS = {
        'Deal', 'Payment', 'Commission', 'Transaction', 'Invoice'
    }
    
    # Fields that should trigger high-priority audit logs
    CRITICAL_FIELDS = {
        'status', 'amount', 'balance', 'is_active', 'is_approved', 
        'permissions', 'role', 'email', 'phone'
    }
    
    def __init__(self):
        self.logger = SecureLogger('audit_service')
    
    def log_model_change(self, instance: models.Model, action: str, user=None, 
                        request=None, reason: str = '', old_instance=None) -> AuditTrail:
        """
        Log changes to model instances with comprehensive audit trail
        """
        # Get old and new values
        old_values = self._get_model_values(old_instance) if old_instance else None
        new_values = self._get_model_values(instance) if action != 'DELETE' else None
        
        # Determine if this is sensitive data
        is_sensitive = self._is_sensitive_model(instance) or self._has_sensitive_changes(old_values, new_values)
        
        # Create audit trail entry
        audit_entry = AuditTrail.log_change(
            instance=instance,
            action=action,
            user=user,
            old_values=old_values,
            new_values=new_values,
            request=request,
            reason=reason,
            is_sensitive=is_sensitive
        )
        
        # Log to secure logger
        self.logger.info(
            f"Audit: {action} {instance._meta.model_name}:{instance.pk}",
            extra={
                'audit_id': str(audit_entry.id),
                'model': instance._meta.model_name,
                'action': action,
                'user_id': user.id if user else None,
                'is_sensitive': is_sensitive
            }
        )
        
        # Send notifications for critical changes
        if self._is_critical_change(instance, old_values, new_values):
            self._notify_critical_change(audit_entry, instance, action, user)
        
        return audit_entry
    
    def log_financial_transaction(self, transaction_data: Dict, user=None, 
                                request=None, transaction_type: str = 'FINANCIAL') -> AuditTrail:
        """
        Log financial transactions with enhanced audit requirements
        """
        # Create a pseudo-instance for financial transactions
        class FinancialTransaction:
            def __init__(self, data):
                self.pk = data.get('transaction_id', 'unknown')
                self._meta = type('Meta', (), {
                    'model_name': 'financial_transaction',
                    'db_table': 'financial_transactions'
                })()
        
        transaction_instance = FinancialTransaction(transaction_data)
        
        # Sanitize sensitive financial data
        sanitized_data = self._sanitize_financial_data(transaction_data)
        
        # Create audit entry with special handling for financial data
        audit_entry = AuditTrail.objects.create(
            content_type=ContentType.objects.get_for_model(User),  # Use User as placeholder
            object_id=str(transaction_data.get('transaction_id', 'unknown')),
            action='FINANCIAL_TRANSACTION',
            table_name='financial_transactions',
            new_values=sanitized_data,
            user=user,
            session_id=request.session.session_key if request else '',
            timestamp=timezone.now(),
            ip_address=AuditTrail._get_client_ip(request) if request else None,
            user_agent=request.META.get('HTTP_USER_AGENT', '') if request else '',
            request_id=getattr(request, 'request_id', '') if request else '',
            request_path=request.path if request else '',
            request_method=request.method if request else '',
            is_sensitive=True,
            retention_period=2555  # 7 years for financial records
        )
        
        # Log to secure logger
        self.logger.info(
            f"Financial transaction audit: {transaction_type}",
            extra={
                'audit_id': str(audit_entry.id),
                'transaction_id': transaction_data.get('transaction_id'),
                'amount': transaction_data.get('amount'),
                'user_id': user.id if user else None
            }
        )
        
        return audit_entry
    
    def log_user_action(self, action: str, user, target_object=None, 
                       request=None, details: Dict = None) -> AuditTrail:
        """
        Log user actions for compliance and monitoring
        """
        action_data = {
            'action_type': action,
            'details': details or {},
            'timestamp': timezone.now().isoformat()
        }
        
        # Use target object if provided, otherwise use user as target
        target = target_object or user
        
        audit_entry = AuditTrail.log_change(
            instance=target,
            action='USER_ACTION',
            user=user,
            new_values=action_data,
            request=request,
            reason=f"User action: {action}"
        )
        
        # Log to secure logger
        self.logger.info(
            f"User action: {action}",
            extra={
                'audit_id': str(audit_entry.id),
                'user_id': user.id,
                'action': action,
                'target_type': target._meta.model_name,
                'target_id': target.pk
            }
        )
        
        return audit_entry
    
    def get_audit_trail(self, instance: models.Model, limit: int = 50) -> List[AuditTrail]:
        """
        Get audit trail for a specific model instance
        """
        content_type = ContentType.objects.get_for_model(instance)
        
        return AuditTrail.objects.filter(
            content_type=content_type,
            object_id=str(instance.pk)
        ).order_by('-timestamp')[:limit]
    
    def get_user_activity(self, user, days: int = 30, limit: int = 100) -> List[AuditTrail]:
        """
        Get user activity audit trail
        """
        start_date = timezone.now() - timedelta(days=days)
        
        return AuditTrail.objects.filter(
            user=user,
            timestamp__gte=start_date
        ).order_by('-timestamp')[:limit]
    
    def generate_compliance_report(self, report_type: str, date_from: datetime, 
                                 date_to: datetime, filters: Dict = None, 
                                 created_by=None) -> ComplianceReport:
        """
        Generate compliance reports for audit purposes
        """
        filters = filters or {}
        
        # Create report record
        report = ComplianceReport.objects.create(
            report_type=report_type,
            title=f"{report_type.replace('_', ' ').title()} Report",
            description=f"Generated for period {date_from.date()} to {date_to.date()}",
            date_from=date_from,
            date_to=date_to,
            filters=filters,
            status='generating',
            created_by=created_by or User.objects.get(username='system')
        )
        
        try:
            # Generate report data based on type
            if report_type == 'audit_trail':
                report_data = self._generate_audit_trail_report(date_from, date_to, filters)
            elif report_type == 'financial_audit':
                report_data = self._generate_financial_audit_report(date_from, date_to, filters)
            elif report_type == 'user_activity':
                report_data = self._generate_user_activity_report(date_from, date_to, filters)
            elif report_type == 'access_report':
                report_data = self._generate_access_report(date_from, date_to, filters)
            else:
                raise ValueError(f"Unknown report type: {report_type}")
            
            # Update report with data
            report.report_data = report_data
            report.record_count = report_data.get('total_records', 0)
            report.status = 'completed'
            report.completed_at = timezone.now()
            report.save()
            
            # Log report generation
            self.logger.info(
                f"Compliance report generated: {report_type}",
                extra={
                    'report_id': str(report.id),
                    'report_type': report_type,
                    'record_count': report.record_count,
                    'created_by': created_by.id if created_by else None
                }
            )
            
        except Exception as e:
            report.status = 'failed'
            report.save()
            
            self.logger.error(
                f"Failed to generate compliance report: {report_type}",
                extra={
                    'report_id': str(report.id),
                    'error': str(e)
                }
            )
            raise
        
        return report
    
    def _get_model_values(self, instance: models.Model) -> Dict:
        """
        Get model field values as dictionary, sanitizing sensitive data
        """
        if not instance:
            return None
        
        values = {}
        
        for field in instance._meta.fields:
            field_name = field.name
            field_value = getattr(instance, field_name, None)
            
            # Sanitize sensitive fields
            if field_name.lower() in self.SENSITIVE_FIELDS:
                values[field_name] = '[REDACTED]'
            elif isinstance(field_value, (datetime, models.Model)):
                # Handle special types
                if isinstance(field_value, datetime):
                    values[field_name] = field_value.isoformat()
                elif isinstance(field_value, models.Model):
                    values[field_name] = str(field_value.pk)
                else:
                    values[field_name] = str(field_value)
            else:
                values[field_name] = field_value
        
        return values
    
    def _is_sensitive_model(self, instance: models.Model) -> bool:
        """
        Determine if a model contains sensitive data
        """
        model_name = instance._meta.model_name.lower()
        sensitive_models = {
            'user', 'payment', 'transaction', 'bankaccount', 
            'creditcard', 'personalinfo', 'securityevent'
        }
        
        return model_name in sensitive_models
    
    def _has_sensitive_changes(self, old_values: Dict, new_values: Dict) -> bool:
        """
        Check if changes involve sensitive fields
        """
        if not old_values or not new_values:
            return False
        
        changed_fields = set(old_values.keys()) | set(new_values.keys())
        sensitive_changed = any(
            field.lower() in self.SENSITIVE_FIELDS 
            for field in changed_fields
        )
        
        return sensitive_changed
    
    def _is_critical_change(self, instance: models.Model, old_values: Dict, new_values: Dict) -> bool:
        """
        Determine if changes are critical and require immediate notification
        """
        if not old_values or not new_values:
            return False
        
        # Check for changes to critical fields
        for field_name in self.CRITICAL_FIELDS:
            if (field_name in old_values and field_name in new_values and
                old_values[field_name] != new_values[field_name]):
                return True
        
        # Check for financial model changes
        if instance._meta.model_name in self.FINANCIAL_MODELS:
            return True
        
        return False
    
    def _sanitize_financial_data(self, data: Dict) -> Dict:
        """
        Sanitize financial transaction data for audit logging
        """
        sanitized = data.copy()
        
        # Mask sensitive financial fields
        sensitive_financial_fields = {
            'account_number', 'routing_number', 'card_number', 
            'cvv', 'pin', 'bank_details'
        }
        
        for field in sensitive_financial_fields:
            if field in sanitized:
                if isinstance(sanitized[field], str) and len(sanitized[field]) > 4:
                    # Keep last 4 digits
                    sanitized[field] = '*' * (len(sanitized[field]) - 4) + sanitized[field][-4:]
                else:
                    sanitized[field] = '[REDACTED]'
        
        return sanitized
    
    def _notify_critical_change(self, audit_entry: AuditTrail, instance: models.Model, 
                              action: str, user):
        """
        Send notifications for critical changes
        """
        # This would integrate with notification system
        self.logger.warning(
            f"Critical change detected: {action} {instance._meta.model_name}",
            extra={
                'audit_id': str(audit_entry.id),
                'model': instance._meta.model_name,
                'instance_id': instance.pk,
                'user_id': user.id if user else None,
                'action': action
            }
        )
    
    def _generate_audit_trail_report(self, date_from: datetime, date_to: datetime, 
                                   filters: Dict) -> Dict:
        """
        Generate comprehensive audit trail report
        """
        queryset = AuditTrail.objects.filter(
            timestamp__gte=date_from,
            timestamp__lte=date_to
        )
        
        # Apply filters
        if filters.get('user_id'):
            queryset = queryset.filter(user_id=filters['user_id'])
        if filters.get('table_name'):
            queryset = queryset.filter(table_name=filters['table_name'])
        if filters.get('action'):
            queryset = queryset.filter(action=filters['action'])
        if filters.get('is_sensitive'):
            queryset = queryset.filter(is_sensitive=filters['is_sensitive'])
        
        # Generate statistics
        total_records = queryset.count()
        actions_summary = queryset.values('action').annotate(count=Count('id'))
        tables_summary = queryset.values('table_name').annotate(count=Count('id'))
        users_summary = queryset.values('user__username').annotate(count=Count('id'))
        
        # Get sample records
        sample_records = [
            audit.to_dict() for audit in queryset.order_by('-timestamp')[:100]
        ]
        
        return {
            'total_records': total_records,
            'period': {
                'from': date_from.isoformat(),
                'to': date_to.isoformat()
            },
            'summary': {
                'actions': list(actions_summary),
                'tables': list(tables_summary),
                'users': list(users_summary)
            },
            'sample_records': sample_records,
            'filters_applied': filters
        }
    
    def _generate_financial_audit_report(self, date_from: datetime, date_to: datetime, 
                                       filters: Dict) -> Dict:
        """
        Generate financial audit report
        """
        queryset = AuditTrail.objects.filter(
            timestamp__gte=date_from,
            timestamp__lte=date_to,
            is_sensitive=True
        ).filter(
            models.Q(table_name__in=['deals', 'payments', 'commissions']) |
            models.Q(action='FINANCIAL_TRANSACTION')
        )
        
        # Apply additional filters
        if filters.get('user_id'):
            queryset = queryset.filter(user_id=filters['user_id'])
        
        total_records = queryset.count()
        
        # Financial-specific analysis
        transaction_types = queryset.filter(
            action='FINANCIAL_TRANSACTION'
        ).values('new_values__transaction_type').annotate(count=Count('id'))
        
        # Get high-value transactions (if amount data is available)
        high_value_transactions = []
        for audit in queryset.filter(action='FINANCIAL_TRANSACTION')[:50]:
            if audit.new_values and 'amount' in audit.new_values:
                try:
                    amount = float(audit.new_values['amount'])
                    if amount > 10000:  # Configurable threshold
                        high_value_transactions.append(audit.to_dict())
                except (ValueError, TypeError):
                    pass
        
        return {
            'total_records': total_records,
            'period': {
                'from': date_from.isoformat(),
                'to': date_to.isoformat()
            },
            'financial_summary': {
                'transaction_types': list(transaction_types),
                'high_value_transactions': high_value_transactions,
                'total_financial_events': queryset.filter(action='FINANCIAL_TRANSACTION').count()
            },
            'compliance_notes': [
                'All financial transactions are logged with 7-year retention',
                'Sensitive financial data is masked in audit logs',
                'High-value transactions are flagged for review'
            ]
        }
    
    def _generate_user_activity_report(self, date_from: datetime, date_to: datetime, 
                                     filters: Dict) -> Dict:
        """
        Generate user activity report
        """
        queryset = AuditTrail.objects.filter(
            timestamp__gte=date_from,
            timestamp__lte=date_to
        ).exclude(user__isnull=True)
        
        if filters.get('user_id'):
            queryset = queryset.filter(user_id=filters['user_id'])
        
        # User activity statistics
        user_activity = queryset.values(
            'user__username', 'user__id'
        ).annotate(
            total_actions=Count('id'),
            create_actions=Count('id', filter=Q(action='CREATE')),
            update_actions=Count('id', filter=Q(action='UPDATE')),
            delete_actions=Count('id', filter=Q(action='DELETE'))
        ).order_by('-total_actions')
        
        # Most active users
        top_users = list(user_activity[:20])
        
        # Activity timeline
        daily_activity = queryset.extra(
            select={'date': 'DATE(timestamp)'}
        ).values('date').annotate(count=Count('id')).order_by('date')
        
        return {
            'total_records': queryset.count(),
            'period': {
                'from': date_from.isoformat(),
                'to': date_to.isoformat()
            },
            'user_activity': {
                'top_users': top_users,
                'total_active_users': user_activity.count(),
                'daily_activity': list(daily_activity)
            }
        }
    
    def _generate_access_report(self, date_from: datetime, date_to: datetime, 
                              filters: Dict) -> Dict:
        """
        Generate data access report
        """
        # This would integrate with SecurityEvent model for access logging
        from .models import SecurityEvent
        
        access_events = SecurityEvent.objects.filter(
            timestamp__gte=date_from,
            timestamp__lte=date_to,
            event_type='data_access'
        )
        
        if filters.get('user_id'):
            access_events = access_events.filter(user_id=filters['user_id'])
        
        # Access patterns
        data_types_accessed = access_events.values(
            'event_data__data_type'
        ).annotate(count=Count('id'))
        
        sensitive_access = access_events.filter(
            event_data__is_sensitive=True
        )
        
        return {
            'total_access_events': access_events.count(),
            'sensitive_access_events': sensitive_access.count(),
            'data_types_accessed': list(data_types_accessed),
            'period': {
                'from': date_from.isoformat(),
                'to': date_to.isoformat()
            }
        }


# Global instance
audit_service = AuditService()


# Signal handlers for automatic audit logging
@receiver(post_save)
def log_model_save(sender, instance, created, **kwargs):
    """
    Automatically log model saves
    """
    # Skip audit models to prevent recursion
    from .models import SecurityEvent, ComplianceReport
    if sender in [AuditTrail, SecurityEvent, ComplianceReport]:
        return
    
    action = 'CREATE' if created else 'UPDATE'
    
    # Get user from thread-local storage if available
    user = getattr(instance, '_audit_user', None)
    request = getattr(instance, '_audit_request', None)
    
    try:
        audit_service.log_model_change(
            instance=instance,
            action=action,
            user=user,
            request=request
        )
    except Exception as e:
        # Log error but don't break the save operation
        logger.error(f"Failed to create audit log: {e}")


@receiver(post_delete)
def log_model_delete(sender, instance, **kwargs):
    """
    Automatically log model deletions
    """
    # Skip audit models to prevent recursion
    from .models import SecurityEvent, ComplianceReport
    if sender in [AuditTrail, SecurityEvent, ComplianceReport]:
        return
    
    # Get user from thread-local storage if available
    user = getattr(instance, '_audit_user', None)
    request = getattr(instance, '_audit_request', None)
    
    try:
        audit_service.log_model_change(
            instance=instance,
            action='DELETE',
            user=user,
            request=request
        )
    except Exception as e:
        # Log error but don't break the delete operation
        logger.error(f"Failed to create audit log: {e}")