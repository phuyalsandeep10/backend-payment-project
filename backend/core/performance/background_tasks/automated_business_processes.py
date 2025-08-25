"""
Automated Business Processes
Implements automated deal verification reminders, commission calculations, audit reports, and cleanup tasks
"""

from celery import shared_task
from celery.utils.log import get_task_logger
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from django.db import transaction
from django.db.models import Q, Count, Sum, Avg
from datetime import timedelta, datetime
from typing import Dict, List, Optional, Any
import logging
import json

# Task logger
logger = get_task_logger(__name__)

class AutomatedBusinessProcessManager:
    """
    Manager for automated business processes
    """
    
    @classmethod
    def get_process_status(cls, process_name: str) -> Dict[str, Any]:
        """Get status of automated business process"""
        try:
            from django.core.cache import cache
            
            status_key = f"automated_process_status:{process_name}"
            status = cache.get(status_key, {})
            
            return {
                'process_name': process_name,
                'status': status.get('status', 'unknown'),
                'last_run': status.get('last_run'),
                'next_run': status.get('next_run'),
                'success_count': status.get('success_count', 0),
                'failure_count': status.get('failure_count', 0)
            }
            
        except Exception as e:
            logger.error(f"Failed to get process status for {process_name}: {str(e)}")
            return {'process_name': process_name, 'status': 'error', 'error': str(e)}
    
    @classmethod
    def update_process_status(cls, process_name: str, status: str, details: Dict[str, Any] = None):
        """Update status of automated business process"""
        try:
            from django.core.cache import cache
            
            status_key = f"automated_process_status:{process_name}"
            current_status = cache.get(status_key, {})
            
            updated_status = {
                'status': status,
                'last_run': timezone.now().isoformat(),
                'success_count': current_status.get('success_count', 0),
                'failure_count': current_status.get('failure_count', 0),
                'details': details or {}
            }
            
            if status == 'success':
                updated_status['success_count'] += 1
            elif status == 'failed':
                updated_status['failure_count'] += 1
            
            cache.set(status_key, updated_status, 86400)  # Cache for 24 hours
            
        except Exception as e:
            logger.error(f"Failed to update process status for {process_name}: {str(e)}")


# Deal Verification Reminders
@shared_task(bind=True, max_retries=3)
def send_deal_verification_reminders(self):
    """
    Send reminders for deals pending verification
    """
    try:
        from deals.models import Deal
        from apps.authentication.models import User
        
        logger.info("Starting deal verification reminders process")
        
        process_name = "deal_verification_reminders"
        AutomatedBusinessProcessManager.update_process_status(process_name, 'running')
        
        # Get deals pending verification for more than 24 hours
        cutoff_time = timezone.now() - timedelta(hours=24)
        pending_deals = Deal.objects.filter(
            verification_status='pending',
            created_at__lt=cutoff_time
        ).select_related('client', 'organization', 'created_by')
        
        reminder_results = {
            'total_pending_deals': pending_deals.count(),
            'reminders_sent': 0,
            'failed_reminders': 0,
            'organizations_notified': set(),
            'details': []
        }
        
        # Group deals by organization for efficient processing
        org_deals = {}
        for deal in pending_deals:
            org_id = deal.organization.id
            if org_id not in org_deals:
                org_deals[org_id] = []
            org_deals[org_id].append(deal)
        
        # Send reminders per organization
        for org_id, deals in org_deals.items():
            try:
                organization = deals[0].organization
                
                # Get organization admins and verifiers
                recipients = User.objects.filter(
                    organization=organization,
                    is_active=True
                ).filter(
                    Q(role__name__icontains='admin') |
                    Q(role__permissions__codename='verify_deal_payment')
                ).distinct()
                
                if recipients.exists():
                    # Prepare reminder email
                    subject = f"Deal Verification Reminders - {organization.name}"
                    
                    deal_list = "\n".join([
                        f"- {deal.deal_id}: {deal.deal_name} (Client: {deal.client.client_name if deal.client else 'N/A'}, Value: {deal.deal_value} {deal.currency})"
                        for deal in deals
                    ])
                    
                    message = f"""
                    The following deals are pending verification for more than 24 hours:
                    
                    {deal_list}
                    
                    Please review and verify these deals at your earliest convenience.
                    
                    Total pending deals: {len(deals)}
                    Organization: {organization.name}
                    
                    Best regards,
                    PRS Automated System
                    """
                    
                    # Send to all recipients
                    recipient_emails = [user.email for user in recipients if user.email]
                    
                    if recipient_emails:
                        send_mail(
                            subject=subject,
                            message=message,
                            from_email=settings.DEFAULT_FROM_EMAIL,
                            recipient_list=recipient_emails,
                            fail_silently=False
                        )
                        
                        reminder_results['reminders_sent'] += len(deals)
                        reminder_results['organizations_notified'].add(organization.name)
                        
                        reminder_results['details'].append({
                            'organization': organization.name,
                            'deals_count': len(deals),
                            'recipients_count': len(recipient_emails),
                            'status': 'sent'
                        })
                        
                        logger.info(f"Verification reminders sent for {organization.name}: {len(deals)} deals")
                
            except Exception as e:
                reminder_results['failed_reminders'] += len(deals)
                reminder_results['details'].append({
                    'organization': deals[0].organization.name if deals else 'Unknown',
                    'deals_count': len(deals),
                    'status': 'failed',
                    'error': str(e)
                })
                logger.error(f"Failed to send verification reminders for organization {org_id}: {str(e)}")
        
        # Convert set to list for JSON serialization
        reminder_results['organizations_notified'] = list(reminder_results['organizations_notified'])
        
        AutomatedBusinessProcessManager.update_process_status(process_name, 'success', reminder_results)
        
        logger.info(f"Deal verification reminders completed: {reminder_results['reminders_sent']} reminders sent")
        return reminder_results
        
    except Exception as e:
        logger.error(f"Deal verification reminders failed: {str(e)}")
        AutomatedBusinessProcessManager.update_process_status("deal_verification_reminders", 'failed', {'error': str(e)})
        
        # Retry with exponential backoff
        if self.request.retries < self.max_retries:
            countdown = 2 ** self.request.retries
            logger.info(f"Retrying deal verification reminders in {countdown} seconds...")
            raise self.retry(countdown=countdown, exc=e)
        
        raise

# Automated Commission Calculation
@shared_task(bind=True, max_retries=3)
def automated_commission_calculation(self, organization_id=None):
    """
    Automated commission calculation processing
    """
    try:
        from deals.models import Deal
        from commission.models import Commission
        from organization.models import Organization
        
        logger.info("Starting automated commission calculation")
        
        process_name = "automated_commission_calculation"
        AutomatedBusinessProcessManager.update_process_status(process_name, 'running')
        
        # Get organizations to process
        if organization_id:
            organizations = Organization.objects.filter(id=organization_id, is_active=True)
        else:
            organizations = Organization.objects.filter(is_active=True)
        
        calculation_results = {
            'organizations_processed': 0,
            'commissions_calculated': 0,
            'commissions_updated': 0,
            'total_commission_amount': 0,
            'failed_calculations': 0,
            'details': []
        }
        
        for organization in organizations:
            try:
                org_result = {
                    'organization_id': organization.id,
                    'organization_name': organization.name,
                    'deals_processed': 0,
                    'commissions_calculated': 0,
                    'total_amount': 0
                }
                
                # Get verified deals that need commission calculation
                verified_deals = Deal.objects.filter(
                    organization=organization,
                    verification_status='verified',
                    payment_status='full_payment'
                ).select_related('client', 'created_by')
                
                for deal in verified_deals:
                    try:
                        # Check if commission already exists
                        existing_commission = Commission.objects.filter(deal=deal).first()
                        
                        if not existing_commission:
                            # Calculate commission (5% default rate)
                            commission_rate = 0.05
                            commission_amount = float(deal.deal_value) * commission_rate
                            
                            # Create commission record
                            commission = Commission.objects.create(
                                deal=deal,
                                organization=organization,
                                amount=commission_amount,
                                rate=commission_rate,
                                calculated_at=timezone.now(),
                                status='calculated'
                            )
                            
                            org_result['commissions_calculated'] += 1
                            org_result['total_amount'] += commission_amount
                            calculation_results['commissions_calculated'] += 1
                            calculation_results['total_commission_amount'] += commission_amount
                        
                        org_result['deals_processed'] += 1
                        
                    except Exception as e:
                        calculation_results['failed_calculations'] += 1
                        logger.error(f"Failed to calculate commission for deal {deal.deal_id}: {str(e)}")
                
                calculation_results['details'].append(org_result)
                calculation_results['organizations_processed'] += 1
                
                logger.info(f"Commission calculation completed for {organization.name}: {org_result['commissions_calculated']} commissions")
                
            except Exception as e:
                calculation_results['failed_calculations'] += 1
                logger.error(f"Failed to process commissions for organization {organization.id}: {str(e)}")
        
        AutomatedBusinessProcessManager.update_process_status(process_name, 'success', calculation_results)
        
        logger.info(f"Automated commission calculation completed: {calculation_results['commissions_calculated']} commissions calculated")
        return calculation_results
        
    except Exception as e:
        logger.error(f"Automated commission calculation failed: {str(e)}")
        AutomatedBusinessProcessManager.update_process_status("automated_commission_calculation", 'failed', {'error': str(e)})
        
        # Retry with exponential backoff
        if self.request.retries < self.max_retries:
            countdown = 2 ** self.request.retries
            logger.info(f"Retrying commission calculation in {countdown} seconds...")
            raise self.retry(countdown=countdown, exc=e)
        
        raise

# Background Audit Report Generation
@shared_task(bind=True, max_retries=3)
def generate_audit_report(self, organization_id=None, report_type='comprehensive', days=30):
    """
    Generate comprehensive audit reports in background
    """
    try:
        from deals.models import Deal, Payment, ActivityLog
        from apps.authentication.models import User, SecureUserSession
        from organization.models import Organization
        
        logger.info(f"Starting audit report generation: {report_type}")
        
        process_name = f"audit_report_{report_type}"
        AutomatedBusinessProcessManager.update_process_status(process_name, 'running')
        
        # Date range for report
        end_date = timezone.now()
        start_date = end_date - timedelta(days=days)
        
        # Get organization(s) to process
        if organization_id:
            organizations = Organization.objects.filter(id=organization_id, is_active=True)
        else:
            organizations = Organization.objects.filter(is_active=True)
        
        audit_report = {
            'report_type': report_type,
            'period_days': days,
            'start_date': start_date.isoformat(),
            'end_date': end_date.isoformat(),
            'generated_at': timezone.now().isoformat(),
            'organizations': [],
            'summary': {}
        }
        
        total_deals = 0
        total_payments = 0
        total_users = 0
        total_sessions = 0
        
        for organization in organizations:
            org_audit = {
                'organization_id': organization.id,
                'organization_name': organization.name,
                'deal_audit': {},
                'payment_audit': {},
                'user_audit': {},
                'security_audit': {}
            }
            
            # Deal audit
            deals = Deal.objects.filter(
                organization=organization,
                created_at__gte=start_date,
                created_at__lte=end_date
            )
            
            org_audit['deal_audit'] = {
                'total_deals': deals.count(),
                'verified_deals': deals.filter(verification_status='verified').count(),
                'pending_deals': deals.filter(verification_status='pending').count(),
                'rejected_deals': deals.filter(verification_status='rejected').count(),
                'total_value': deals.aggregate(total=Sum('deal_value'))['total'] or 0,
                'avg_deal_value': deals.aggregate(avg=Avg('deal_value'))['avg'] or 0,
                'deal_sources': list(deals.values('source_type').annotate(count=Count('id')).order_by('-count'))
            }
            
            # Payment audit
            payments = Payment.objects.filter(
                deal__organization=organization,
                created_at__gte=start_date,
                created_at__lte=end_date
            )
            
            org_audit['payment_audit'] = {
                'total_payments': payments.count(),
                'total_amount': payments.aggregate(total=Sum('received_amount'))['total'] or 0,
                'avg_payment': payments.aggregate(avg=Avg('received_amount'))['avg'] or 0,
                'payment_methods': list(payments.values('payment_type').annotate(count=Count('id')).order_by('-count'))
            }
            
            # User audit
            users = User.objects.filter(organization=organization)
            active_users = users.filter(is_active=True)
            
            org_audit['user_audit'] = {
                'total_users': users.count(),
                'active_users': active_users.count(),
                'inactive_users': users.filter(is_active=False).count(),
                'new_users_period': users.filter(
                    created_at__gte=start_date,
                    created_at__lte=end_date
                ).count(),
                'role_distribution': list(users.values('role__name').annotate(count=Count('id')).order_by('-count'))
            }
            
            # Security audit
            sessions = SecureUserSession.objects.filter(
                user__organization=organization,
                created_at__gte=start_date,
                created_at__lte=end_date
            )
            
            org_audit['security_audit'] = {
                'total_sessions': sessions.count(),
                'active_sessions': sessions.filter(is_active=True).count(),
                'expired_sessions': sessions.filter(expires_at__lt=timezone.now()).count(),
                'unique_users_logged_in': sessions.values('user').distinct().count()
            }
            
            audit_report['organizations'].append(org_audit)
            
            # Update totals
            total_deals += org_audit['deal_audit']['total_deals']
            total_payments += org_audit['payment_audit']['total_payments']
            total_users += org_audit['user_audit']['total_users']
            total_sessions += org_audit['security_audit']['total_sessions']
        
        # Generate summary
        audit_report['summary'] = {
            'total_organizations': len(organizations),
            'total_deals': total_deals,
            'total_payments': total_payments,
            'total_users': total_users,
            'total_sessions': total_sessions,
            'report_size_mb': len(json.dumps(audit_report)) / (1024 * 1024)
        }
        
        # Store report in cache for access
        from django.core.cache import cache
        report_key = f"audit_report:{report_type}:{organization_id or 'all'}:{days}"
        cache.set(report_key, audit_report, 86400)  # Cache for 24 hours
        
        AutomatedBusinessProcessManager.update_process_status(process_name, 'success', audit_report['summary'])
        
        logger.info(f"Audit report generation completed: {report_type}")
        return audit_report
        
    except Exception as e:
        logger.error(f"Audit report generation failed: {str(e)}")
        AutomatedBusinessProcessManager.update_process_status(f"audit_report_{report_type}", 'failed', {'error': str(e)})
        
        # Retry with exponential backoff
        if self.request.retries < self.max_retries:
            countdown = 2 ** self.request.retries
            logger.info(f"Retrying audit report generation in {countdown} seconds...")
            raise self.retry(countdown=countdown, exc=e)
        
        raise

# Automated Cleanup Tasks
@shared_task(bind=True, max_retries=3)
def cleanup_expired_sessions_and_tokens(self):
    """
    Clean up expired sessions and tokens
    """
    try:
        from apps.authentication.models import SecureUserSession, OTPToken
        
        logger.info("Starting cleanup of expired sessions and tokens")
        
        process_name = "cleanup_expired_sessions_tokens"
        AutomatedBusinessProcessManager.update_process_status(process_name, 'running')
        
        cleanup_results = {
            'expired_sessions_deleted': 0,
            'expired_tokens_deleted': 0,
            'old_activity_logs_deleted': 0,
            'temp_files_cleaned': 0,
            'details': {}
        }
        
        # Clean up expired sessions
        expired_sessions = SecureUserSession.objects.filter(
            expires_at__lt=timezone.now()
        )
        expired_sessions_count = expired_sessions.count()
        expired_sessions.delete()
        cleanup_results['expired_sessions_deleted'] = expired_sessions_count
        
        logger.info(f"Deleted {expired_sessions_count} expired sessions")
        
        # Clean up expired OTP tokens
        expired_tokens = OTPToken.objects.filter(
            expires_at__lt=timezone.now()
        )
        expired_tokens_count = expired_tokens.count()
        expired_tokens.delete()
        cleanup_results['expired_tokens_deleted'] = expired_tokens_count
        
        logger.info(f"Deleted {expired_tokens_count} expired OTP tokens")
        
        # Clean up old activity logs (older than 90 days)
        from deals.models import ActivityLog
        old_logs_cutoff = timezone.now() - timedelta(days=90)
        old_logs = ActivityLog.objects.filter(timestamp__lt=old_logs_cutoff)
        old_logs_count = old_logs.count()
        old_logs.delete()
        cleanup_results['old_activity_logs_deleted'] = old_logs_count
        
        logger.info(f"Deleted {old_logs_count} old activity logs")
        
        # Clean up temporary files
        import tempfile
        import os
        
        temp_files_cleaned = 0
        temp_dir = tempfile.gettempdir()
        
        try:
            for filename in os.listdir(temp_dir):
                if filename.startswith('prs_temp_'):
                    file_path = os.path.join(temp_dir, filename)
                    file_age = timezone.now().timestamp() - os.path.getmtime(file_path)
                    
                    # Delete files older than 24 hours
                    if file_age > 86400:
                        os.remove(file_path)
                        temp_files_cleaned += 1
            
            cleanup_results['temp_files_cleaned'] = temp_files_cleaned
            logger.info(f"Cleaned {temp_files_cleaned} temporary files")
            
        except Exception as e:
            logger.warning(f"Failed to clean temporary files: {str(e)}")
            cleanup_results['temp_files_error'] = str(e)
        
        # Additional cleanup details
        cleanup_results['details'] = {
            'session_cleanup': {
                'expired_sessions': expired_sessions_count,
                'cleanup_time': timezone.now().isoformat()
            },
            'token_cleanup': {
                'expired_tokens': expired_tokens_count,
                'cleanup_time': timezone.now().isoformat()
            },
            'log_cleanup': {
                'old_logs_deleted': old_logs_count,
                'cutoff_date': old_logs_cutoff.isoformat()
            }
        }
        
        AutomatedBusinessProcessManager.update_process_status(process_name, 'success', cleanup_results)
        
        total_cleaned = (expired_sessions_count + expired_tokens_count + 
                        old_logs_count + temp_files_cleaned)
        
        logger.info(f"Cleanup completed: {total_cleaned} items cleaned")
        return cleanup_results
        
    except Exception as e:
        logger.error(f"Cleanup of expired sessions and tokens failed: {str(e)}")
        AutomatedBusinessProcessManager.update_process_status("cleanup_expired_sessions_tokens", 'failed', {'error': str(e)})
        
        # Retry with exponential backoff
        if self.request.retries < self.max_retries:
            countdown = 2 ** self.request.retries
            logger.info(f"Retrying cleanup in {countdown} seconds...")
            raise self.retry(countdown=countdown, exc=e)
        
        raise

# Automated System Health Check
@shared_task(bind=True, max_retries=3)
def system_health_check(self):
    """
    Perform automated system health check
    """
    try:
        from django.db import connection
        from django.core.cache import cache
        
        logger.info("Starting system health check")
        
        process_name = "system_health_check"
        AutomatedBusinessProcessManager.update_process_status(process_name, 'running')
        
        health_report = {
            'timestamp': timezone.now().isoformat(),
            'overall_status': 'healthy',
            'checks': {},
            'warnings': [],
            'errors': []
        }
        
        # Database health check
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                result = cursor.fetchone()
                
            health_report['checks']['database'] = {
                'status': 'healthy',
                'response_time_ms': 0,  # Would measure actual response time
                'connection_count': len(connection.queries)
            }
            
        except Exception as e:
            health_report['checks']['database'] = {
                'status': 'unhealthy',
                'error': str(e)
            }
            health_report['errors'].append(f"Database check failed: {str(e)}")
            health_report['overall_status'] = 'unhealthy'
        
        # Cache health check
        try:
            test_key = 'health_check_test'
            test_value = 'test_value'
            
            cache.set(test_key, test_value, 60)
            retrieved_value = cache.get(test_key)
            cache.delete(test_key)
            
            if retrieved_value == test_value:
                health_report['checks']['cache'] = {
                    'status': 'healthy',
                    'backend': str(cache.__class__)
                }
            else:
                health_report['checks']['cache'] = {
                    'status': 'unhealthy',
                    'error': 'Cache read/write test failed'
                }
                health_report['warnings'].append("Cache read/write test failed")
                
        except Exception as e:
            health_report['checks']['cache'] = {
                'status': 'unhealthy',
                'error': str(e)
            }
            health_report['errors'].append(f"Cache check failed: {str(e)}")
            health_report['overall_status'] = 'unhealthy'
        
        # Celery health check
        try:
            from celery import current_app
            
            inspect = current_app.control.inspect()
            stats = inspect.stats()
            
            if stats:
                health_report['checks']['celery'] = {
                    'status': 'healthy',
                    'workers': len(stats),
                    'worker_stats': stats
                }
            else:
                health_report['checks']['celery'] = {
                    'status': 'warning',
                    'message': 'No Celery workers detected'
                }
                health_report['warnings'].append("No Celery workers detected")
                
        except Exception as e:
            health_report['checks']['celery'] = {
                'status': 'unhealthy',
                'error': str(e)
            }
            health_report['warnings'].append(f"Celery check failed: {str(e)}")
        
        # File system health check
        try:
            import tempfile
            import os
            
            # Test file write/read
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_file.write(b'health check test')
                temp_file_path = temp_file.name
            
            with open(temp_file_path, 'rb') as temp_file:
                content = temp_file.read()
            
            os.unlink(temp_file_path)
            
            if content == b'health check test':
                health_report['checks']['filesystem'] = {
                    'status': 'healthy',
                    'temp_dir': tempfile.gettempdir()
                }
            else:
                health_report['checks']['filesystem'] = {
                    'status': 'unhealthy',
                    'error': 'File system read/write test failed'
                }
                health_report['errors'].append("File system read/write test failed")
                health_report['overall_status'] = 'unhealthy'
                
        except Exception as e:
            health_report['checks']['filesystem'] = {
                'status': 'unhealthy',
                'error': str(e)
            }
            health_report['errors'].append(f"File system check failed: {str(e)}")
            health_report['overall_status'] = 'unhealthy'
        
        # Determine overall status
        if health_report['errors']:
            health_report['overall_status'] = 'unhealthy'
        elif health_report['warnings']:
            health_report['overall_status'] = 'warning'
        
        # Store health report
        cache.set('system_health_report', health_report, 300)  # Cache for 5 minutes
        
        AutomatedBusinessProcessManager.update_process_status(process_name, 'success', {
            'overall_status': health_report['overall_status'],
            'checks_passed': len([c for c in health_report['checks'].values() if c['status'] == 'healthy']),
            'total_checks': len(health_report['checks']),
            'warnings': len(health_report['warnings']),
            'errors': len(health_report['errors'])
        })
        
        logger.info(f"System health check completed: {health_report['overall_status']}")
        return health_report
        
    except Exception as e:
        logger.error(f"System health check failed: {str(e)}")
        AutomatedBusinessProcessManager.update_process_status("system_health_check", 'failed', {'error': str(e)})
        
        # Retry with exponential backoff
        if self.request.retries < self.max_retries:
            countdown = 2 ** self.request.retries
            logger.info(f"Retrying system health check in {countdown} seconds...")
            raise self.retry(countdown=countdown, exc=e)
        
        raise


# Periodic task configuration for automated business processes
AUTOMATED_BUSINESS_PROCESSES_TASKS = {
    'deal-verification-reminders': {
        'task': 'core_config.automated_business_processes.send_deal_verification_reminders',
        'schedule': 86400.0,  # Run daily
        'options': {'queue': 'business_processes'}
    },
    'automated-commission-calculation': {
        'task': 'core_config.automated_business_processes.automated_commission_calculation',
        'schedule': 21600.0,  # Run every 6 hours
        'options': {'queue': 'business_processes'}
    },
    'generate-audit-report': {
        'task': 'core_config.automated_business_processes.generate_audit_report',
        'schedule': 604800.0,  # Run weekly
        'options': {'queue': 'reports'}
    },
    'cleanup-expired-sessions-tokens': {
        'task': 'core_config.automated_business_processes.cleanup_expired_sessions_and_tokens',
        'schedule': 3600.0,  # Run hourly
        'options': {'queue': 'maintenance'}
    },
    'system-health-check': {
        'task': 'core_config.automated_business_processes.system_health_check',
        'schedule': 300.0,  # Run every 5 minutes
        'options': {'queue': 'monitoring'}
    }
}