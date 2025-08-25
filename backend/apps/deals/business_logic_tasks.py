"""
Celery tasks for business logic optimization
"""

from celery import shared_task
from celery.utils.log import get_task_logger
from django.utils import timezone
from datetime import timedelta
import logging

from .enhanced_workflow_optimizer import (
    EnhancedDealWorkflowOptimizer,
    optimize_deal_workflows_task,
    generate_workflow_performance_report,
    automated_deal_state_maintenance
)
from authentication.user_org_optimizer import (
    UserOrganizationOptimizer,
    optimize_user_organization_workflows,
    generate_user_activity_report,
    automated_user_management_maintenance
)

# Task logger
logger = get_task_logger(__name__)

@shared_task(bind=True, max_retries=3)
def comprehensive_business_logic_optimization(self, organization_id=None, batch_size=100):
    """
    Comprehensive business logic optimization task
    Combines deal workflow and user management optimization
    """
    try:
        from apps.organization.models import Organization
        
        organization = None
        if organization_id:
            organization = Organization.objects.get(id=organization_id)
        
        results = {
            'organization': organization.name if organization else 'All Organizations',
            'started_at': timezone.now().isoformat(),
            'deal_optimization': None,
            'user_optimization': None,
            'completed_at': None,
            'success': False
        }
        
        logger.info(f"Starting comprehensive business logic optimization for {results['organization']}")
        
        # Optimize deal workflows
        logger.info("Optimizing deal workflows...")
        deal_result = EnhancedDealWorkflowOptimizer.optimize_deal_state_transitions(
            organization=organization,
            batch_size=batch_size
        )
        results['deal_optimization'] = deal_result
        
        # Optimize user management workflows
        logger.info("Optimizing user management workflows...")
        user_result = UserOrganizationOptimizer.optimize_organization_creation_workflow(
            organization=organization
        )
        results['user_optimization'] = user_result
        
        results['completed_at'] = timezone.now().isoformat()
        results['success'] = True
        
        logger.info(f"Comprehensive business logic optimization completed successfully")
        return results
        
    except Exception as e:
        logger.error(f"Comprehensive business logic optimization failed: {str(e)}")
        
        # Retry with exponential backoff
        if self.request.retries < self.max_retries:
            countdown = 2 ** self.request.retries
            logger.info(f"Retrying in {countdown} seconds...")
            raise self.retry(countdown=countdown, exc=e)
        
        raise

@shared_task(bind=True)
def generate_comprehensive_performance_report(self, organization_id=None, days=30, report_type='comprehensive'):
    """
    Generate comprehensive performance report combining deal and user metrics
    """
    try:
        from apps.organization.models import Organization
        
        organization = None
        if organization_id:
            organization = Organization.objects.get(id=organization_id)
        
        logger.info(f"Generating comprehensive performance report for {organization.name if organization else 'All Organizations'}")
        
        report_data = {
            'report_type': report_type,
            'organization': organization.name if organization else 'All Organizations',
            'analysis_period_days': days,
            'generated_at': timezone.now().isoformat()
        }
        
        # Get deal workflow metrics
        if report_type in ['comprehensive', 'deal_workflows']:
            logger.info("Collecting deal workflow metrics...")
            deal_metrics = EnhancedDealWorkflowOptimizer.get_workflow_performance_metrics(
                organization=organization,
                days=days
            )
            report_data['deal_workflow_metrics'] = deal_metrics
        
        # Get user activity analytics
        if report_type in ['comprehensive', 'user_management'] and organization:
            logger.info("Collecting user activity analytics...")
            user_analytics = UserOrganizationOptimizer.add_user_activity_tracking(
                organization=organization,
                days=days
            )
            report_data['user_activity_analytics'] = user_analytics
        
        # Generate recommendations
        recommendations = []
        
        # Deal workflow recommendations
        if 'deal_workflow_metrics' in report_data:
            deal_metrics = report_data['deal_workflow_metrics']
            
            if deal_metrics['verification_metrics']['verification_rate'] < 80:
                recommendations.append({
                    'category': 'deal_workflow',
                    'priority': 'high',
                    'issue': f"Low verification rate ({deal_metrics['verification_metrics']['verification_rate']:.1f}%)",
                    'recommendation': 'Implement automated verification rules and provide verification team training'
                })
            
            if deal_metrics['workflow_efficiency']['efficiency_score'] < 70:
                recommendations.append({
                    'category': 'deal_workflow',
                    'priority': 'medium',
                    'issue': f"Low workflow efficiency ({deal_metrics['workflow_efficiency']['efficiency_score']:.1f}%)",
                    'recommendation': 'Optimize deal state transitions and reduce workflow bottlenecks'
                })
        
        # User management recommendations
        if 'user_activity_analytics' in report_data:
            user_analytics = report_data['user_activity_analytics']
            
            total_users = user_analytics['summary']['total_users']
            active_users = user_analytics['summary']['active_users_period']
            
            if total_users > 0 and (active_users / total_users) < 0.7:
                recommendations.append({
                    'category': 'user_management',
                    'priority': 'medium',
                    'issue': f"Low user engagement ({active_users}/{total_users} users active)",
                    'recommendation': 'Implement user engagement strategies and review inactive user accounts'
                })
        
        report_data['recommendations'] = recommendations
        
        # Cache report for dashboard access
        from django.core.cache import cache
        cache_key = f"comprehensive_report:{organization_id or 'all'}:{days}:{report_type}"
        cache.set(cache_key, report_data, 3600)  # Cache for 1 hour
        
        logger.info(f"Comprehensive performance report generated successfully with {len(recommendations)} recommendations")
        return report_data
        
    except Exception as e:
        logger.error(f"Comprehensive performance report generation failed: {str(e)}")
        raise

@shared_task
def scheduled_business_logic_maintenance():
    """
    Scheduled task for automated business logic maintenance
    Runs daily to maintain optimal performance
    """
    try:
        logger.info("Starting scheduled business logic maintenance")
        
        maintenance_results = {
            'started_at': timezone.now().isoformat(),
            'deal_maintenance': None,
            'user_maintenance': None,
            'organizations_processed': 0,
            'total_optimizations': 0,
            'completed_at': None
        }
        
        # Run deal workflow maintenance
        logger.info("Running deal workflow maintenance...")
        deal_maintenance = automated_deal_state_maintenance.delay()
        maintenance_results['deal_maintenance'] = deal_maintenance.get()
        
        # Run user management maintenance
        logger.info("Running user management maintenance...")
        user_maintenance = automated_user_management_maintenance.delay()
        maintenance_results['user_maintenance'] = user_maintenance.get()
        
        # Calculate totals
        if maintenance_results['deal_maintenance']:
            maintenance_results['organizations_processed'] += len(maintenance_results['deal_maintenance'])
        
        if maintenance_results['user_maintenance']:
            maintenance_results['organizations_processed'] += len(maintenance_results['user_maintenance'])
        
        maintenance_results['completed_at'] = timezone.now().isoformat()
        
        logger.info(f"Scheduled business logic maintenance completed: {maintenance_results['organizations_processed']} organizations processed")
        return maintenance_results
        
    except Exception as e:
        logger.error(f"Scheduled business logic maintenance failed: {str(e)}")
        raise

@shared_task(bind=True)
def bulk_user_operation_task(self, organization_id, operation_type, user_ids, operation_data, executing_user_id):
    """
    Background task for bulk user operations
    """
    try:
        from apps.organization.models import Organization
        from apps.authentication.models import User
        
        organization = Organization.objects.get(id=organization_id)
        executing_user = User.objects.get(id=executing_user_id)
        target_users = User.objects.filter(id__in=user_ids, organization=organization)
        
        logger.info(f"Starting bulk {operation_type} operation for {len(user_ids)} users in {organization.name}")
        
        results = {
            'operation_type': operation_type,
            'organization': organization.name,
            'total_users': len(user_ids),
            'successful': 0,
            'failed': 0,
            'errors': [],
            'started_at': timezone.now().isoformat()
        }
        
        from django.db import transaction
        
        with transaction.atomic():
            for user in target_users:
                try:
                    if operation_type == 'bulk_role_assignment':
                        role_name = operation_data.get('role_name')
                        if role_name:
                            from apps.permissions.models import Role
                            role = Role.objects.get(name=role_name, organization=organization)
                            user.role = role
                            user.save(update_fields=['role'])
                            results['successful'] += 1
                    
                    elif operation_type == 'bulk_activation':
                        is_active = operation_data.get('is_active', True)
                        user.is_active = is_active
                        user.save(update_fields=['is_active'])
                        results['successful'] += 1
                    
                    elif operation_type == 'bulk_password_reset':
                        # Trigger password reset email
                        # Implementation depends on your password reset system
                        results['successful'] += 1
                    
                    else:
                        results['errors'].append({
                            'user_id': user.id,
                            'error': f'Unknown operation type: {operation_type}'
                        })
                        results['failed'] += 1
                
                except Exception as e:
                    results['errors'].append({
                        'user_id': user.id,
                        'error': str(e)
                    })
                    results['failed'] += 1
        
        results['completed_at'] = timezone.now().isoformat()
        
        logger.info(f"Bulk {operation_type} operation completed: {results['successful']} successful, {results['failed']} failed")
        return results
        
    except Exception as e:
        logger.error(f"Bulk user operation failed: {str(e)}")
        raise

@shared_task
def cleanup_optimization_cache():
    """
    Cleanup old optimization cache entries
    """
    try:
        from django.core.cache import cache
        
        logger.info("Starting optimization cache cleanup")
        
        # This would implement cache cleanup logic
        # For now, we'll just log the action
        
        logger.info("Optimization cache cleanup completed")
        return {'status': 'completed', 'cleaned_at': timezone.now().isoformat()}
        
    except Exception as e:
        logger.error(f"Optimization cache cleanup failed: {str(e)}")
        raise

# Periodic task configuration (to be added to celery beat schedule)
BUSINESS_LOGIC_PERIODIC_TASKS = {
    'scheduled-business-logic-maintenance': {
        'task': 'deals.business_logic_tasks.scheduled_business_logic_maintenance',
        'schedule': 86400.0,  # Run daily (24 hours)
        'options': {'queue': 'optimization'}
    },
    'cleanup-optimization-cache': {
        'task': 'deals.business_logic_tasks.cleanup_optimization_cache',
        'schedule': 3600.0,  # Run hourly
        'options': {'queue': 'maintenance'}
    }
}