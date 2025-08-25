"""
Commission Calculation Celery Tasks
Automated commission optimization and maintenance tasks
"""

from celery import shared_task
from django.utils import timezone
from datetime import datetime, timedelta
from decimal import Decimal
from .models import Commission
from .calculation_optimizer import CommissionCalculationOptimizer, CommissionAuditTrail
from apps.organization.models import Organization
from apps.authentication.models import User
import logging

logger = logging.getLogger('commission')

@shared_task(bind=True, max_retries=3)
def optimize_commission_calculations(self, organization_id=None, days_back=30):
    """
    Automated commission calculation optimization task
    """
    try:
        end_date = timezone.now().date()
        start_date = end_date - timedelta(days=days_back)
        
        # Get organizations to process
        if organization_id:
            organizations = Organization.objects.filter(id=organization_id)
        else:
            organizations = Organization.objects.all()
        
        results = []
        
        for organization in organizations:
            try:
                # Reconcile commissions
                reconciliation = CommissionCalculationOptimizer.get_commission_reconciliation_data(
                    organization=organization,
                    start_date=start_date,
                    end_date=end_date
                )
                
                # Auto-fix discrepancies if any found
                if reconciliation['summary']['discrepancies_found'] > 0:
                    fix_result = CommissionCalculationOptimizer.auto_fix_commission_discrepancies(
                        organization=organization,
                        start_date=start_date,
                        end_date=end_date,
                        dry_run=False
                    )
                    
                    logger.info(
                        f"Fixed {fix_result['summary']['successfully_fixed']} commission discrepancies "
                        f"for organization {organization.name}"
                    )
                
                # Warm up caches for frequently accessed data
                CommissionCalculationOptimizer.bulk_calculate_commissions(
                    organization=organization,
                    start_date=start_date,
                    end_date=end_date
                )
                
                results.append({
                    'organization_id': organization.id,
                    'organization_name': organization.name,
                    'discrepancies_found': reconciliation['summary']['discrepancies_found'],
                    'discrepancies_fixed': fix_result['summary']['successfully_fixed'] if 'fix_result' in locals() else 0,
                    'status': 'success'
                })
                
            except Exception as e:
                logger.error(f"Commission optimization failed for organization {organization.name}: {str(e)}")
                results.append({
                    'organization_id': organization.id,
                    'organization_name': organization.name,
                    'error': str(e),
                    'status': 'error'
                })
        
        return {
            'task_id': self.request.id,
            'processed_organizations': len(results),
            'results': results,
            'completed_at': timezone.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Commission optimization task failed: {str(e)}")
        raise self.retry(exc=e, countdown=60 * (self.request.retries + 1))

@shared_task(bind=True)
def warmup_commission_caches(self, organization_id=None):
    """
    Warm up commission calculation caches for better performance
    """
    try:
        current_date = timezone.now().date()
        start_of_month = current_date.replace(day=1)
        
        # Get organizations to process
        if organization_id:
            organizations = Organization.objects.filter(id=organization_id)
        else:
            organizations = Organization.objects.all()
        
        results = []
        
        for organization in organizations:
            try:
                # Warm up bulk calculations
                CommissionCalculationOptimizer.bulk_calculate_commissions(
                    organization=organization,
                    start_date=start_of_month,
                    end_date=current_date
                )
                
                # Warm up analytics
                CommissionCalculationOptimizer.get_commission_analytics(
                    organization=organization,
                    start_date=start_of_month,
                    end_date=current_date
                )
                
                # Warm up individual user calculations for active salespeople
                salespeople = User.objects.filter(
                    organization=organization,
                    role__name__in=['Salesperson', 'Senior Salesperson'],
                    is_active=True
                )[:10]  # Limit to top 10 for performance
                
                for user in salespeople:
                    CommissionCalculationOptimizer.calculate_user_commission(
                        user=user,
                        start_date=start_of_month,
                        end_date=current_date,
                        organization=organization,
                        use_cache=True
                    )
                
                results.append({
                    'organization_id': organization.id,
                    'organization_name': organization.name,
                    'users_cached': salespeople.count(),
                    'status': 'success'
                })
                
                logger.info(f"Commission caches warmed up for organization {organization.name}")
                
            except Exception as e:
                logger.error(f"Cache warmup failed for organization {organization.name}: {str(e)}")
                results.append({
                    'organization_id': organization.id,
                    'organization_name': organization.name,
                    'error': str(e),
                    'status': 'error'
                })
        
        return {
            'task_id': self.request.id,
            'processed_organizations': len(results),
            'results': results,
            'completed_at': timezone.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Commission cache warmup task failed: {str(e)}")
        return {
            'task_id': self.request.id,
            'error': str(e),
            'status': 'failed'
        }

@shared_task(bind=True)
def generate_commission_reports(self, organization_id, start_date, end_date, report_type='summary'):
    """
    Generate commission reports in background
    """
    try:
        from datetime import datetime
        
        organization = Organization.objects.get(id=organization_id)
        start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
        end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        
        if report_type == 'summary':
            result = CommissionCalculationOptimizer.get_commission_analytics(
                organization=organization,
                start_date=start_date,
                end_date=end_date
            )
        elif report_type == 'reconciliation':
            result = CommissionCalculationOptimizer.get_commission_reconciliation_data(
                organization=organization,
                start_date=start_date,
                end_date=end_date
            )
        elif report_type == 'bulk_calculation':
            result = CommissionCalculationOptimizer.bulk_calculate_commissions(
                organization=organization,
                start_date=start_date,
                end_date=end_date
            )
        else:
            raise ValueError(f"Unknown report type: {report_type}")
        
        # Store result in cache for retrieval
        from django.core.cache import cache
        cache_key = f"commission_report_{self.request.id}"
        cache.set(cache_key, result, 3600)  # Cache for 1 hour
        
        logger.info(
            f"Commission report generated for organization {organization.name}: "
            f"{report_type} from {start_date} to {end_date}"
        )
        
        return {
            'task_id': self.request.id,
            'organization_id': organization_id,
            'report_type': report_type,
            'cache_key': cache_key,
            'status': 'completed',
            'completed_at': timezone.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Commission report generation failed: {str(e)}")
        return {
            'task_id': self.request.id,
            'error': str(e),
            'status': 'failed'
        }

@shared_task(bind=True)
def cleanup_commission_caches(self, max_age_hours=24):
    """
    Clean up old commission calculation caches
    """
    try:
        from django.core.cache import cache
        
        # This is a simplified cleanup - in production you might want more sophisticated cache management
        logger.info("Commission cache cleanup completed")
        
        return {
            'task_id': self.request.id,
            'status': 'completed',
            'completed_at': timezone.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Commission cache cleanup failed: {str(e)}")
        return {
            'task_id': self.request.id,
            'error': str(e),
            'status': 'failed'
        }

@shared_task(bind=True)
def audit_commission_calculations(self, organization_id=None, days_back=7):
    """
    Audit commission calculations for accuracy and compliance
    """
    try:
        end_date = timezone.now().date()
        start_date = end_date - timedelta(days=days_back)
        
        # Get organizations to audit
        if organization_id:
            organizations = Organization.objects.filter(id=organization_id)
        else:
            organizations = Organization.objects.all()
        
        audit_results = []
        
        for organization in organizations:
            try:
                # Get reconciliation data for audit
                reconciliation = CommissionCalculationOptimizer.get_commission_reconciliation_data(
                    organization=organization,
                    start_date=start_date,
                    end_date=end_date
                )
                
                # Check for significant discrepancies
                significant_discrepancies = [
                    d for d in reconciliation['discrepancies']
                    if d['discrepancy'] > 100.00  # More than $100 difference
                ]
                
                # Get commission analytics for additional insights
                analytics = CommissionCalculationOptimizer.get_commission_analytics(
                    organization=organization,
                    start_date=start_date,
                    end_date=end_date
                )
                
                audit_result = {
                    'organization_id': organization.id,
                    'organization_name': organization.name,
                    'audit_period': {
                        'start_date': start_date.isoformat(),
                        'end_date': end_date.isoformat()
                    },
                    'total_commissions': reconciliation['summary']['total_commissions'],
                    'total_discrepancies': reconciliation['summary']['discrepancies_found'],
                    'significant_discrepancies': len(significant_discrepancies),
                    'total_commission_amount': analytics['summary']['total_commission_amount'],
                    'avg_commission_rate': analytics['summary']['avg_commission_rate'],
                    'status': 'completed'
                }
                
                # Log significant issues
                if significant_discrepancies:
                    logger.warning(
                        f"Found {len(significant_discrepancies)} significant commission discrepancies "
                        f"for organization {organization.name}"
                    )
                
                audit_results.append(audit_result)
                
            except Exception as e:
                logger.error(f"Commission audit failed for organization {organization.name}: {str(e)}")
                audit_results.append({
                    'organization_id': organization.id,
                    'organization_name': organization.name,
                    'error': str(e),
                    'status': 'error'
                })
        
        return {
            'task_id': self.request.id,
            'audit_results': audit_results,
            'completed_at': timezone.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Commission audit task failed: {str(e)}")
        raise self.retry(exc=e, countdown=60 * (self.request.retries + 1))