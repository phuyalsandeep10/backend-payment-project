"""
Enhanced Deal Workflow Optimizer
Optimizes deal state machine transitions with proper validation and background processing
"""

from django.db import transaction, models
from django.utils import timezone
from django.core.cache import cache
from django.db.models import Q, Count, Avg, Sum, F, Case, When
from django.db.models.functions import Extract, TruncDate
from celery import shared_task
from datetime import datetime, timedelta
from decimal import Decimal
import logging
from typing import Dict, List, Optional, Tuple, Any

from .models import Deal, Payment, ActivityLog
from apps.authentication.models import User
from core_config.query_performance_middleware import monitor_org_query_performance

# Performance logger
performance_logger = logging.getLogger('performance')

class EnhancedDealWorkflowOptimizer:
    """
    Enhanced workflow optimizer with state machine validation and performance monitoring
    """
    
    # Cache keys for workflow optimization
    WORKFLOW_CACHE_PREFIX = "deal_workflow"
    PERFORMANCE_CACHE_TTL = 300  # 5 minutes
    
    @classmethod
    @monitor_org_query_performance
    def optimize_deal_state_transitions(cls, organization=None, batch_size=100):
        """
        Optimize deal state machine transitions with proper validation
        """
        optimization_results = {
            'processed_deals': 0,
            'optimized_transitions': 0,
            'validation_errors': [],
            'performance_improvements': {},
            'recommendations': []
        }
        
        # Get deals that need state optimization
        base_query = Deal.objects.select_related('client', 'organization', 'created_by')
        
        if organization:
            base_query = base_query.filter(organization=organization)
        
        # Find deals with inconsistent states
        inconsistent_deals = cls._find_inconsistent_deal_states(base_query)
        
        # Process deals in batches for better performance
        for i in range(0, len(inconsistent_deals), batch_size):
            batch = inconsistent_deals[i:i + batch_size]
            batch_results = cls._process_deal_batch(batch)
            
            optimization_results['processed_deals'] += len(batch)
            optimization_results['optimized_transitions'] += batch_results['optimized_count']
            optimization_results['validation_errors'].extend(batch_results['errors'])
        
        # Generate performance recommendations
        optimization_results['recommendations'] = cls._generate_workflow_recommendations(
            organization, optimization_results
        )
        
        # Cache results for dashboard
        cache_key = f"{cls.WORKFLOW_CACHE_PREFIX}:optimization:{organization.id if organization else 'all'}"
        cache.set(cache_key, optimization_results, cls.PERFORMANCE_CACHE_TTL)
        
        performance_logger.info(
            f"Deal workflow optimization completed: {optimization_results['processed_deals']} deals processed, "
            f"{optimization_results['optimized_transitions']} transitions optimized"
        )
        
        return optimization_results
    
    @classmethod
    def _find_inconsistent_deal_states(cls, base_query):
        """
        Find deals with inconsistent state machine states
        """
        inconsistent_deals = []
        
        # Check payment status inconsistencies
        for deal in base_query.prefetch_related('payments'):
            total_paid = deal.get_total_paid_amount()
            deal_value = float(deal.deal_value)
            
            # Determine correct payment status
            if total_paid == 0:
                correct_status = 'initial payment'
            elif abs(total_paid - deal_value) <= 0.01:
                correct_status = 'full_payment'
            else:
                correct_status = 'partial_payment'
            
            # Check if current status is incorrect
            if deal.payment_status != correct_status:
                inconsistent_deals.append({
                    'deal': deal,
                    'issue_type': 'payment_status_mismatch',
                    'current_status': deal.payment_status,
                    'correct_status': correct_status,
                    'total_paid': total_paid,
                    'deal_value': deal_value
                })
        
        # Check verification status inconsistencies
        verification_issues = base_query.filter(
            Q(verification_status='verified', payments__isnull=True) |
            Q(verification_status='pending', created_at__lt=timezone.now() - timedelta(days=7))
        ).distinct()
        
        for deal in verification_issues:
            if not deal.payments.exists() and deal.verification_status == 'verified':
                inconsistent_deals.append({
                    'deal': deal,
                    'issue_type': 'verified_without_payments',
                    'current_status': deal.verification_status,
                    'recommendation': 'Review verification or add payment records'
                })
            elif deal.verification_status == 'pending' and deal.created_at < timezone.now() - timedelta(days=7):
                inconsistent_deals.append({
                    'deal': deal,
                    'issue_type': 'long_pending_verification',
                    'current_status': deal.verification_status,
                    'days_pending': (timezone.now() - deal.created_at).days
                })
        
        return inconsistent_deals
    
    @classmethod
    def _process_deal_batch(cls, batch):
        """
        Process a batch of deals for state optimization
        """
        results = {
            'optimized_count': 0,
            'errors': []
        }
        
        with transaction.atomic():
            for deal_info in batch:
                try:
                    deal = deal_info['deal']
                    issue_type = deal_info['issue_type']
                    
                    if issue_type == 'payment_status_mismatch':
                        # Update payment status
                        old_status = deal.payment_status
                        new_status = deal_info['correct_status']
                        
                        # Validate transition
                        if deal.can_transition_payment_status(new_status):
                            deal.payment_status = new_status
                            deal.save(update_fields=['payment_status', 'updated_at'])
                            
                            # Log the optimization
                            ActivityLog.objects.create(
                                deal=deal,
                                message=f"Auto-optimized payment status from '{old_status}' to '{new_status}' "
                                       f"(Total paid: {deal_info['total_paid']}, Deal value: {deal_info['deal_value']})"
                            )
                            
                            results['optimized_count'] += 1
                        else:
                            results['errors'].append({
                                'deal_id': deal.deal_id,
                                'error': f"Invalid payment status transition from '{old_status}' to '{new_status}'"
                            })
                    
                    elif issue_type == 'long_pending_verification':
                        # Flag for manual review
                        ActivityLog.objects.create(
                            deal=deal,
                            message=f"Deal pending verification for {deal_info['days_pending']} days - requires manual review"
                        )
                        results['optimized_count'] += 1
                
                except Exception as e:
                    results['errors'].append({
                        'deal_id': deal_info['deal'].deal_id,
                        'error': str(e)
                    })
        
        return results
    
    @classmethod
    def _generate_workflow_recommendations(cls, organization, optimization_results):
        """
        Generate workflow optimization recommendations
        """
        recommendations = []
        
        # Analyze error patterns
        error_types = {}
        for error in optimization_results['validation_errors']:
            error_type = error.get('error', 'unknown')
            error_types[error_type] = error_types.get(error_type, 0) + 1
        
        if error_types:
            recommendations.append({
                'type': 'validation_errors',
                'priority': 'high',
                'description': f"Found {len(optimization_results['validation_errors'])} validation errors",
                'details': error_types,
                'action': 'Review and fix validation errors in deal state transitions'
            })
        
        # Check optimization ratio
        if optimization_results['processed_deals'] > 0:
            optimization_ratio = optimization_results['optimized_transitions'] / optimization_results['processed_deals']
            
            if optimization_ratio > 0.1:  # More than 10% of deals needed optimization
                recommendations.append({
                    'type': 'high_inconsistency',
                    'priority': 'medium',
                    'description': f"{optimization_ratio:.1%} of deals had inconsistent states",
                    'action': 'Implement automated state validation in deal creation/update workflows'
                })
        
        return recommendations
    
    @classmethod
    @monitor_org_query_performance
    def get_workflow_performance_metrics(cls, organization=None, days=30):
        """
        Get comprehensive workflow performance metrics
        """
        cache_key = f"{cls.WORKFLOW_CACHE_PREFIX}:metrics:{organization.id if organization else 'all'}:{days}"
        cached_metrics = cache.get(cache_key)
        
        if cached_metrics:
            return cached_metrics
        
        base_query = Deal.objects.filter(
            created_at__gte=timezone.now() - timedelta(days=days)
        )
        
        if organization:
            base_query = base_query.filter(organization=organization)
        
        # Calculate comprehensive metrics
        metrics = {
            'total_deals': base_query.count(),
            'verification_metrics': cls._calculate_verification_metrics(base_query),
            'payment_metrics': cls._calculate_payment_metrics(base_query),
            'workflow_efficiency': cls._calculate_workflow_efficiency(base_query),
            'bottleneck_analysis': cls._analyze_workflow_bottlenecks(base_query),
            'trend_analysis': cls._calculate_workflow_trends(base_query, days),
            'generated_at': timezone.now().isoformat()
        }
        
        # Cache metrics
        cache.set(cache_key, metrics, cls.PERFORMANCE_CACHE_TTL)
        
        return metrics
    
    @classmethod
    def _calculate_verification_metrics(cls, base_query):
        """
        Calculate verification workflow metrics
        """
        verification_stats = base_query.aggregate(
            total=Count('id'),
            verified=Count('id', filter=Q(verification_status='verified')),
            pending=Count('id', filter=Q(verification_status='pending')),
            rejected=Count('id', filter=Q(verification_status='rejected'))
        )
        
        # Calculate average verification time
        verified_deals = base_query.filter(
            verification_status='verified',
            activity_logs__message__icontains='Verification status changed'
        ).prefetch_related('activity_logs')
        
        verification_times = []
        for deal in verified_deals:
            verification_log = deal.activity_logs.filter(
                message__icontains='verified'
            ).first()
            if verification_log:
                time_diff = verification_log.timestamp - deal.created_at
                verification_times.append(time_diff.total_seconds() / 3600)  # Convert to hours
        
        avg_verification_time = sum(verification_times) / len(verification_times) if verification_times else 0
        
        return {
            'total_deals': verification_stats['total'],
            'verified_count': verification_stats['verified'],
            'pending_count': verification_stats['pending'],
            'rejected_count': verification_stats['rejected'],
            'verification_rate': (verification_stats['verified'] / verification_stats['total'] * 100) if verification_stats['total'] > 0 else 0,
            'rejection_rate': (verification_stats['rejected'] / verification_stats['total'] * 100) if verification_stats['total'] > 0 else 0,
            'avg_verification_time_hours': round(avg_verification_time, 2),
            'pending_over_24h': base_query.filter(
                verification_status='pending',
                created_at__lt=timezone.now() - timedelta(hours=24)
            ).count()
        }
    
    @classmethod
    def _calculate_payment_metrics(cls, base_query):
        """
        Calculate payment workflow metrics
        """
        payment_stats = base_query.aggregate(
            total=Count('id'),
            full_payment=Count('id', filter=Q(payment_status='full_payment')),
            partial_payment=Count('id', filter=Q(payment_status='partial_payment')),
            initial_payment=Count('id', filter=Q(payment_status='initial payment'))
        )
        
        # Calculate payment completion times
        completion_times = []
        for deal in base_query.filter(payment_status='full_payment').prefetch_related('payments'):
            last_payment = deal.payments.order_by('-payment_date').first()
            if last_payment:
                time_diff = last_payment.payment_date - deal.deal_date
                completion_times.append(time_diff.days)
        
        avg_completion_time = sum(completion_times) / len(completion_times) if completion_times else 0
        
        return {
            'total_deals': payment_stats['total'],
            'full_payment_count': payment_stats['full_payment'],
            'partial_payment_count': payment_stats['partial_payment'],
            'initial_payment_count': payment_stats['initial_payment'],
            'completion_rate': (payment_stats['full_payment'] / payment_stats['total'] * 100) if payment_stats['total'] > 0 else 0,
            'avg_completion_days': round(avg_completion_time, 1),
            'overdue_deals': base_query.filter(
                due_date__lt=timezone.now().date(),
                payment_status__in=['initial payment', 'partial_payment']
            ).count()
        }
    
    @classmethod
    def _calculate_workflow_efficiency(cls, base_query):
        """
        Calculate overall workflow efficiency metrics
        """
        # Deals that completed both verification and payment
        completed_deals = base_query.filter(
            verification_status='verified',
            payment_status='full_payment'
        ).count()
        
        total_deals = base_query.count()
        
        # Calculate efficiency score
        efficiency_score = (completed_deals / total_deals * 100) if total_deals > 0 else 0
        
        # Identify stuck deals
        stuck_deals = base_query.filter(
            Q(verification_status='pending', created_at__lt=timezone.now() - timedelta(days=3)) |
            Q(payment_status='partial_payment', created_at__lt=timezone.now() - timedelta(days=14))
        ).count()
        
        return {
            'total_deals': total_deals,
            'completed_deals': completed_deals,
            'efficiency_score': round(efficiency_score, 2),
            'stuck_deals': stuck_deals,
            'stuck_percentage': (stuck_deals / total_deals * 100) if total_deals > 0 else 0
        }
    
    @classmethod
    def _analyze_workflow_bottlenecks(cls, base_query):
        """
        Analyze workflow bottlenecks
        """
        bottlenecks = []
        
        # Verification bottlenecks
        long_pending_verification = base_query.filter(
            verification_status='pending',
            created_at__lt=timezone.now() - timedelta(days=3)
        ).count()
        
        if long_pending_verification > 0:
            bottlenecks.append({
                'type': 'verification_delay',
                'count': long_pending_verification,
                'severity': 'high' if long_pending_verification > 10 else 'medium',
                'description': f'{long_pending_verification} deals pending verification for >3 days'
            })
        
        # Payment bottlenecks
        stalled_payments = base_query.filter(
            payment_status='partial_payment',
            created_at__lt=timezone.now() - timedelta(days=14)
        ).count()
        
        if stalled_payments > 0:
            bottlenecks.append({
                'type': 'payment_stall',
                'count': stalled_payments,
                'severity': 'medium',
                'description': f'{stalled_payments} deals with stalled partial payments'
            })
        
        # Overdue deals
        overdue_deals = base_query.filter(
            due_date__lt=timezone.now().date(),
            payment_status__in=['initial payment', 'partial_payment']
        ).count()
        
        if overdue_deals > 0:
            bottlenecks.append({
                'type': 'overdue_payments',
                'count': overdue_deals,
                'severity': 'high',
                'description': f'{overdue_deals} deals are overdue for payment'
            })
        
        return bottlenecks
    
    @classmethod
    def _calculate_workflow_trends(cls, base_query, days):
        """
        Calculate workflow trends over time
        """
        # Daily deal creation trend
        daily_trends = base_query.annotate(
            date=TruncDate('created_at')
        ).values('date').annotate(
            count=Count('id'),
            verified=Count('id', filter=Q(verification_status='verified')),
            completed=Count('id', filter=Q(payment_status='full_payment'))
        ).order_by('date')
        
        # Weekly aggregation for longer periods
        if days > 30:
            weekly_trends = base_query.annotate(
                week=Extract('created_at', 'week'),
                year=Extract('created_at', 'year')
            ).values('year', 'week').annotate(
                count=Count('id'),
                verified=Count('id', filter=Q(verification_status='verified')),
                completed=Count('id', filter=Q(payment_status='full_payment'))
            ).order_by('year', 'week')
            
            return {
                'daily_trends': list(daily_trends),
                'weekly_trends': list(weekly_trends)
            }
        
        return {
            'daily_trends': list(daily_trends)
        }


# Background tasks for workflow optimization
@shared_task
def optimize_deal_workflows_task(organization_id=None):
    """
    Background task to optimize deal workflows
    """
    try:
        from apps.organization.models import Organization
        
        if organization_id:
            organization = Organization.objects.get(id=organization_id)
            result = EnhancedDealWorkflowOptimizer.optimize_deal_state_transitions(organization)
        else:
            result = EnhancedDealWorkflowOptimizer.optimize_deal_state_transitions()
        
        performance_logger.info(f"Workflow optimization task completed: {result}")
        return result
        
    except Exception as e:
        performance_logger.error(f"Workflow optimization task failed: {str(e)}")
        raise

@shared_task
def generate_workflow_performance_report(organization_id=None, days=30):
    """
    Generate comprehensive workflow performance report
    """
    try:
        from apps.organization.models import Organization
        
        organization = None
        if organization_id:
            organization = Organization.objects.get(id=organization_id)
        
        metrics = EnhancedDealWorkflowOptimizer.get_workflow_performance_metrics(
            organization=organization,
            days=days
        )
        
        # Store report in cache for dashboard access
        cache_key = f"workflow_report:{organization_id or 'all'}:{days}"
        cache.set(cache_key, metrics, 3600)  # Cache for 1 hour
        
        performance_logger.info(f"Workflow performance report generated for {days} days")
        return metrics
        
    except Exception as e:
        performance_logger.error(f"Workflow performance report generation failed: {str(e)}")
        raise

@shared_task
def automated_deal_state_maintenance():
    """
    Automated maintenance task for deal state consistency
    """
    try:
        from apps.organization.models import Organization
        
        maintenance_results = []
        
        for org in Organization.objects.filter(is_active=True):
            result = EnhancedDealWorkflowOptimizer.optimize_deal_state_transitions(
                organization=org,
                batch_size=50
            )
            
            if result['optimized_transitions'] > 0 or result['validation_errors']:
                maintenance_results.append({
                    'organization': org.name,
                    'optimized_transitions': result['optimized_transitions'],
                    'validation_errors': len(result['validation_errors']),
                    'recommendations': result['recommendations']
                })
        
        performance_logger.info(f"Automated deal state maintenance completed: {len(maintenance_results)} organizations processed")
        return maintenance_results
        
    except Exception as e:
        performance_logger.error(f"Automated deal state maintenance failed: {str(e)}")
        raise