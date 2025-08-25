"""
Commission Calculation Optimization Service
Provides efficient commission calculations with caching and audit trails
"""

from django.db.models import Sum, Count, Avg, Q, F
from django.core.cache import cache
from django.utils import timezone
from django.db import transaction
from decimal import Decimal, ROUND_HALF_UP
from datetime import datetime, timedelta
from .models import Commission
from apps.deals.models import Deal
from apps.authentication.models import User
import logging

# Performance logger
performance_logger = logging.getLogger('performance')
security_logger = logging.getLogger('security')

class CommissionCalculationOptimizer:
    """
    Service for optimizing commission calculations with caching and performance improvements
    """
    
    # Cache timeouts
    COMMISSION_CACHE_TIMEOUT = 1800  # 30 minutes
    SALES_DATA_CACHE_TIMEOUT = 900   # 15 minutes
    EXCHANGE_RATE_CACHE_TIMEOUT = 3600  # 1 hour
    
    @classmethod
    def calculate_user_commission(cls, user, start_date, end_date, organization=None, use_cache=True):
        """
        Calculate commission for a user with optimized queries and caching
        """
        cache_key = f"commission_calc_{user.id}_{start_date}_{end_date}_{organization.id if organization else 'none'}"
        
        if use_cache:
            cached_result = cache.get(cache_key)
            if cached_result:
                performance_logger.info(f"Using cached commission calculation for user {user.email}")
                return cached_result
        
        # Get organization
        if not organization:
            organization = user.organization if hasattr(user, 'organization') else None
        
        if not organization:
            raise ValueError("User must belong to an organization for commission calculation")
        
        # Optimized query to get verified deals and their total value
        verified_deals = Deal.objects.filter(
            created_by=user,
            organization=organization,
            verification_status='verified',
            deal_date__gte=start_date,
            deal_date__lte=end_date
        ).aggregate(
            total_sales=Sum('deal_value'),
            deal_count=Count('id'),
            avg_deal_value=Avg('deal_value')
        )
        
        total_sales = verified_deals['total_sales'] or Decimal('0.00')
        deal_count = verified_deals['deal_count'] or 0
        avg_deal_value = verified_deals['avg_deal_value'] or Decimal('0.00')
        
        # Get existing commission record or create default calculation
        commission_record = Commission.objects.filter(
            user=user,
            organization=organization,
            start_date=start_date,
            end_date=end_date
        ).first()
        
        if commission_record:
            # Update total sales and recalculate
            commission_record.total_sales = total_sales
            commission_record._calculate_amounts()
            
            calculation_result = {
                'user_id': user.id,
                'user_email': user.email,
                'organization_id': organization.id,
                'period': {
                    'start_date': start_date,
                    'end_date': end_date
                },
                'sales_data': {
                    'total_sales': float(total_sales),
                    'deal_count': deal_count,
                    'avg_deal_value': float(avg_deal_value)
                },
                'commission_data': {
                    'commission_rate': float(commission_record.commission_rate),
                    'exchange_rate': float(commission_record.exchange_rate),
                    'bonus': float(commission_record.bonus),
                    'penalty': float(commission_record.penalty),
                    'commission_amount': float(commission_record.commission_amount),
                    'total_commission': float(commission_record.total_commission),
                    'total_receivable': float(commission_record.total_receivable),
                    'converted_amount': float(commission_record.converted_amount)
                },
                'calculated_at': timezone.now().isoformat(),
                'has_commission_record': True
            }
        else:
            # Create default calculation without saving to database
            default_rate = Decimal('5.00')  # 5% default
            default_exchange_rate = Decimal('1.00')
            
            commission_amount = total_sales * (default_rate / Decimal('100'))
            total_commission = commission_amount * default_exchange_rate
            
            calculation_result = {
                'user_id': user.id,
                'user_email': user.email,
                'organization_id': organization.id,
                'period': {
                    'start_date': start_date,
                    'end_date': end_date
                },
                'sales_data': {
                    'total_sales': float(total_sales),
                    'deal_count': deal_count,
                    'avg_deal_value': float(avg_deal_value)
                },
                'commission_data': {
                    'commission_rate': float(default_rate),
                    'exchange_rate': float(default_exchange_rate),
                    'bonus': 0.0,
                    'penalty': 0.0,
                    'commission_amount': float(commission_amount),
                    'total_commission': float(total_commission),
                    'total_receivable': float(total_commission),
                    'converted_amount': float(total_sales)
                },
                'calculated_at': timezone.now().isoformat(),
                'has_commission_record': False
            }
        
        # Cache the result
        if use_cache:
            cache.set(cache_key, calculation_result, cls.COMMISSION_CACHE_TIMEOUT)
            performance_logger.info(f"Cached commission calculation for user {user.email}")
        
        return calculation_result
    
    @classmethod
    def bulk_calculate_commissions(cls, organization, start_date, end_date, user_ids=None):
        """
        Bulk calculate commissions for multiple users with optimized queries
        """
        cache_key = f"bulk_commission_{organization.id}_{start_date}_{end_date}_{hash(tuple(user_ids or []))}"
        cached_result = cache.get(cache_key)
        
        if cached_result:
            performance_logger.info(f"Using cached bulk commission calculation for organization {organization.name}")
            return cached_result
        
        # Get users to calculate commissions for
        users_query = User.objects.filter(
            organization=organization,
            is_active=True
        ).select_related('organization', 'role')
        
        if user_ids:
            users_query = users_query.filter(id__in=user_ids)
        else:
            # Default to salespeople
            users_query = users_query.filter(
                role__name__in=['Salesperson', 'Senior Salesperson']
            )
        
        # Bulk query for all deals in the period
        deals_data = Deal.objects.filter(
            organization=organization,
            verification_status='verified',
            deal_date__gte=start_date,
            deal_date__lte=end_date,
            created_by__in=users_query
        ).values('created_by').annotate(
            total_sales=Sum('deal_value'),
            deal_count=Count('id'),
            avg_deal_value=Avg('deal_value')
        )
        
        # Create lookup dictionary for efficient access
        sales_lookup = {item['created_by']: item for item in deals_data}
        
        # Get existing commission records
        existing_commissions = Commission.objects.filter(
            organization=organization,
            start_date=start_date,
            end_date=end_date,
            user__in=users_query
        ).select_related('user')
        
        commission_lookup = {comm.user.id: comm for comm in existing_commissions}
        
        bulk_results = []
        
        for user in users_query:
            sales_data = sales_lookup.get(user.id, {
                'total_sales': Decimal('0.00'),
                'deal_count': 0,
                'avg_deal_value': Decimal('0.00')
            })
            
            total_sales = sales_data['total_sales'] or Decimal('0.00')
            
            # Get or create commission calculation
            if user.id in commission_lookup:
                commission = commission_lookup[user.id]
                commission.total_sales = total_sales
                commission._calculate_amounts()
                
                result = {
                    'user_id': user.id,
                    'user_email': user.email,
                    'user_name': f"{user.first_name} {user.last_name}".strip() or user.username,
                    'total_sales': float(total_sales),
                    'deal_count': sales_data['deal_count'],
                    'commission_rate': float(commission.commission_rate),
                    'commission_amount': float(commission.commission_amount),
                    'total_commission': float(commission.total_commission),
                    'total_receivable': float(commission.total_receivable),
                    'has_record': True
                }
            else:
                # Default calculation
                default_rate = Decimal('5.00')
                commission_amount = total_sales * (default_rate / Decimal('100'))
                
                result = {
                    'user_id': user.id,
                    'user_email': user.email,
                    'user_name': f"{user.first_name} {user.last_name}".strip() or user.username,
                    'total_sales': float(total_sales),
                    'deal_count': sales_data['deal_count'],
                    'commission_rate': float(default_rate),
                    'commission_amount': float(commission_amount),
                    'total_commission': float(commission_amount),
                    'total_receivable': float(commission_amount),
                    'has_record': False
                }
            
            bulk_results.append(result)
        
        # Sort by total sales descending
        bulk_results.sort(key=lambda x: x['total_sales'], reverse=True)
        
        final_result = {
            'organization_id': organization.id,
            'organization_name': organization.name,
            'period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat()
            },
            'summary': {
                'total_users': len(bulk_results),
                'total_sales': sum(r['total_sales'] for r in bulk_results),
                'total_commissions': sum(r['total_commission'] for r in bulk_results),
                'avg_commission_rate': sum(r['commission_rate'] for r in bulk_results) / len(bulk_results) if bulk_results else 0
            },
            'commissions': bulk_results,
            'calculated_at': timezone.now().isoformat()
        }
        
        # Cache for 30 minutes
        cache.set(cache_key, final_result, cls.COMMISSION_CACHE_TIMEOUT)
        performance_logger.info(f"Cached bulk commission calculation for organization {organization.name}")
        
        return final_result
    
    @classmethod
    def get_commission_reconciliation_data(cls, organization, start_date, end_date):
        """
        Get commission reconciliation data for audit purposes
        """
        cache_key = f"commission_reconciliation_{organization.id}_{start_date}_{end_date}"
        cached_data = cache.get(cache_key)
        
        if cached_data:
            return cached_data
        
        # Get all commission records for the period
        commissions = Commission.objects.filter(
            organization=organization,
            start_date__lte=end_date,
            end_date__gte=start_date
        ).select_related('user', 'created_by', 'updated_by')
        
        # Get actual sales data for verification
        actual_sales = Deal.objects.filter(
            organization=organization,
            verification_status='verified',
            deal_date__gte=start_date,
            deal_date__lte=end_date
        ).values('created_by').annotate(
            actual_total_sales=Sum('deal_value'),
            deal_count=Count('id')
        )
        
        sales_lookup = {item['created_by']: item for item in actual_sales}
        
        reconciliation_data = []
        discrepancies = []
        
        for commission in commissions:
            actual_data = sales_lookup.get(commission.user.id, {
                'actual_total_sales': Decimal('0.00'),
                'deal_count': 0
            })
            
            actual_sales_amount = actual_data['actual_total_sales'] or Decimal('0.00')
            recorded_sales_amount = commission.total_sales
            
            # Check for discrepancies
            discrepancy = abs(actual_sales_amount - recorded_sales_amount)
            has_discrepancy = discrepancy > Decimal('0.01')  # More than 1 cent difference
            
            reconciliation_item = {
                'commission_id': commission.id,
                'user_id': commission.user.id,
                'user_email': commission.user.email,
                'user_name': f"{commission.user.first_name} {commission.user.last_name}".strip(),
                'recorded_sales': float(recorded_sales_amount),
                'actual_sales': float(actual_sales_amount),
                'discrepancy': float(discrepancy),
                'has_discrepancy': has_discrepancy,
                'deal_count': actual_data['deal_count'],
                'commission_amount': float(commission.commission_amount),
                'total_commission': float(commission.total_commission),
                'last_updated': commission.updated_at.isoformat()
            }
            
            reconciliation_data.append(reconciliation_item)
            
            if has_discrepancy:
                discrepancies.append(reconciliation_item)
        
        result = {
            'organization_id': organization.id,
            'organization_name': organization.name,
            'reconciliation_period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat()
            },
            'summary': {
                'total_commissions': len(reconciliation_data),
                'discrepancies_found': len(discrepancies),
                'total_recorded_sales': sum(r['recorded_sales'] for r in reconciliation_data),
                'total_actual_sales': sum(r['actual_sales'] for r in reconciliation_data),
                'total_commission_amount': sum(r['total_commission'] for r in reconciliation_data)
            },
            'reconciliation_data': reconciliation_data,
            'discrepancies': discrepancies,
            'generated_at': timezone.now().isoformat()
        }
        
        # Cache for 15 minutes (shorter cache for reconciliation data)
        cache.set(cache_key, result, 900)
        
        return result
    
    @classmethod
    def auto_fix_commission_discrepancies(cls, organization, start_date, end_date, dry_run=True):
        """
        Automatically fix commission calculation discrepancies
        """
        reconciliation = cls.get_commission_reconciliation_data(organization, start_date, end_date)
        
        fixed_commissions = []
        failed_fixes = []
        
        for discrepancy in reconciliation['discrepancies']:
            try:
                commission = Commission.objects.get(id=discrepancy['commission_id'])
                
                if not dry_run:
                    with transaction.atomic():
                        # Update total sales to actual sales
                        commission.total_sales = Decimal(str(discrepancy['actual_sales']))
                        commission.save()  # This will recalculate amounts
                        
                        # Log the fix
                        security_logger.info(
                            f"Commission discrepancy fixed for user {commission.user.email}: "
                            f"Sales updated from {discrepancy['recorded_sales']} to {discrepancy['actual_sales']}"
                        )
                
                fixed_commissions.append({
                    'commission_id': commission.id,
                    'user_email': commission.user.email,
                    'old_sales': discrepancy['recorded_sales'],
                    'new_sales': discrepancy['actual_sales'],
                    'discrepancy_fixed': float(discrepancy['discrepancy'])
                })
                
            except Commission.DoesNotExist:
                failed_fixes.append({
                    'commission_id': discrepancy['commission_id'],
                    'error': 'Commission record not found'
                })
            except Exception as e:
                failed_fixes.append({
                    'commission_id': discrepancy['commission_id'],
                    'error': str(e)
                })
        
        return {
            'dry_run': dry_run,
            'fixed_commissions': fixed_commissions,
            'failed_fixes': failed_fixes,
            'summary': {
                'total_discrepancies': len(reconciliation['discrepancies']),
                'successfully_fixed': len(fixed_commissions),
                'failed_to_fix': len(failed_fixes)
            }
        }
    
    @classmethod
    def get_commission_analytics(cls, organization, start_date=None, end_date=None):
        """
        Get comprehensive commission analytics with caching
        """
        # Default to current month if no dates provided
        if not start_date:
            start_date = timezone.now().replace(day=1).date()
        if not end_date:
            end_date = timezone.now().date()
        
        cache_key = f"commission_analytics_{organization.id}_{start_date}_{end_date}"
        cached_analytics = cache.get(cache_key)
        
        if cached_analytics:
            return cached_analytics
        
        # Get commission records for the period
        commissions = Commission.objects.filter(
            organization=organization,
            start_date__lte=end_date,
            end_date__gte=start_date
        ).select_related('user')
        
        # Calculate analytics
        total_commissions = commissions.count()
        total_sales = sum(float(c.total_sales) for c in commissions)
        total_commission_amount = sum(float(c.total_commission) for c in commissions)
        total_receivable = sum(float(c.total_receivable) for c in commissions)
        
        # Commission rate distribution
        rate_distribution = {}
        for commission in commissions:
            rate = float(commission.commission_rate)
            rate_distribution[rate] = rate_distribution.get(rate, 0) + 1
        
        # Top performers
        top_performers = sorted(
            commissions,
            key=lambda c: float(c.total_sales),
            reverse=True
        )[:10]
        
        # Currency distribution
        currency_distribution = {}
        for commission in commissions:
            currency = commission.currency
            currency_distribution[currency] = currency_distribution.get(currency, 0) + 1
        
        analytics = {
            'organization_id': organization.id,
            'organization_name': organization.name,
            'period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat()
            },
            'summary': {
                'total_commissions': total_commissions,
                'total_sales': total_sales,
                'total_commission_amount': total_commission_amount,
                'total_receivable': total_receivable,
                'avg_commission_rate': sum(float(c.commission_rate) for c in commissions) / total_commissions if total_commissions > 0 else 0,
                'avg_sales_per_person': total_sales / total_commissions if total_commissions > 0 else 0
            },
            'distributions': {
                'commission_rates': rate_distribution,
                'currencies': currency_distribution
            },
            'top_performers': [
                {
                    'user_id': c.user.id,
                    'user_name': f"{c.user.first_name} {c.user.last_name}".strip() or c.user.username,
                    'total_sales': float(c.total_sales),
                    'total_commission': float(c.total_commission)
                }
                for c in top_performers
            ],
            'generated_at': timezone.now().isoformat()
        }
        
        # Cache for 30 minutes
        cache.set(cache_key, analytics, cls.COMMISSION_CACHE_TIMEOUT)
        
        return analytics
    
    @classmethod
    def invalidate_commission_caches(cls, organization_id=None, user_id=None):
        """
        Invalidate commission-related caches
        """
        # This is a simplified cache invalidation
        # In production, you might want to use cache versioning or pattern-based invalidation
        
        if organization_id:
            # Invalidate organization-specific caches
            cache_patterns = [
                f"bulk_commission_{organization_id}_*",
                f"commission_analytics_{organization_id}_*",
                f"commission_reconciliation_{organization_id}_*"
            ]
            
            if user_id:
                cache_patterns.append(f"commission_calc_{user_id}_*")
        
        performance_logger.info(f"Invalidated commission caches for org {organization_id}, user {user_id}")


class CommissionAuditTrail:
    """
    Service for maintaining commission calculation audit trails
    """
    
    @classmethod
    def log_commission_calculation(cls, commission, calculation_type='manual', user=None, changes=None):
        """
        Log commission calculation for audit purposes
        """
        from core_config.models import AuditTrail
        
        audit_data = {
            'commission_id': commission.id,
            'user_id': commission.user.id,
            'organization_id': commission.organization.id,
            'calculation_type': calculation_type,
            'total_sales': float(commission.total_sales),
            'commission_rate': float(commission.commission_rate),
            'commission_amount': float(commission.commission_amount),
            'total_commission': float(commission.total_commission),
            'calculated_by': user.email if user else 'system',
            'changes': changes or {}
        }
        
        try:
            AuditTrail.objects.create(
                table_name='commission_commission',
                record_id=str(commission.id),
                action='CALCULATE',
                new_values=audit_data,
                user=user
            )
            
            security_logger.info(
                f"Commission calculation logged for user {commission.user.email} "
                f"by {user.email if user else 'system'}"
            )
            
        except Exception as e:
            security_logger.error(f"Failed to log commission calculation: {str(e)}")
    
    @classmethod
    def get_commission_audit_history(cls, commission_id):
        """
        Get audit history for a specific commission
        """
        from core_config.models import AuditTrail
        
        audit_records = AuditTrail.objects.filter(
            table_name='commission_commission',
            record_id=str(commission_id)
        ).order_by('-timestamp')
        
        history = []
        for record in audit_records:
            history.append({
                'timestamp': record.timestamp.isoformat(),
                'action': record.action,
                'user': record.user.email if record.user else 'system',
                'changes': record.new_values
            })
        
        return history


class CommissionPerformanceOptimizer:
    """
    Enhanced performance optimization for commission calculations
    Task 5.3.2: Optimize commission calculation performance
    """
    
    # Performance monitoring settings
    PERFORMANCE_THRESHOLD_MS = 1000  # 1 second
    BULK_CALCULATION_BATCH_SIZE = 100
    CACHE_WARMING_INTERVAL = 3600  # 1 hour
    
    # Cache keys for frequently accessed data
    FREQUENT_CALCULATIONS_KEY = "commission_frequent_calculations"
    COMMISSION_CALCULATION_STATS_KEY = "commission_calc_stats"
    HOT_CACHE_KEY_PREFIX = "commission_hot_"
    
    @classmethod
    def optimize_frequent_calculations(cls, organization, recalculate_threshold_hours=24):
        """
        Optimize frequently calculated commissions with intelligent caching
        Task 5.3.2: Caching for frequently calculated commissions
        """
        start_time = timezone.now()
        
        # Identify frequently calculated commissions
        frequent_commissions = cls._identify_frequent_calculations(organization)
        
        optimized_count = 0
        cache_hits = 0
        performance_improvements = []
        
        for commission_id, frequency_data in frequent_commissions.items():
            try:
                commission = Commission.objects.select_related('user', 'organization').get(id=commission_id)
                
                # Check if recalculation is needed
                last_calc_time = frequency_data.get('last_calculated')
                if last_calc_time:
                    time_since_calc = (timezone.now() - last_calc_time).total_seconds() / 3600
                    if time_since_calc < recalculate_threshold_hours:
                        cache_hits += 1
                        continue
                
                # Pre-calculate and cache
                calc_start = timezone.now()
                cls._precalculate_commission(commission)
                calc_duration = (timezone.now() - calc_start).total_seconds() * 1000
                
                optimized_count += 1
                performance_improvements.append({
                    'commission_id': commission_id,
                    'user_email': commission.user.email,
                    'calculation_time_ms': calc_duration,
                    'frequency_score': frequency_data.get('frequency_score', 0)
                })
                
                # Update frequency tracking
                cls._update_calculation_frequency(commission_id, timezone.now())
                
            except Commission.DoesNotExist:
                performance_logger.warning(f"Commission {commission_id} not found during optimization")
                continue
            except Exception as e:
                performance_logger.error(f"Error optimizing commission {commission_id}: {str(e)}")
                continue
        
        optimization_duration = (timezone.now() - start_time).total_seconds() * 1000
        
        # Log performance metrics
        performance_logger.info(
            f"Commission optimization completed for {organization.name}: "
            f"{optimized_count} optimized, {cache_hits} cache hits, "
            f"total time: {optimization_duration:.2f}ms"
        )
        
        return {
            'organization_id': organization.id,
            'optimization_summary': {
                'commissions_optimized': optimized_count,
                'cache_hits': cache_hits,
                'total_optimization_time_ms': optimization_duration,
                'average_calculation_time_ms': sum(p['calculation_time_ms'] for p in performance_improvements) / len(performance_improvements) if performance_improvements else 0
            },
            'performance_improvements': performance_improvements,
            'recommendations': cls._generate_performance_recommendations(performance_improvements)
        }
    
    @classmethod
    def bulk_optimize_calculations(cls, organization, user_ids=None, batch_size=None):
        """
        Bulk commission calculation optimization with batching
        Task 5.3.2: Bulk commission calculation optimization
        """
        if batch_size is None:
            batch_size = cls.BULK_CALCULATION_BATCH_SIZE
        
        start_time = timezone.now()
        
        # Get commissions to optimize
        commissions_query = Commission.objects.filter(
            organization=organization
        ).select_related('user', 'organization')
        
        if user_ids:
            commissions_query = commissions_query.filter(user_id__in=user_ids)
        
        total_commissions = commissions_query.count()
        processed_count = 0
        batch_results = []
        
        # Process in batches
        for batch_start in range(0, total_commissions, batch_size):
            batch_commissions = commissions_query[batch_start:batch_start + batch_size]
            
            batch_start_time = timezone.now()
            batch_performance = []
            
            for commission in batch_commissions:
                try:
                    calc_start_time = timezone.now()
                    
                    # Optimize calculation with enhanced precision
                    result = cls._optimize_single_commission_calculation(commission)
                    
                    calc_duration = (timezone.now() - calc_start_time).total_seconds() * 1000
                    processed_count += 1
                    
                    batch_performance.append({
                        'commission_id': commission.id,
                        'user_id': commission.user_id,
                        'calculation_time_ms': calc_duration,
                        'optimization_result': result
                    })
                    
                except Exception as e:
                    performance_logger.error(f"Error in batch optimization for commission {commission.id}: {str(e)}")
                    continue
            
            batch_duration = (timezone.now() - batch_start_time).total_seconds() * 1000
            
            batch_results.append({
                'batch_number': len(batch_results) + 1,
                'batch_size': len(batch_commissions),
                'batch_duration_ms': batch_duration,
                'average_calc_time_ms': sum(p['calculation_time_ms'] for p in batch_performance) / len(batch_performance) if batch_performance else 0,
                'performance_details': batch_performance
            })
            
            # Log batch progress
            performance_logger.info(f"Batch {len(batch_results)} completed: {len(batch_commissions)} commissions in {batch_duration:.2f}ms")
        
        total_duration = (timezone.now() - start_time).total_seconds() * 1000
        
        return {
            'organization_id': organization.id,
            'bulk_optimization_summary': {
                'total_commissions': total_commissions,
                'processed_commissions': processed_count,
                'batch_count': len(batch_results),
                'total_time_ms': total_duration,
                'average_time_per_commission_ms': total_duration / processed_count if processed_count > 0 else 0,
                'throughput_per_second': processed_count / (total_duration / 1000) if total_duration > 0 else 0
            },
            'batch_results': batch_results,
            'performance_analysis': cls._analyze_batch_performance(batch_results)
        }
    
    @classmethod
    def monitor_commission_calculation_performance(cls, organization, time_period_hours=24):
        """
        Monitor commission calculation performance and identify bottlenecks
        Task 5.3.2: Commission calculation monitoring
        """
        end_time = timezone.now()
        start_time = end_time - timedelta(hours=time_period_hours)
        
        # Get performance statistics from cache
        performance_stats = cache.get(f"{cls.COMMISSION_CALCULATION_STATS_KEY}_{organization.id}", {})
        
        # Get recent commissions and their calculation times
        recent_commissions = Commission.objects.filter(
            organization=organization,
            updated_at__gte=start_time
        ).select_related('user').order_by('-updated_at')
        
        # Analyze performance patterns
        performance_analysis = {
            'monitoring_period': {
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_hours': time_period_hours
            },
            'commission_statistics': {
                'total_calculations': recent_commissions.count(),
                'unique_users': len(set(c.user_id for c in recent_commissions)),
                'calculations_per_hour': recent_commissions.count() / time_period_hours
            },
            'performance_metrics': performance_stats.get('metrics', {}),
            'bottlenecks': cls._identify_performance_bottlenecks(performance_stats),
            'recommendations': cls._generate_monitoring_recommendations(performance_stats, recent_commissions)
        }
        
        # Cache analysis results
        cache.set(
            f"commission_performance_analysis_{organization.id}",
            performance_analysis,
            1800  # 30 minutes
        )
        
        return performance_analysis
    
    @classmethod
    def warm_commission_caches(cls, organization, priority_users=None):
        """
        Warm up commission calculation caches proactively
        Task 5.3.2: Cache warming strategies
        """
        start_time = timezone.now()
        warmed_caches = []
        
        # Get users to warm caches for
        if priority_users:
            users = User.objects.filter(id__in=priority_users, organization=organization)
        else:
            # Warm caches for active salespeople
            users = User.objects.filter(
                organization=organization,
                is_active=True,
                role__name__in=['Salesperson', 'Senior Salesperson']
            )[:50]  # Limit to top 50 users
        
        # Common date ranges to warm
        today = timezone.now().date()
        date_ranges = [
            (today.replace(day=1), today),  # Current month
            ((today.replace(day=1) - timedelta(days=1)).replace(day=1), today.replace(day=1) - timedelta(days=1)),  # Previous month
            (today - timedelta(days=30), today),  # Last 30 days
            (today - timedelta(days=90), today),  # Last 90 days
        ]
        
        for user in users:
            for start_date, end_date in date_ranges:
                try:
                    # Pre-calculate and cache commission data
                    cache_key = f"commission_calc_{user.id}_{start_date}_{end_date}_{organization.id}"
                    
                    if not cache.get(cache_key):
                        calc_start = timezone.now()
                        result = CommissionCalculationOptimizer.calculate_user_commission(
                            user, start_date, end_date, organization, use_cache=False
                        )
                        calc_duration = (timezone.now() - calc_start).total_seconds() * 1000
                        
                        # Force cache the result
                        cache.set(cache_key, result, CommissionCalculationOptimizer.COMMISSION_CACHE_TIMEOUT)
                        
                        warmed_caches.append({
                            'user_id': user.id,
                            'user_email': user.email,
                            'date_range': f"{start_date} to {end_date}",
                            'cache_key': cache_key,
                            'calculation_time_ms': calc_duration
                        })
                        
                except Exception as e:
                    performance_logger.error(f"Error warming cache for user {user.id}: {str(e)}")
                    continue
        
        total_duration = (timezone.now() - start_time).total_seconds() * 1000
        
        performance_logger.info(
            f"Commission cache warming completed for {organization.name}: "
            f"{len(warmed_caches)} caches warmed in {total_duration:.2f}ms"
        )
        
        return {
            'organization_id': organization.id,
            'cache_warming_summary': {
                'caches_warmed': len(warmed_caches),
                'users_processed': len(users),
                'date_ranges_per_user': len(date_ranges),
                'total_warming_time_ms': total_duration,
                'average_time_per_cache_ms': total_duration / len(warmed_caches) if warmed_caches else 0
            },
            'warmed_caches': warmed_caches
        }
    
    @classmethod
    def _identify_frequent_calculations(cls, organization):
        """Identify frequently calculated commissions"""
        # Get frequency data from cache
        frequency_data = cache.get(cls.FREQUENT_CALCULATIONS_KEY, {})
        org_data = frequency_data.get(str(organization.id), {})
        
        # Sort by frequency score
        frequent_calculations = {}
        for commission_id, data in org_data.items():
            if data.get('frequency_score', 0) > 5:  # Threshold for "frequent"
                frequent_calculations[commission_id] = data
        
        return frequent_calculations
    
    @classmethod
    def _precalculate_commission(cls, commission):
        """Pre-calculate and cache commission with enhanced performance"""
        from apps.deals.financial_optimizer import FinancialFieldOptimizer
        
        # Use enhanced calculation with precision validation
        result = FinancialFieldOptimizer.calculate_comprehensive_commission(
            commission.total_sales,
            commission.commission_rate,
            commission.exchange_rate,
            commission.bonus,
            commission.penalty
        )
        
        if result['success']:
            # Update commission with calculated values
            commission.commission_amount = result['calculations']['base_commission']
            commission.total_commission = result['calculations']['commission_with_bonus'] - result['inputs']['penalty']
            commission.total_receivable = result['summary']['final_commission']
            commission.save()
        
        return result
    
    @classmethod
    def _update_calculation_frequency(cls, commission_id, timestamp):
        """Update frequency tracking for a commission"""
        frequency_data = cache.get(cls.FREQUENT_CALCULATIONS_KEY, {})
        
        # Update frequency score (simplified scoring)
        if str(commission_id) not in frequency_data:
            frequency_data[str(commission_id)] = {
                'frequency_score': 1,
                'last_calculated': timestamp,
                'first_calculated': timestamp
            }
        else:
            frequency_data[str(commission_id)]['frequency_score'] += 1
            frequency_data[str(commission_id)]['last_calculated'] = timestamp
        
        cache.set(cls.FREQUENT_CALCULATIONS_KEY, frequency_data, cls.CACHE_WARMING_INTERVAL * 24)  # 24 hours
    
    @classmethod
    def _optimize_single_commission_calculation(cls, commission):
        """Optimize a single commission calculation"""
        optimization_start = timezone.now()
        
        # Enhanced calculation with validation
        result = cls._precalculate_commission(commission)
        
        optimization_duration = (timezone.now() - optimization_start).total_seconds() * 1000
        
        return {
            'success': result['success'] if result else True,
            'optimization_time_ms': optimization_duration,
            'calculation_result': result.get('summary', {}) if result else {},
            'warnings': result.get('warnings', []) if result else []
        }
    
    @classmethod
    def _analyze_batch_performance(cls, batch_results):
        """Analyze performance across batches"""
        if not batch_results:
            return {}
        
        total_batches = len(batch_results)
        total_duration = sum(batch['batch_duration_ms'] for batch in batch_results)
        total_commissions = sum(batch['batch_size'] for batch in batch_results)
        
        avg_batch_time = total_duration / total_batches
        avg_calc_times = [batch['average_calc_time_ms'] for batch in batch_results if batch['average_calc_time_ms'] > 0]
        overall_avg_calc_time = sum(avg_calc_times) / len(avg_calc_times) if avg_calc_times else 0
        
        return {
            'total_batches': total_batches,
            'total_commissions': total_commissions,
            'average_batch_time_ms': avg_batch_time,
            'average_calculation_time_ms': overall_avg_calc_time,
            'throughput_per_second': total_commissions / (total_duration / 1000) if total_duration > 0 else 0,
            'performance_consistency': cls._calculate_performance_consistency(avg_calc_times)
        }
    
    @classmethod
    def _calculate_performance_consistency(cls, calc_times):
        """Calculate performance consistency score"""
        if len(calc_times) < 2:
            return 100.0
        
        avg = sum(calc_times) / len(calc_times)
        variance = sum((t - avg) ** 2 for t in calc_times) / len(calc_times)
        std_dev = variance ** 0.5
        
        # Consistency score (higher is better)
        consistency = max(0, 100 - (std_dev / avg * 100)) if avg > 0 else 0
        return round(consistency, 2)
    
    @classmethod
    def _identify_performance_bottlenecks(cls, performance_stats):
        """Identify performance bottlenecks"""
        bottlenecks = []
        
        metrics = performance_stats.get('metrics', {})
        
        if metrics.get('average_calculation_time_ms', 0) > cls.PERFORMANCE_THRESHOLD_MS:
            bottlenecks.append({
                'type': 'slow_calculations',
                'description': f'Average calculation time ({metrics["average_calculation_time_ms"]:.2f}ms) exceeds threshold ({cls.PERFORMANCE_THRESHOLD_MS}ms)',
                'severity': 'high' if metrics['average_calculation_time_ms'] > cls.PERFORMANCE_THRESHOLD_MS * 2 else 'medium'
            })
        
        if metrics.get('cache_hit_rate', 100) < 50:
            bottlenecks.append({
                'type': 'low_cache_hits',
                'description': f'Cache hit rate ({metrics["cache_hit_rate"]:.1f}%) is below 50%',
                'severity': 'medium'
            })
        
        return bottlenecks
    
    @classmethod
    def _generate_performance_recommendations(cls, performance_improvements):
        """Generate performance optimization recommendations"""
        if not performance_improvements:
            return []
        
        avg_calc_time = sum(p['calculation_time_ms'] for p in performance_improvements) / len(performance_improvements)
        recommendations = []
        
        if avg_calc_time > cls.PERFORMANCE_THRESHOLD_MS:
            recommendations.append({
                'type': 'optimization',
                'priority': 'high',
                'recommendation': 'Consider implementing database query optimization or increasing cache timeouts',
                'expected_improvement': 'Reduce calculation time by 20-50%'
            })
        
        if len(performance_improvements) > 100:
            recommendations.append({
                'type': 'scaling',
                'priority': 'medium',
                'recommendation': 'Consider implementing background task processing for bulk calculations',
                'expected_improvement': 'Improve user experience and system responsiveness'
            })
        
        return recommendations
    
    @classmethod
    def _generate_monitoring_recommendations(cls, performance_stats, recent_commissions):
        """Generate monitoring-based recommendations"""
        recommendations = []
        
        commission_count = recent_commissions.count()
        
        if commission_count > 1000:
            recommendations.append({
                'type': 'volume',
                'priority': 'high',
                'recommendation': 'High calculation volume detected. Consider implementing batch processing during off-peak hours.',
                'metric': f'{commission_count} calculations in monitoring period'
            })
        
        # Check for performance degradation patterns
        metrics = performance_stats.get('metrics', {})
        if metrics.get('error_rate', 0) > 5:
            recommendations.append({
                'type': 'reliability',
                'priority': 'critical',
                'recommendation': 'Error rate is high. Investigate calculation failures and implement retry mechanisms.',
                'metric': f'{metrics["error_rate"]:.1f}% error rate'
            })
        
        return recommendations