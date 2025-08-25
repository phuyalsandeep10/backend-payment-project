"""
Deal Query Optimization Service
Provides optimized queries and pagination for deal management
"""

from django.db.models import Q, Count, Sum, Avg, Max, Min, F, Case, When, Value
from django.db.models.functions import TruncDate, TruncMonth, TruncYear, Coalesce
from django.core.paginator import Paginator
from django.core.cache import cache
from django.utils import timezone
from datetime import datetime, timedelta
from .models import Deal, Payment, PaymentApproval
from decimal import Decimal
import logging

# Performance logger
performance_logger = logging.getLogger('performance')

class DealQueryOptimizer:
    """
    Service for optimizing deal queries and providing efficient pagination
    """
    
    @classmethod
    def get_optimized_deal_queryset(cls, organization=None, user=None):
        """
        Get optimized base queryset for deals with proper select_related and prefetch_related
        """
        queryset = Deal.objects.select_related(
            'organization',
            'client',
            'project',
            'created_by',
            'updated_by'
        ).prefetch_related(
            'payments',
            'payments__approvals',
            'payments__invoice',
            'approvals',
            'activity_logs'
        )
        
        if organization:
            queryset = queryset.filter(organization=organization)
        
        if user and not user.is_superuser:
            # Filter by user's organization if not superuser
            if hasattr(user, 'organization') and user.organization:
                queryset = queryset.filter(organization=user.organization)
        
        return queryset
    
    @classmethod
    def get_deals_with_filters(cls, organization=None, filters=None, user=None):
        """
        Get deals with advanced filtering and optimization
        
        Args:
            organization: Organization to filter by
            filters: Dictionary of filters to apply
            user: User making the request
            
        Returns:
            Optimized queryset with filters applied
        """
        queryset = cls.get_optimized_deal_queryset(organization, user)
        
        if not filters:
            return queryset
        
        # Apply filters efficiently
        filter_conditions = Q()
        
        # Status filters
        if 'verification_status' in filters:
            status_list = filters['verification_status']
            if isinstance(status_list, str):
                status_list = [status_list]
            filter_conditions &= Q(verification_status__in=status_list)
        
        if 'payment_status' in filters:
            payment_list = filters['payment_status']
            if isinstance(payment_list, str):
                payment_list = [payment_list]
            filter_conditions &= Q(payment_status__in=payment_list)
        
        # Date range filters
        if 'date_from' in filters:
            filter_conditions &= Q(deal_date__gte=filters['date_from'])
        
        if 'date_to' in filters:
            filter_conditions &= Q(deal_date__lte=filters['date_to'])
        
        if 'created_from' in filters:
            filter_conditions &= Q(created_at__gte=filters['created_from'])
        
        if 'created_to' in filters:
            filter_conditions &= Q(created_at__lte=filters['created_to'])
        
        # Value range filters
        if 'min_value' in filters:
            filter_conditions &= Q(deal_value__gte=filters['min_value'])
        
        if 'max_value' in filters:
            filter_conditions &= Q(deal_value__lte=filters['max_value'])
        
        # Source type filter
        if 'source_type' in filters:
            source_list = filters['source_type']
            if isinstance(source_list, str):
                source_list = [source_list]
            filter_conditions &= Q(source_type__in=source_list)
        
        # Client filter
        if 'client_id' in filters:
            filter_conditions &= Q(client_id=filters['client_id'])
        
        # Created by filter
        if 'created_by' in filters:
            filter_conditions &= Q(created_by_id=filters['created_by'])
        
        # Project filter
        if 'project_id' in filters:
            filter_conditions &= Q(project_id=filters['project_id'])
        
        # Payment method filter
        if 'payment_method' in filters:
            method_list = filters['payment_method']
            if isinstance(method_list, str):
                method_list = [method_list]
            filter_conditions &= Q(payment_method__in=method_list)
        
        # Search filter (deal name, deal ID, client name)
        if 'search' in filters and filters['search']:
            search_term = filters['search']
            search_conditions = (
                Q(deal_name__icontains=search_term) |
                Q(deal_id__icontains=search_term) |
                Q(client__client_name__icontains=search_term) |
                Q(deal_remarks__icontains=search_term)
            )
            filter_conditions &= search_conditions
        
        # Apply all filters
        if filter_conditions:
            queryset = queryset.filter(filter_conditions)
        
        return queryset
    
    @classmethod
    def get_paginated_deals(cls, queryset, page=1, page_size=25, order_by='-created_at'):
        """
        Get paginated deals with efficient pagination
        """
        # Apply ordering
        if order_by:
            queryset = queryset.order_by(order_by)
        
        # Use Django's Paginator for efficient pagination
        paginator = Paginator(queryset, page_size)
        
        try:
            page_obj = paginator.get_page(page)
        except Exception:
            page_obj = paginator.get_page(1)
        
        return {
            'deals': list(page_obj),
            'pagination': {
                'current_page': page_obj.number,
                'total_pages': paginator.num_pages,
                'total_count': paginator.count,
                'page_size': page_size,
                'has_next': page_obj.has_next(),
                'has_previous': page_obj.has_previous(),
                'next_page': page_obj.next_page_number() if page_obj.has_next() else None,
                'previous_page': page_obj.previous_page_number() if page_obj.has_previous() else None,
            }
        }
    
    @classmethod
    def get_deal_analytics(cls, organization=None, date_from=None, date_to=None, user=None):
        """
        Get comprehensive deal analytics with optimized queries
        """
        cache_key = f"deal_analytics_{organization.id if organization else 'all'}_{date_from}_{date_to}"
        cached_analytics = cache.get(cache_key)
        
        if cached_analytics:
            performance_logger.info(f"Using cached deal analytics for organization {organization.id if organization else 'all'}")
            return cached_analytics
        
        queryset = cls.get_optimized_deal_queryset(organization, user)
        
        # Apply date filters
        if date_from:
            queryset = queryset.filter(created_at__gte=date_from)
        if date_to:
            queryset = queryset.filter(created_at__lte=date_to)
        
        # Basic statistics
        basic_stats = queryset.aggregate(
            total_deals=Count('id'),
            total_value=Coalesce(Sum('deal_value'), Value(0)),
            avg_deal_value=Coalesce(Avg('deal_value'), Value(0)),
            max_deal_value=Coalesce(Max('deal_value'), Value(0)),
            min_deal_value=Coalesce(Min('deal_value'), Value(0)),
        )
        
        # Status distribution
        status_distribution = queryset.values('verification_status').annotate(
            count=Count('id'),
            total_value=Coalesce(Sum('deal_value'), Value(0))
        ).order_by('verification_status')
        
        # Payment status distribution
        payment_distribution = queryset.values('payment_status').annotate(
            count=Count('id'),
            total_value=Coalesce(Sum('deal_value'), Value(0))
        ).order_by('payment_status')
        
        # Source type analysis
        source_analysis = queryset.values('source_type').annotate(
            count=Count('id'),
            total_value=Coalesce(Sum('deal_value'), Value(0)),
            avg_value=Coalesce(Avg('deal_value'), Value(0))
        ).order_by('-count')
        
        # Monthly trends (last 12 months)
        monthly_trends = queryset.filter(
            created_at__gte=timezone.now() - timedelta(days=365)
        ).annotate(
            month=TruncMonth('created_at')
        ).values('month').annotate(
            count=Count('id'),
            total_value=Coalesce(Sum('deal_value'), Value(0))
        ).order_by('month')
        
        # Top clients by deal count and value
        top_clients = queryset.values(
            'client__id', 'client__client_name'
        ).annotate(
            deal_count=Count('id'),
            total_value=Coalesce(Sum('deal_value'), Value(0))
        ).order_by('-total_value')[:10]
        
        # Top creators by deal count and value
        top_creators = queryset.values(
            'created_by__id', 'created_by__email', 'created_by__first_name', 'created_by__last_name'
        ).annotate(
            deal_count=Count('id'),
            total_value=Coalesce(Sum('deal_value'), Value(0))
        ).order_by('-deal_count')[:10]
        
        # Deal value ranges
        value_ranges = {
            'small': queryset.filter(deal_value__lt=1000).count(),
            'medium': queryset.filter(deal_value__gte=1000, deal_value__lt=10000).count(),
            'large': queryset.filter(deal_value__gte=10000, deal_value__lt=50000).count(),
            'enterprise': queryset.filter(deal_value__gte=50000).count(),
        }
        
        analytics = {
            'basic_stats': basic_stats,
            'status_distribution': list(status_distribution),
            'payment_distribution': list(payment_distribution),
            'source_analysis': list(source_analysis),
            'monthly_trends': list(monthly_trends),
            'top_clients': list(top_clients),
            'top_creators': list(top_creators),
            'value_ranges': value_ranges,
            'generated_at': timezone.now().isoformat(),
            'date_range': {
                'from': date_from.isoformat() if date_from else None,
                'to': date_to.isoformat() if date_to else None
            }
        }
        
        # Cache for 30 minutes
        cache.set(cache_key, analytics, 1800)
        performance_logger.info(f"Generated and cached deal analytics for organization {organization.id if organization else 'all'}")
        
        return analytics
    
    @classmethod
    def get_deal_performance_metrics(cls, organization=None, user=None):
        """
        Get deal performance metrics for dashboard
        """
        cache_key = f"deal_performance_{organization.id if organization else 'all'}"
        cached_metrics = cache.get(cache_key)
        
        if cached_metrics:
            return cached_metrics
        
        queryset = cls.get_optimized_deal_queryset(organization, user)
        
        # Current month metrics
        current_month_start = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        current_month_deals = queryset.filter(created_at__gte=current_month_start)
        
        # Previous month metrics for comparison
        previous_month_start = (current_month_start - timedelta(days=1)).replace(day=1)
        previous_month_deals = queryset.filter(
            created_at__gte=previous_month_start,
            created_at__lt=current_month_start
        )
        
        # Calculate metrics
        current_stats = current_month_deals.aggregate(
            count=Count('id'),
            total_value=Coalesce(Sum('deal_value'), Value(0)),
            verified_count=Count('id', filter=Q(verification_status='verified')),
            pending_count=Count('id', filter=Q(verification_status='pending')),
        )
        
        previous_stats = previous_month_deals.aggregate(
            count=Count('id'),
            total_value=Coalesce(Sum('deal_value'), Value(0)),
        )
        
        # Calculate growth rates
        count_growth = 0
        value_growth = 0
        
        if previous_stats['count'] > 0:
            count_growth = ((current_stats['count'] - previous_stats['count']) / previous_stats['count']) * 100
        
        if previous_stats['total_value'] > 0:
            value_growth = ((float(current_stats['total_value']) - float(previous_stats['total_value'])) / float(previous_stats['total_value'])) * 100
        
        # Conversion rates
        verification_rate = 0
        if current_stats['count'] > 0:
            verification_rate = (current_stats['verified_count'] / current_stats['count']) * 100
        
        metrics = {
            'current_month': {
                'deal_count': current_stats['count'],
                'total_value': float(current_stats['total_value']),
                'verified_count': current_stats['verified_count'],
                'pending_count': current_stats['pending_count'],
                'verification_rate': round(verification_rate, 2),
            },
            'growth': {
                'count_growth': round(count_growth, 2),
                'value_growth': round(value_growth, 2),
            },
            'previous_month': {
                'deal_count': previous_stats['count'],
                'total_value': float(previous_stats['total_value']),
            },
            'generated_at': timezone.now().isoformat()
        }
        
        # Cache for 15 minutes
        cache.set(cache_key, metrics, 900)
        
        return metrics
    
    @classmethod
    def get_deal_search_suggestions(cls, query, organization=None, limit=10):
        """
        Get search suggestions for deals
        """
        if not query or len(query) < 2:
            return []
        
        queryset = Deal.objects.filter(organization=organization) if organization else Deal.objects.all()
        
        # Search in deal names, IDs, and client names
        suggestions = []
        
        # Deal names
        deal_names = queryset.filter(
            deal_name__icontains=query
        ).values_list('deal_name', flat=True).distinct()[:limit//3]
        
        suggestions.extend([{'type': 'deal_name', 'value': name} for name in deal_names])
        
        # Deal IDs
        deal_ids = queryset.filter(
            deal_id__icontains=query
        ).values_list('deal_id', flat=True).distinct()[:limit//3]
        
        suggestions.extend([{'type': 'deal_id', 'value': deal_id} for deal_id in deal_ids])
        
        # Client names
        client_names = queryset.filter(
            client__client_name__icontains=query
        ).values_list('client__client_name', flat=True).distinct()[:limit//3]
        
        suggestions.extend([{'type': 'client_name', 'value': name} for name in client_names])
        
        return suggestions[:limit]
    
    @classmethod
    def invalidate_deal_caches(cls, organization_id=None):
        """
        Invalidate deal-related caches
        """
        cache_patterns = [
            f"deal_analytics_{organization_id or 'all'}_*",
            f"deal_performance_{organization_id or 'all'}",
        ]
        
        # Note: This is a simplified cache invalidation
        # In production, you might want to use cache versioning or more sophisticated invalidation
        for pattern in cache_patterns:
            cache.delete(pattern)
        
        performance_logger.info(f"Invalidated deal caches for organization {organization_id or 'all'}")


class DealReportingOptimizer:
    """
    Specialized optimizer for deal reporting queries
    """
    
    @classmethod
    def get_financial_summary(cls, organization=None, date_from=None, date_to=None):
        """
        Get optimized financial summary for deals
        """
        queryset = Deal.objects.filter(organization=organization) if organization else Deal.objects.all()
        
        if date_from:
            queryset = queryset.filter(created_at__gte=date_from)
        if date_to:
            queryset = queryset.filter(created_at__lte=date_to)
        
        # Use database aggregation for efficiency
        summary = queryset.aggregate(
            total_deals=Count('id'),
            total_value=Coalesce(Sum('deal_value'), Value(0)),
            verified_value=Coalesce(
                Sum('deal_value', filter=Q(verification_status='verified')), 
                Value(0)
            ),
            pending_value=Coalesce(
                Sum('deal_value', filter=Q(verification_status='pending')), 
                Value(0)
            ),
            rejected_value=Coalesce(
                Sum('deal_value', filter=Q(verification_status='rejected')), 
                Value(0)
            ),
            avg_deal_value=Coalesce(Avg('deal_value'), Value(0)),
        )
        
        return summary
    
    @classmethod
    def get_payment_summary(cls, organization=None, date_from=None, date_to=None):
        """
        Get optimized payment summary
        """
        payment_queryset = Payment.objects.select_related('deal')
        
        if organization:
            payment_queryset = payment_queryset.filter(deal__organization=organization)
        
        if date_from:
            payment_queryset = payment_queryset.filter(created_at__gte=date_from)
        if date_to:
            payment_queryset = payment_queryset.filter(created_at__lte=date_to)
        
        summary = payment_queryset.aggregate(
            total_payments=Count('id'),
            total_amount=Coalesce(Sum('received_amount'), Value(0)),
            avg_payment=Coalesce(Avg('received_amount'), Value(0)),
            max_payment=Coalesce(Max('received_amount'), Value(0)),
        )
        
        return summary