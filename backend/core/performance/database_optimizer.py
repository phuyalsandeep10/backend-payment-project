"""
Database Performance Optimization Service
Provides strategic database indexing and ORM query optimization
"""

from django.db import models, connection
from django.core.cache import cache
from django.utils import timezone
from django.db.models import Prefetch, Q, Count, Sum, Avg
from django.conf import settings
from contextlib import contextmanager
import logging
import time
from typing import Dict, List, Optional, Any
import json

logger = logging.getLogger('database_optimizer')

class DatabaseOptimizer:
    """
    Service for database performance optimization including indexing and query optimization
    """
    
    # Cache settings
    QUERY_CACHE_TIMEOUT = 300  # 5 minutes
    INDEX_ANALYSIS_CACHE_TIMEOUT = 3600  # 1 hour
    
    @classmethod
    def analyze_query_performance(cls, query_name: str = None) -> Dict:
        """
        Analyze database query performance and provide optimization recommendations
        """
        cache_key = f"query_analysis_{query_name or 'all'}"
        cached_result = cache.get(cache_key)
        
        if cached_result:
            return cached_result
        
        with connection.cursor() as cursor:
            # Get slow queries from PostgreSQL
            cursor.execute("""
                SELECT query, calls, total_time, mean_time, rows
                FROM pg_stat_statements 
                WHERE query NOT LIKE '%pg_stat_statements%'
                ORDER BY total_time DESC 
                LIMIT 20
            """)
            
            slow_queries = []
            for row in cursor.fetchall():
                slow_queries.append({
                    'query': row[0][:200] + '...' if len(row[0]) > 200 else row[0],
                    'calls': row[1],
                    'total_time': float(row[2]) if row[2] else 0,
                    'mean_time': float(row[3]) if row[3] else 0,
                    'rows': row[4]
                })
            
            # Get index usage statistics
            cursor.execute("""
                SELECT schemaname, tablename, indexname, idx_tup_read, idx_tup_fetch
                FROM pg_stat_user_indexes 
                ORDER BY idx_tup_read DESC 
                LIMIT 20
            """)
            
            index_usage = []
            for row in cursor.fetchall():
                index_usage.append({
                    'schema': row[0],
                    'table': row[1],
                    'index': row[2],
                    'reads': row[3],
                    'fetches': row[4]
                })
            
            # Get table statistics
            cursor.execute("""
                SELECT schemaname, tablename, n_tup_ins, n_tup_upd, n_tup_del, n_tup_hot_upd
                FROM pg_stat_user_tables 
                ORDER BY n_tup_ins + n_tup_upd + n_tup_del DESC 
                LIMIT 20
            """)
            
            table_stats = []
            for row in cursor.fetchall():
                table_stats.append({
                    'schema': row[0],
                    'table': row[1],
                    'inserts': row[2],
                    'updates': row[3],
                    'deletes': row[4],
                    'hot_updates': row[5]
                })
        
        result = {
            'slow_queries': slow_queries,
            'index_usage': index_usage,
            'table_statistics': table_stats,
            'analysis_timestamp': timezone.now().isoformat(),
            'recommendations': cls._generate_optimization_recommendations(slow_queries, index_usage, table_stats)
        }
        
        cache.set(cache_key, result, cls.INDEX_ANALYSIS_CACHE_TIMEOUT)
        return result
    
    @classmethod
    def _generate_optimization_recommendations(cls, slow_queries, index_usage, table_stats) -> List[Dict]:
        """
        Generate optimization recommendations based on query analysis
        """
        recommendations = []
        
        # Analyze slow queries for missing indexes
        for query in slow_queries[:5]:  # Top 5 slow queries
            if query['mean_time'] > 100:  # More than 100ms average
                recommendations.append({
                    'type': 'slow_query',
                    'priority': 'high',
                    'description': f"Query with {query['mean_time']:.2f}ms average time needs optimization",
                    'suggestion': 'Consider adding indexes or optimizing query structure',
                    'query_snippet': query['query'][:100] + '...'
                })
        
        # Analyze unused indexes
        unused_indexes = [idx for idx in index_usage if idx['reads'] < 100]
        if unused_indexes:
            recommendations.append({
                'type': 'unused_indexes',
                'priority': 'medium',
                'description': f"Found {len(unused_indexes)} potentially unused indexes",
                'suggestion': 'Consider removing unused indexes to improve write performance',
                'indexes': [f"{idx['table']}.{idx['index']}" for idx in unused_indexes[:5]]
            })
        
        # Analyze high-activity tables
        high_activity_tables = [t for t in table_stats if (t['inserts'] + t['updates'] + t['deletes']) > 10000]
        for table in high_activity_tables[:3]:
            recommendations.append({
                'type': 'high_activity_table',
                'priority': 'medium',
                'description': f"Table {table['table']} has high activity ({table['inserts'] + table['updates'] + table['deletes']} operations)",
                'suggestion': 'Ensure proper indexing for frequently queried columns',
                'table': table['table']
            })
        
        return recommendations
    
    @classmethod
    def get_missing_indexes_recommendations(cls) -> List[Dict]:
        """
        Analyze models and suggest missing indexes based on common query patterns
        """
        recommendations = []
        
        # Analyze User model
        from apps.authentication.models import User
        user_recommendations = cls._analyze_model_indexes(User, [
            ['organization', 'is_active'],
            ['organization', 'role'],
            ['email', 'is_active'],
            ['organization', 'created_at'],
            ['last_login', 'is_active']
        ])
        recommendations.extend(user_recommendations)
        
        # Analyze Deal model
        from apps.deals.models import Deal
        deal_recommendations = cls._analyze_model_indexes(Deal, [
            ['organization', 'verification_status', 'payment_status'],
            ['organization', 'created_by', 'deal_date'],
            ['organization', 'client', 'verification_status'],
            ['organization', 'deal_value', 'created_at'],
            ['verification_status', 'deal_date'],
            ['payment_status', 'due_date']
        ])
        recommendations.extend(deal_recommendations)
        
        # Analyze Commission model
        from apps.commission.models import Commission
        commission_recommendations = cls._analyze_model_indexes(Commission, [
            ['organization', 'user', 'start_date'],
            ['organization', 'created_at', 'total_sales'],
            ['user', 'start_date', 'end_date'],
            ['organization', 'commission_rate']
        ])
        recommendations.extend(commission_recommendations)
        
        return recommendations
    
    @classmethod
    def _analyze_model_indexes(cls, model_class, suggested_indexes) -> List[Dict]:
        """
        Analyze a model's existing indexes and suggest missing ones
        """
        recommendations = []
        existing_indexes = []
        
        # Get existing indexes from model meta
        if hasattr(model_class._meta, 'indexes'):
            for index in model_class._meta.indexes:
                existing_indexes.append([field.name for field in index.fields])
        
        # Check for missing suggested indexes
        for suggested_index in suggested_indexes:
            if suggested_index not in existing_indexes:
                recommendations.append({
                    'model': model_class.__name__,
                    'table': model_class._meta.db_table,
                    'suggested_index': suggested_index,
                    'reason': f"Composite index on {', '.join(suggested_index)} would optimize common queries",
                    'priority': 'medium'
                })
        
        return recommendations


class QueryOptimizer:
    """
    Service for ORM query optimization with caching and prefetching
    """
    
    @classmethod
    def optimize_user_queryset(cls, queryset=None, organization=None, include_related=False):
        """
        Optimize User queryset with proper select_related and prefetch_related
        """
        from apps.authentication.models import User
        
        if queryset is None:
            queryset = User.objects.all()
        
        # Apply organization filter if provided
        if organization:
            queryset = queryset.filter(organization=organization)
        
        # Optimize with select_related for foreign keys (only valid fields)
        optimized_queryset = queryset.select_related(
            'organization',
            'role',
            'team'
        ).prefetch_related(
            'role__permissions'
        )
        
        # Only add expensive prefetch_related when specifically requested
        if include_related:
            optimized_queryset = optimized_queryset.prefetch_related(
                'created_deals',
                'commissions'
            )
        
        return optimized_queryset
    
    @classmethod
    def optimize_deal_queryset(cls, queryset=None, organization=None, include_payments=False):
        """
        Optimize Deal queryset with proper select_related and prefetch_related
        """
        from apps.deals.models import Deal
        
        if queryset is None:
            queryset = Deal.objects.all()
        
        # Apply organization filter if provided
        if organization:
            queryset = queryset.filter(organization=organization)
        
        # Optimize with select_related for foreign keys
        optimized_queryset = queryset.select_related(
            'organization',
            'client',
            'project',
            'created_by',
            'updated_by'
        )
        
        # Add prefetch_related for reverse foreign keys
        prefetch_list = []
        
        if include_payments:
            prefetch_list.append('payments')
        
        if prefetch_list:
            optimized_queryset = optimized_queryset.prefetch_related(*prefetch_list)
        
        return optimized_queryset
    
    @classmethod
    def optimize_commission_queryset(cls, queryset=None, organization=None):
        """
        Optimize Commission queryset with proper select_related and prefetch_related
        """
        from apps.commission.models import Commission
        
        if queryset is None:
            queryset = Commission.objects.all()
        
        # Apply organization filter if provided
        if organization:
            queryset = queryset.filter(organization=organization)
        
        # Optimize with select_related for foreign keys (only valid fields)
        optimized_queryset = queryset.select_related(
            'organization',
            'user'
        )
        
        return optimized_queryset
    
    @classmethod
    def get_cached_organization_data(cls, organization_id: int, cache_timeout: int = 300) -> Dict:
        """
        Get frequently accessed organization data with caching
        """
        cache_key = f"org_data_{organization_id}"
        cached_data = cache.get(cache_key)
        
        if cached_data:
            return cached_data
        
        from apps.organization.models import Organization
        from apps.authentication.models import User
        from apps.deals.models import Deal
        from apps.commission.models import Commission
        
        try:
            organization = Organization.objects.get(id=organization_id)
            
            # Get aggregated data
            user_stats = User.objects.filter(organization=organization).aggregate(
                total_users=Count('id'),
                active_users=Count('id', filter=Q(is_active=True))
            )
            
            deal_stats = Deal.objects.filter(organization=organization).aggregate(
                total_deals=Count('id'),
                verified_deals=Count('id', filter=Q(verification_status='verified')),
                total_deal_value=Sum('deal_value'),
                avg_deal_value=Avg('deal_value')
            )
            
            commission_stats = Commission.objects.filter(organization=organization).aggregate(
                total_commissions=Count('id'),
                total_commission_amount=Sum('total_commission'),
                avg_commission_rate=Avg('commission_rate')
            )
            
            org_data = {
                'organization': {
                    'id': organization.id,
                    'name': organization.name,
                    'created_at': organization.created_at.isoformat()
                },
                'user_stats': user_stats,
                'deal_stats': deal_stats,
                'commission_stats': commission_stats,
                'cached_at': timezone.now().isoformat()
            }
            
            cache.set(cache_key, org_data, cache_timeout)
            return org_data
            
        except Organization.DoesNotExist:
            return {}
    
    @classmethod
    def invalidate_organization_cache(cls, organization_id: int):
        """
        Invalidate cached organization data
        """
        cache_key = f"org_data_{organization_id}"
        cache.delete(cache_key)
        logger.info(f"Invalidated organization cache for org {organization_id}")


class QueryMonitor:
    """
    Service for monitoring database query performance
    """
    
    @classmethod
    @contextmanager
    def monitor_query(cls, query_name: str, log_slow_queries: bool = True, slow_threshold: float = 0.1):
        """
        Context manager to monitor query execution time
        """
        start_time = time.time()
        initial_queries = len(connection.queries)
        
        try:
            yield
        finally:
            end_time = time.time()
            execution_time = end_time - start_time
            query_count = len(connection.queries) - initial_queries
            
            # Log query performance
            logger.info(f"Query '{query_name}': {execution_time:.3f}s, {query_count} queries")
            
            # Log slow queries
            if log_slow_queries and execution_time > slow_threshold:
                logger.warning(f"Slow query detected: '{query_name}' took {execution_time:.3f}s")
                
                # Log the actual SQL queries if in debug mode
                if settings.DEBUG and query_count > 0:
                    recent_queries = connection.queries[-query_count:]
                    for i, query in enumerate(recent_queries):
                        logger.debug(f"Query {i+1}: {query['sql'][:200]}... ({query['time']}s)")
    
    @classmethod
    def get_query_statistics(cls) -> Dict:
        """
        Get current query statistics
        """
        if not settings.DEBUG:
            return {'error': 'Query statistics only available in DEBUG mode'}
        
        total_queries = len(connection.queries)
        if total_queries == 0:
            return {'total_queries': 0}
        
        # Analyze query times
        query_times = [float(q['time']) for q in connection.queries]
        
        return {
            'total_queries': total_queries,
            'total_time': sum(query_times),
            'avg_time': sum(query_times) / len(query_times),
            'max_time': max(query_times),
            'min_time': min(query_times),
            'slow_queries': len([t for t in query_times if t > 0.1])
        }


class OptimizedQueryMixin:
    """
    Mixin to add optimized query methods to ViewSets
    """
    
    def get_optimized_queryset(self):
        """
        Get optimized queryset based on the model type
        """
        queryset = self.get_queryset()
        model_class = queryset.model
        
        # Get user's organization for filtering
        organization = getattr(self.request.user, 'organization', None)
        
        if model_class.__name__ == 'User':
            return QueryOptimizer.optimize_user_queryset(queryset, organization)
        elif model_class.__name__ == 'Deal':
            include_payments = 'payments' in self.request.query_params.get('include', '')
            return QueryOptimizer.optimize_deal_queryset(queryset, organization, include_payments)
        elif model_class.__name__ == 'Commission':
            return QueryOptimizer.optimize_commission_queryset(queryset, organization)
        else:
            return queryset
    
    def list(self, request, *args, **kwargs):
        """
        Override list method to use optimized queryset and query monitoring
        """
        with QueryMonitor.monitor_query(f"{self.__class__.__name__}.list"):
            # Use optimized queryset
            self.queryset = self.get_optimized_queryset()
            return super().list(request, *args, **kwargs)
    
    def retrieve(self, request, *args, **kwargs):
        """
        Override retrieve method with query monitoring
        """
        with QueryMonitor.monitor_query(f"{self.__class__.__name__}.retrieve"):
            return super().retrieve(request, *args, **kwargs)