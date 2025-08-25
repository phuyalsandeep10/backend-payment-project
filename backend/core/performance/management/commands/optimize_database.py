"""
Database Performance Optimization Management Command
Provides tools for analyzing and optimizing database performance
"""

from django.core.management.base import BaseCommand
from django.db import connection
from django.utils import timezone
from core_config.database_optimizer import DatabaseOptimizer, QueryOptimizer
from organization.models import Organization
import logging

logger = logging.getLogger('database_optimizer')

class Command(BaseCommand):
    help = 'Database performance optimization and analysis tools'

    def add_arguments(self, parser):
        parser.add_argument(
            '--action',
            type=str,
            choices=['analyze', 'recommend', 'test-queries', 'cache-warmup', 'monitor'],
            required=True,
            help='Action to perform'
        )
        
        parser.add_argument(
            '--organization-id',
            type=int,
            help='Organization ID for testing (optional)'
        )
        
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Show detailed output'
        )

    def handle(self, *args, **options):
        action = options['action']
        organization_id = options.get('organization_id')
        verbose = options.get('verbose', False)
        
        self.stdout.write(f"Running database optimization: {action}")
        
        try:
            if action == 'analyze':
                self.analyze_performance(verbose)
            elif action == 'recommend':
                self.show_recommendations(verbose)
            elif action == 'test-queries':
                self.test_query_optimization(organization_id, verbose)
            elif action == 'cache-warmup':
                self.warmup_caches(organization_id, verbose)
            elif action == 'monitor':
                self.monitor_queries(verbose)
                
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Database optimization failed: {str(e)}')
            )
            logger.error(f"Database optimization error: {str(e)}")

    def analyze_performance(self, verbose):
        """Analyze database performance"""
        self.stdout.write("Analyzing database performance...")
        
        try:
            analysis = DatabaseOptimizer.analyze_query_performance()
            
            self.stdout.write(f"Analysis completed at: {analysis['analysis_timestamp']}")
            
            # Show slow queries
            slow_queries = analysis['slow_queries']
            self.stdout.write(f"\nSlow Queries ({len(slow_queries)} found):")
            
            for i, query in enumerate(slow_queries[:5], 1):
                self.stdout.write(f"  {i}. Average time: {query['mean_time']:.2f}ms, Calls: {query['calls']}")
                if verbose:
                    self.stdout.write(f"     Query: {query['query'][:100]}...")
            
            # Show index usage
            index_usage = analysis['index_usage']
            self.stdout.write(f"\nTop Index Usage ({len(index_usage)} indexes):")
            
            for i, idx in enumerate(index_usage[:5], 1):
                self.stdout.write(f"  {i}. {idx['table']}.{idx['index']}: {idx['reads']} reads, {idx['fetches']} fetches")
            
            # Show table statistics
            table_stats = analysis['table_statistics']
            self.stdout.write(f"\nTable Activity ({len(table_stats)} tables):")
            
            for i, table in enumerate(table_stats[:5], 1):
                total_ops = table['inserts'] + table['updates'] + table['deletes']
                self.stdout.write(f"  {i}. {table['table']}: {total_ops} total operations")
                if verbose:
                    self.stdout.write(f"     Inserts: {table['inserts']}, Updates: {table['updates']}, Deletes: {table['deletes']}")
            
            self.stdout.write(self.style.SUCCESS("Performance analysis completed"))
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Performance analysis failed: {str(e)}"))

    def show_recommendations(self, verbose):
        """Show optimization recommendations"""
        self.stdout.write("Generating optimization recommendations...")
        
        try:
            # Get performance analysis recommendations
            analysis = DatabaseOptimizer.analyze_query_performance()
            recommendations = analysis.get('recommendations', [])
            
            self.stdout.write(f"\nPerformance Recommendations ({len(recommendations)} found):")
            
            for i, rec in enumerate(recommendations, 1):
                priority_style = self.style.ERROR if rec['priority'] == 'high' else self.style.WARNING
                self.stdout.write(f"  {i}. [{rec['priority'].upper()}] {rec['description']}")
                self.stdout.write(f"     Suggestion: {rec['suggestion']}")
                
                if verbose and 'query_snippet' in rec:
                    self.stdout.write(f"     Query: {rec['query_snippet']}")
            
            # Get missing index recommendations
            missing_indexes = DatabaseOptimizer.get_missing_indexes_recommendations()
            
            self.stdout.write(f"\nMissing Index Recommendations ({len(missing_indexes)} found):")
            
            for i, idx in enumerate(missing_indexes, 1):
                self.stdout.write(f"  {i}. {idx['model']}: {', '.join(idx['suggested_index'])}")
                self.stdout.write(f"     Reason: {idx['reason']}")
            
            self.stdout.write(self.style.SUCCESS("Recommendations generated"))
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Recommendation generation failed: {str(e)}"))

    def test_query_optimization(self, organization_id, verbose):
        """Test query optimization performance"""
        self.stdout.write("Testing query optimization...")
        
        # Get test organization
        if organization_id:
            try:
                organization = Organization.objects.get(id=organization_id)
            except Organization.DoesNotExist:
                self.stdout.write(self.style.ERROR(f'Organization {organization_id} not found'))
                return
        else:
            organization = Organization.objects.first()
            if not organization:
                self.stdout.write(self.style.ERROR('No organizations found'))
                return
        
        self.stdout.write(f"Testing with organization: {organization.name}")
        
        try:
            from apps.authentication.models import User
            from deals.models import Deal
            from commission.models import Commission
            import time
            
            # Test User query optimization
            start_time = time.time()
            initial_queries = len(connection.queries)
            
            # Unoptimized query
            users_unoptimized = list(User.objects.filter(organization=organization)[:10])
            
            unoptimized_time = time.time() - start_time
            unoptimized_queries = len(connection.queries) - initial_queries
            
            # Reset query count
            connection.queries_log.clear()
            
            # Optimized query
            start_time = time.time()
            initial_queries = len(connection.queries)
            
            users_optimized = list(QueryOptimizer.optimize_user_queryset(
                User.objects.filter(organization=organization)
            )[:10])
            
            optimized_time = time.time() - start_time
            optimized_queries = len(connection.queries) - initial_queries
            
            self.stdout.write(f"\nUser Query Optimization Results:")
            self.stdout.write(f"  Unoptimized: {unoptimized_time:.3f}s, {unoptimized_queries} queries")
            self.stdout.write(f"  Optimized: {optimized_time:.3f}s, {optimized_queries} queries")
            
            if optimized_time < unoptimized_time:
                improvement = ((unoptimized_time - optimized_time) / unoptimized_time) * 100
                self.stdout.write(self.style.SUCCESS(f"  Improvement: {improvement:.1f}% faster"))
            
            # Test Deal query optimization
            connection.queries_log.clear()
            
            start_time = time.time()
            deals_optimized = list(QueryOptimizer.optimize_deal_queryset(
                Deal.objects.filter(organization=organization)
            )[:10])
            
            deal_time = time.time() - start_time
            deal_queries = len(connection.queries)
            
            self.stdout.write(f"\nDeal Query Optimization:")
            self.stdout.write(f"  Optimized query: {deal_time:.3f}s, {deal_queries} queries")
            
            self.stdout.write(self.style.SUCCESS("Query optimization testing completed"))
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Query optimization testing failed: {str(e)}"))

    def warmup_caches(self, organization_id, verbose):
        """Warm up query result caches"""
        self.stdout.write("Warming up query caches...")
        
        # Get organizations to warm up
        if organization_id:
            organizations = Organization.objects.filter(id=organization_id)
        else:
            organizations = Organization.objects.all()[:5]  # Limit to 5 for performance
        
        warmed_count = 0
        
        for organization in organizations:
            try:
                # Warm up organization data cache
                org_data = QueryOptimizer.get_cached_organization_data(organization.id)
                
                self.stdout.write(f"  Warmed cache for: {organization.name}")
                if verbose:
                    self.stdout.write(f"    Users: {org_data.get('user_stats', {}).get('total_users', 0)}")
                    self.stdout.write(f"    Deals: {org_data.get('deal_stats', {}).get('total_deals', 0)}")
                    self.stdout.write(f"    Commissions: {org_data.get('commission_stats', {}).get('total_commissions', 0)}")
                
                warmed_count += 1
                
            except Exception as e:
                self.stdout.write(f"  Failed to warm cache for {organization.name}: {str(e)}")
        
        self.stdout.write(self.style.SUCCESS(f"Cache warmup completed for {warmed_count} organizations"))

    def monitor_queries(self, verbose):
        """Monitor current query performance"""
        self.stdout.write("Monitoring query performance...")
        
        try:
            from core_config.database_optimizer import QueryMonitor
            
            # Get current query statistics
            stats = QueryMonitor.get_query_statistics()
            
            if 'error' in stats:
                self.stdout.write(self.style.WARNING(stats['error']))
                return
            
            self.stdout.write(f"\nCurrent Query Statistics:")
            self.stdout.write(f"  Total queries: {stats['total_queries']}")
            self.stdout.write(f"  Total time: {stats['total_time']:.3f}s")
            self.stdout.write(f"  Average time: {stats['avg_time']:.3f}s")
            self.stdout.write(f"  Max time: {stats['max_time']:.3f}s")
            self.stdout.write(f"  Min time: {stats['min_time']:.3f}s")
            self.stdout.write(f"  Slow queries (>100ms): {stats['slow_queries']}")
            
            if verbose and stats['total_queries'] > 0:
                self.stdout.write("\nRecent queries:")
                for i, query in enumerate(connection.queries[-5:], 1):
                    self.stdout.write(f"  {i}. {query['time']}s: {query['sql'][:100]}...")
            
            self.stdout.write(self.style.SUCCESS("Query monitoring completed"))
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Query monitoring failed: {str(e)}"))