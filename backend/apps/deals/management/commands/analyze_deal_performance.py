"""
Management command to analyze deal query performance and provide optimization recommendations
"""

from django.core.management.base import BaseCommand
from django.db import connection
from django.utils import timezone
from django.conf import settings
from apps.deals.models import Deal, Payment
from deals.query_optimizer import DealQueryOptimizer, DealReportingOptimizer
from apps.organization.models import Organization
import time


class Command(BaseCommand):
    help = 'Analyze deal query performance and provide optimization recommendations'

    def add_arguments(self, parser):
        parser.add_argument(
            '--organization',
            type=str,
            help='Specific organization name to analyze'
        )
        parser.add_argument(
            '--test-queries',
            action='store_true',
            help='Run performance tests on common deal queries'
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Show detailed query analysis'
        )
        parser.add_argument(
            '--benchmark',
            action='store_true',
            help='Run benchmark tests comparing optimized vs unoptimized queries'
        )

    def handle(self, *args, **options):
        self.stdout.write(
            self.style.SUCCESS('Starting deal query performance analysis...')
        )

        organization = None
        if options['organization']:
            try:
                organization = Organization.objects.get(name=options['organization'])
                self.stdout.write(f"Analyzing organization: {organization.name}")
            except Organization.DoesNotExist:
                self.stdout.write(
                    self.style.ERROR(f"Organization '{options['organization']}' not found")
                )
                return

        if options['test_queries']:
            self.test_common_queries(organization, options['verbose'])
        
        if options['benchmark']:
            self.run_benchmark_tests(organization, options['verbose'])
        
        # Always run basic analysis
        self.analyze_deal_data(organization, options['verbose'])
        self.provide_recommendations(organization)

    def test_common_queries(self, organization, verbose):
        """Test performance of common deal queries"""
        self.stdout.write("\n=== Testing Common Deal Queries ===")
        
        queries_to_test = [
            {
                'name': 'List all deals with basic filters',
                'test': lambda: self._test_deal_list_query(organization)
            },
            {
                'name': 'Deal analytics query',
                'test': lambda: self._test_analytics_query(organization)
            },
            {
                'name': 'Financial summary query',
                'test': lambda: self._test_financial_summary_query(organization)
            },
            {
                'name': 'Deal search query',
                'test': lambda: self._test_search_query(organization)
            },
            {
                'name': 'Paginated deal query',
                'test': lambda: self._test_pagination_query(organization)
            }
        ]
        
        for query_test in queries_to_test:
            self.stdout.write(f"\nTesting: {query_test['name']}")
            
            start_time = time.time()
            start_queries = len(connection.queries)
            
            try:
                result = query_test['test']()
                
                end_time = time.time()
                end_queries = len(connection.queries)
                
                query_time = end_time - start_time
                query_count = end_queries - start_queries
                
                self.stdout.write(
                    f"  Time: {query_time:.3f}s, Queries: {query_count}, Result count: {result.get('count', 'N/A')}"
                )
                
                if verbose and query_count > 0:
                    recent_queries = connection.queries[-query_count:]
                    for i, query in enumerate(recent_queries):
                        self.stdout.write(f"    Query {i+1}: {query['time']}s - {query['sql'][:100]}...")
                
                # Performance warnings
                if query_time > 1.0:
                    self.stdout.write(
                        self.style.WARNING(f"  SLOW QUERY: {query_test['name']} took {query_time:.3f}s")
                    )
                
                if query_count > 10:
                    self.stdout.write(
                        self.style.WARNING(f"  HIGH QUERY COUNT: {query_test['name']} used {query_count} queries")
                    )
                
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f"  ERROR: {str(e)}")
                )

    def _test_deal_list_query(self, organization):
        """Test deal list query performance"""
        filters = {
            'verification_status': ['pending', 'verified'],
            'date_from': timezone.now().date() - timezone.timedelta(days=30)
        }
        
        queryset = DealQueryOptimizer.get_deals_with_filters(
            organization=organization,
            filters=filters
        )
        
        count = queryset.count()
        list(queryset[:25])  # Force evaluation of first 25 items
        
        return {'count': count}

    def _test_analytics_query(self, organization):
        """Test analytics query performance"""
        analytics = DealQueryOptimizer.get_deal_analytics(
            organization=organization,
            date_from=timezone.now() - timezone.timedelta(days=90)
        )
        
        return {'count': analytics['basic_stats']['total_deals']}

    def _test_financial_summary_query(self, organization):
        """Test financial summary query performance"""
        summary = DealReportingOptimizer.get_financial_summary(
            organization=organization,
            date_from=timezone.now() - timezone.timedelta(days=30)
        )
        
        return {'count': summary['total_deals']}

    def _test_search_query(self, organization):
        """Test search query performance"""
        suggestions = DealQueryOptimizer.get_deal_search_suggestions(
            query='test',
            organization=organization,
            limit=10
        )
        
        return {'count': len(suggestions)}

    def _test_pagination_query(self, organization):
        """Test pagination query performance"""
        queryset = DealQueryOptimizer.get_optimized_deal_queryset(organization)
        
        paginated = DealQueryOptimizer.get_paginated_deals(
            queryset=queryset,
            page=1,
            page_size=25
        )
        
        return {'count': paginated['pagination']['total_count']}

    def run_benchmark_tests(self, organization, verbose):
        """Run benchmark tests comparing optimized vs unoptimized queries"""
        self.stdout.write("\n=== Running Benchmark Tests ===")
        
        # Test 1: Basic deal listing
        self.stdout.write("\nBenchmark 1: Deal Listing")
        
        # Unoptimized query
        start_time = time.time()
        start_queries = len(connection.queries)
        
        unoptimized_deals = list(Deal.objects.filter(
            organization=organization
        )[:25]) if organization else list(Deal.objects.all()[:25])
        
        unopt_time = time.time() - start_time
        unopt_queries = len(connection.queries) - start_queries
        
        # Optimized query
        start_time = time.time()
        start_queries = len(connection.queries)
        
        optimized_queryset = DealQueryOptimizer.get_optimized_deal_queryset(organization)
        optimized_deals = list(optimized_queryset[:25])
        
        opt_time = time.time() - start_time
        opt_queries = len(connection.queries) - start_queries
        
        self.stdout.write(f"  Unoptimized: {unopt_time:.3f}s, {unopt_queries} queries")
        self.stdout.write(f"  Optimized: {opt_time:.3f}s, {opt_queries} queries")
        
        if opt_time < unopt_time:
            improvement = ((unopt_time - opt_time) / unopt_time) * 100
            self.stdout.write(
                self.style.SUCCESS(f"  Improvement: {improvement:.1f}% faster")
            )
        
        # Test 2: Deal with payments
        self.stdout.write("\nBenchmark 2: Deals with Payment Data")
        
        # Unoptimized
        start_time = time.time()
        start_queries = len(connection.queries)
        
        for deal in unoptimized_deals[:10]:
            total_paid = deal.get_total_paid_amount()  # This might cause N+1 queries
        
        unopt_time = time.time() - start_time
        unopt_queries = len(connection.queries) - start_queries
        
        # Optimized (with prefetch_related)
        start_time = time.time()
        start_queries = len(connection.queries)
        
        for deal in optimized_deals[:10]:
            total_paid = deal.get_total_paid_amount()
        
        opt_time = time.time() - start_time
        opt_queries = len(connection.queries) - start_queries
        
        self.stdout.write(f"  Unoptimized: {unopt_time:.3f}s, {unopt_queries} queries")
        self.stdout.write(f"  Optimized: {opt_time:.3f}s, {opt_queries} queries")
        
        if opt_queries < unopt_queries:
            query_reduction = ((unopt_queries - opt_queries) / unopt_queries) * 100
            self.stdout.write(
                self.style.SUCCESS(f"  Query Reduction: {query_reduction:.1f}%")
            )

    def analyze_deal_data(self, organization, verbose):
        """Analyze deal data and performance characteristics"""
        self.stdout.write("\n=== Deal Data Analysis ===")
        
        # Basic statistics
        if organization:
            total_deals = Deal.objects.filter(organization=organization).count()
            total_payments = Payment.objects.filter(deal__organization=organization).count()
        else:
            total_deals = Deal.objects.count()
            total_payments = Payment.objects.count()
        
        self.stdout.write(f"Total Deals: {total_deals}")
        self.stdout.write(f"Total Payments: {total_payments}")
        
        if total_deals > 0:
            avg_payments_per_deal = total_payments / total_deals
            self.stdout.write(f"Average Payments per Deal: {avg_payments_per_deal:.2f}")
        
        # Index usage analysis
        if verbose:
            self.stdout.write("\nIndex Usage Analysis:")
            
            # Check for deals without proper indexing patterns
            recent_deals = Deal.objects.filter(
                created_at__gte=timezone.now() - timezone.timedelta(days=30)
            )
            
            if organization:
                recent_deals = recent_deals.filter(organization=organization)
            
            status_distribution = {}
            for status_choice in Deal.DEAL_STATUS:
                status = status_choice[0]
                count = recent_deals.filter(verification_status=status).count()
                status_distribution[status] = count
            
            self.stdout.write("  Recent Deal Status Distribution:")
            for status, count in status_distribution.items():
                self.stdout.write(f"    {status}: {count}")
            
            # Payment method distribution
            payment_methods = {}
            for method_choice in Deal.PAYMENT_METHOD_CHOICES:
                method = method_choice[0]
                count = recent_deals.filter(payment_method=method).count()
                payment_methods[method] = count
            
            self.stdout.write("  Payment Method Distribution:")
            for method, count in payment_methods.items():
                self.stdout.write(f"    {method}: {count}")

    def provide_recommendations(self, organization):
        """Provide optimization recommendations"""
        self.stdout.write("\n=== Optimization Recommendations ===")
        
        # Analyze data patterns
        if organization:
            deals = Deal.objects.filter(organization=organization)
            payments = Payment.objects.filter(deal__organization=organization)
        else:
            deals = Deal.objects.all()
            payments = Payment.objects.all()
        
        total_deals = deals.count()
        total_payments = payments.count()
        
        recommendations = []
        
        # Volume-based recommendations
        if total_deals > 10000:
            recommendations.append("• Consider implementing deal archiving for old deals")
            recommendations.append("• Use date-based partitioning for very large datasets")
        
        if total_deals > 1000:
            recommendations.append("• Always use pagination for deal listings")
            recommendations.append("• Implement caching for frequently accessed deal analytics")
        
        # Query pattern recommendations
        recommendations.append("• Always use select_related() for organization, client, and user fields")
        recommendations.append("• Use prefetch_related() for payments and approvals when needed")
        recommendations.append("• Filter by organization_id instead of organization object for better performance")
        
        # Index recommendations
        if total_deals > 5000:
            recommendations.append("• Consider adding custom indexes for frequently filtered combinations")
            recommendations.append("• Monitor slow query logs and add indexes accordingly")
        
        # Caching recommendations
        recommendations.append("• Cache deal analytics and dashboard data for 15-30 minutes")
        recommendations.append("• Use Redis for session-based deal filters and search results")
        
        # Performance monitoring
        recommendations.append("• Monitor query performance with the analyze_deal_performance command")
        recommendations.append("• Set up alerts for queries taking longer than 1 second")
        
        self.stdout.write("Recommendations:")
        for rec in recommendations:
            self.stdout.write(rec)
        
        # Database-specific recommendations
        self.stdout.write("\nDatabase Optimization:")
        self.stdout.write("• Ensure PostgreSQL has adequate shared_buffers and work_mem")
        self.stdout.write("• Run ANALYZE on deal and payment tables after bulk operations")
        self.stdout.write("• Consider connection pooling for high-traffic applications")
        
        self.stdout.write(f"\nAnalysis completed at: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}")