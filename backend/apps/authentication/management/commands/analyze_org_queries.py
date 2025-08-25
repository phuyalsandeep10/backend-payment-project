"""
Management command to analyze organization-scoped query performance
"""

from django.core.management.base import BaseCommand
from django.db import connection
from django.conf import settings
from apps.authentication.models import User
from apps.deals.models import Deal
from apps.organization.models import Organization
from core_config.query_performance_middleware import OrganizationQueryOptimizer
import time


class Command(BaseCommand):
    help = 'Analyze organization-scoped query performance and provide optimization recommendations'

    def add_arguments(self, parser):
        parser.add_argument(
            '--organization',
            type=str,
            help='Specific organization name to analyze'
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Show detailed query analysis'
        )

    def handle(self, *args, **options):
        self.stdout.write(
            self.style.SUCCESS('Starting organization-scoped query analysis...')
        )

        if options['organization']:
            try:
                org = Organization.objects.get(name=options['organization'])
                self.analyze_organization(org, options['verbose'])
            except Organization.DoesNotExist:
                self.stdout.write(
                    self.style.ERROR(f"Organization '{options['organization']}' not found")
                )
        else:
            # Analyze all organizations
            organizations = Organization.objects.all()
            for org in organizations:
                self.analyze_organization(org, options['verbose'])

    def analyze_organization(self, organization, verbose=False):
        """Analyze query performance for a specific organization"""
        self.stdout.write(f"\n=== Analyzing Organization: {organization.name} ===")
        
        # Reset query count
        initial_queries = len(connection.queries)
        start_time = time.time()

        # Test basic user queries
        self.test_user_queries(organization, verbose)
        
        # Test deal queries
        self.test_deal_queries(organization, verbose)
        
        # Test organization stats
        self.test_organization_stats(organization, verbose)

        # Calculate performance metrics
        end_time = time.time()
        total_queries = len(connection.queries) - initial_queries
        total_time = end_time - start_time

        self.stdout.write(
            f"Total Queries: {total_queries}, Total Time: {total_time:.3f}s"
        )

        if total_queries > 20:
            self.stdout.write(
                self.style.WARNING(
                    f"High query count detected for {organization.name}. "
                    "Consider query optimization."
                )
            )

        if total_time > 1.0:
            self.stdout.write(
                self.style.WARNING(
                    f"Slow query performance for {organization.name}. "
                    "Consider database indexing."
                )
            )

    def test_user_queries(self, organization, verbose):
        """Test user-related queries for the organization"""
        self.stdout.write("Testing user queries...")
        
        start_queries = len(connection.queries)
        start_time = time.time()

        # Test unoptimized query
        users_unoptimized = list(User.objects.filter(organization=organization))
        
        mid_queries = len(connection.queries)
        mid_time = time.time()

        # Test optimized query
        users_optimized = list(
            OrganizationQueryOptimizer.optimize_user_queryset(
                User.objects.all(), organization
            )
        )
        
        end_queries = len(connection.queries)
        end_time = time.time()

        unoptimized_queries = mid_queries - start_queries
        unoptimized_time = mid_time - start_time
        optimized_queries = end_queries - mid_queries
        optimized_time = end_time - mid_time

        self.stdout.write(
            f"  Unoptimized: {unoptimized_queries} queries, {unoptimized_time:.3f}s"
        )
        self.stdout.write(
            f"  Optimized: {optimized_queries} queries, {optimized_time:.3f}s"
        )

        if optimized_queries < unoptimized_queries:
            self.stdout.write(
                self.style.SUCCESS(
                    f"  Optimization reduced queries by {unoptimized_queries - optimized_queries}"
                )
            )

        if verbose and connection.queries:
            recent_queries = connection.queries[-5:]  # Last 5 queries
            for i, query in enumerate(recent_queries):
                self.stdout.write(f"    Query {i+1}: {query['time']}s - {query['sql'][:100]}...")

    def test_deal_queries(self, organization, verbose):
        """Test deal-related queries for the organization"""
        self.stdout.write("Testing deal queries...")
        
        start_queries = len(connection.queries)
        start_time = time.time()

        # Test deal queries
        deals = list(Deal.objects.filter(organization=organization)[:10])
        
        end_queries = len(connection.queries)
        end_time = time.time()

        query_count = end_queries - start_queries
        query_time = end_time - start_time

        self.stdout.write(
            f"  Deal queries: {query_count} queries, {query_time:.3f}s for {len(deals)} deals"
        )

        if verbose and connection.queries:
            recent_queries = connection.queries[-3:]  # Last 3 queries
            for i, query in enumerate(recent_queries):
                self.stdout.write(f"    Query {i+1}: {query['time']}s - {query['sql'][:100]}...")

    def test_organization_stats(self, organization, verbose):
        """Test organization statistics queries"""
        self.stdout.write("Testing organization stats...")
        
        start_queries = len(connection.queries)
        start_time = time.time()

        # Get organization stats
        stats = OrganizationQueryOptimizer.get_organization_stats(organization)
        
        end_queries = len(connection.queries)
        end_time = time.time()

        query_count = end_queries - start_queries
        query_time = end_time - start_time

        self.stdout.write(
            f"  Stats queries: {query_count} queries, {query_time:.3f}s"
        )
        self.stdout.write(
            f"  Stats: {stats['user_count']} users, {stats['deal_count']} deals, "
            f"${stats['total_deal_value']:.2f} total value"
        )

        if verbose and connection.queries:
            recent_queries = connection.queries[-query_count:]
            for i, query in enumerate(recent_queries):
                self.stdout.write(f"    Query {i+1}: {query['time']}s - {query['sql'][:100]}...")

    def provide_recommendations(self, organization):
        """Provide optimization recommendations"""
        self.stdout.write(f"\n=== Recommendations for {organization.name} ===")
        
        user_count = User.objects.filter(organization=organization).count()
        deal_count = Deal.objects.filter(organization=organization).count()

        if user_count > 100:
            self.stdout.write(
                "• Consider implementing user pagination for large user lists"
            )

        if deal_count > 1000:
            self.stdout.write(
                "• Consider implementing deal archiving for old deals"
            )
            self.stdout.write(
                "• Use date-based filtering for deal queries"
            )

        self.stdout.write(
            "• Always use select_related() for organization and role fields"
        )
        self.stdout.write(
            "• Use prefetch_related() for related objects like permissions"
        )
        self.stdout.write(
            "• Filter by organization_id instead of organization object for better performance"
        )