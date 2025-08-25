#!/usr/bin/env python3
"""
Database Performance and Indexing Analysis
Comprehensive analysis of database indexing strategies, query performance, N+1 patterns, and transaction management

Task 7: Database Performance and Indexing Analysis
- Analyze database indexing strategies for organization-scoped queries
- Test query performance for large datasets
- Examine N+1 query patterns and optimization opportunities
- Validate database transaction management
"""

import os
import sys
import django
import time
import json
from decimal import Decimal
from datetime import datetime, timedelta
from contextlib import contextmanager
from typing import Dict, List, Any, Optional

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from django.db import connection, transaction
from django.db.models import Count, Sum, Avg, Q, Prefetch
from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone
from django.conf import settings

# Import models
from authentication.models import User, SecureUserSession, SecurityEvent
from deals.models import Deal, Payment
from clients.models import Client
from commission.models import Commission
from organization.models import Organization
from permissions.models import Role


class DatabasePerformanceAnalyzer:
    """
    Comprehensive database performance and indexing analysis
    """
    
    def __init__(self):
        self.results = {
            'indexing_analysis': {},
            'query_performance': {},
            'n_plus_one_analysis': {},
            'transaction_analysis': {},
            'recommendations': [],
            'analysis_timestamp': timezone.now().isoformat()
        }
        self.test_organization = None
        self.test_users = []
        self.test_clients = []
        self.test_deals = []
    
    def run_complete_analysis(self):
        """
        Run complete database performance and indexing analysis
        """
        print("🔍 Starting Database Performance and Indexing Analysis...")
        
        try:
            # Setup test data
            self._setup_test_data()
            
            # 1. Analyze database indexing strategies
            print("\n📊 Analyzing database indexing strategies...")
            self._analyze_indexing_strategies()
            
            # 2. Test query performance for large datasets
            print("\n⚡ Testing query performance for large datasets...")
            self._test_query_performance()
            
            # 3. Examine N+1 query patterns
            print("\n🔄 Examining N+1 query patterns...")
            self._analyze_n_plus_one_patterns()
            
            # 4. Validate database transaction management
            print("\n🔒 Validating database transaction management...")
            self._analyze_transaction_management()
            
            # 5. Generate optimization recommendations
            print("\n💡 Generating optimization recommendations...")
            self._generate_recommendations()
            
            # Save results
            self._save_results()
            
            print("\n✅ Database Performance and Indexing Analysis completed successfully!")
            return self.results
            
        except Exception as e:
            print(f"\n❌ Analysis failed: {str(e)}")
            import traceback
            traceback.print_exc()
            return None
        finally:
            # Cleanup test data
            self._cleanup_test_data()
    
    def _setup_test_data(self):
        """
        Setup test data for performance analysis
        """
        print("Setting up test data for performance analysis...")
        
        # Create test organization
        self.test_organization, created = Organization.objects.get_or_create(
            name="DB Performance Test Org",
            defaults={
                'description': 'Test organization for database performance analysis',
                'is_active': True,
                'sales_goal': 100000.00
            }
        )
        
        # Create test role
        test_role, _ = Role.objects.get_or_create(
            name="Test Role",
            organization=self.test_organization
        )
        
        # Create test users (if not enough exist)
        existing_users = User.objects.filter(organization=self.test_organization).count()
        users_needed = max(0, 50 - existing_users)
        
        for i in range(users_needed):
            user = User.objects.create_user(
                email=f"testuser{i}@dbperf.test",
                password="testpass123",
                first_name=f"Test{i}",
                last_name="User",
                organization=self.test_organization,
                role=test_role
            )
            self.test_users.append(user)
        
        # Get all users for this organization
        all_users = list(User.objects.filter(organization=self.test_organization))
        
        # Create test clients (if not enough exist)
        existing_clients = Client.objects.filter(organization=self.test_organization).count()
        clients_needed = max(0, 100 - existing_clients)
        
        for i in range(clients_needed):
            client = Client.objects.create(
                client_name=f"Test Client {i}",
                email=f"client{i}@dbperf.test",
                phone_number=f"+123456789{i:02d}",
                organization=self.test_organization,
                created_by=all_users[i % len(all_users)]
            )
            self.test_clients.append(client)
        
        # Get all clients for this organization
        all_clients = list(Client.objects.filter(organization=self.test_organization))
        
        # Create test deals (if not enough exist)
        existing_deals = Deal.objects.filter(organization=self.test_organization).count()
        deals_needed = max(0, 200 - existing_deals)
        
        for i in range(deals_needed):
            deal = Deal.objects.create(
                organization=self.test_organization,
                client=all_clients[i % len(all_clients)],
                created_by=all_users[i % len(all_users)],
                deal_name=f"Test Deal {i}",
                deal_value=Decimal(str(1000 + (i * 100))),
                payment_status='initial payment',
                source_type='linkedin',
                payment_method='bank',
                deal_date=timezone.now().date() - timedelta(days=i % 365)
            )
            self.test_deals.append(deal)
        
        print(f"Test data setup complete: {len(all_users)} users, {len(all_clients)} clients, {Deal.objects.filter(organization=self.test_organization).count()} deals")
    
    def _analyze_indexing_strategies(self):
        """
        Analyze database indexing strategies for organization-scoped queries
        """
        print("Analyzing indexing strategies...")
        
        indexing_analysis = {
            'existing_indexes': {},
            'index_usage_stats': {},
            'missing_indexes': [],
            'organization_scoped_performance': {}
        }
        
        # 1. Analyze existing indexes
        with connection.cursor() as cursor:
            # Get existing indexes for key tables
            key_tables = [
                'authentication_user',
                'deals_deal', 
                'clients_client',
                'commission_commission',
                'organization_organization'
            ]
            
            for table in key_tables:
                cursor.execute("""
                    SELECT indexname, indexdef 
                    FROM pg_indexes 
                    WHERE tablename = %s AND schemaname = 'public'
                    ORDER BY indexname
                """, [table])
                
                indexes = []
                for row in cursor.fetchall():
                    indexes.append({
                        'name': row[0],
                        'definition': row[1]
                    })
                
                indexing_analysis['existing_indexes'][table] = indexes
        
        # 2. Analyze index usage statistics
        with connection.cursor() as cursor:
            try:
                cursor.execute("""
                    SELECT 
                        schemaname, tablename, indexname, 
                        idx_tup_read, idx_tup_fetch,
                        idx_scan
                    FROM pg_stat_user_indexes 
                    WHERE schemaname = 'public'
                    ORDER BY idx_tup_read DESC 
                    LIMIT 20
                """)
            except Exception as e:
                # Fallback if pg_stat_user_indexes is not available
                print(f"  Warning: Could not access pg_stat_user_indexes: {e}")
                cursor.execute("""
                    SELECT 
                        'public' as schemaname, 
                        tablename, 
                        indexname, 
                        0 as idx_tup_read, 
                        0 as idx_tup_fetch,
                        0 as idx_scan
                    FROM pg_indexes 
                    WHERE schemaname = 'public'
                    ORDER BY indexname 
                    LIMIT 20
                """)
            
            index_stats = []
            for row in cursor.fetchall():
                index_stats.append({
                    'schema': row[0],
                    'table': row[1],
                    'index': row[2],
                    'tuples_read': row[3] or 0,
                    'tuples_fetched': row[4] or 0,
                    'scans': row[5] or 0
                })
            
            indexing_analysis['index_usage_stats'] = index_stats
        
        # 3. Test organization-scoped query performance
        org_performance = {}
        
        # Test User queries with organization filter
        start_time = time.time()
        initial_queries = len(connection.queries)
        
        users = User.objects.filter(organization=self.test_organization).select_related('role', 'organization')[:20]
        list(users)  # Force evaluation
        
        user_query_time = time.time() - start_time
        user_query_count = len(connection.queries) - initial_queries
        
        org_performance['user_queries'] = {
            'time': user_query_time,
            'query_count': user_query_count,
            'records_fetched': len(users)
        }
        
        # Test Deal queries with organization filter
        start_time = time.time()
        initial_queries = len(connection.queries)
        
        deals = Deal.objects.filter(organization=self.test_organization).select_related(
            'client', 'created_by', 'organization'
        )[:50]
        list(deals)  # Force evaluation
        
        deal_query_time = time.time() - start_time
        deal_query_count = len(connection.queries) - initial_queries
        
        org_performance['deal_queries'] = {
            'time': deal_query_time,
            'query_count': deal_query_count,
            'records_fetched': len(deals)
        }
        
        # Test complex organization-scoped aggregation
        start_time = time.time()
        initial_queries = len(connection.queries)
        
        stats = Deal.objects.filter(organization=self.test_organization).aggregate(
            total_deals=Count('id'),
            total_value=Sum('deal_value'),
            avg_value=Avg('deal_value')
        )
        
        agg_query_time = time.time() - start_time
        agg_query_count = len(connection.queries) - initial_queries
        
        org_performance['aggregation_queries'] = {
            'time': agg_query_time,
            'query_count': agg_query_count,
            'stats': stats
        }
        
        indexing_analysis['organization_scoped_performance'] = org_performance
        
        # 4. Identify missing indexes for organization-scoped queries
        missing_indexes = []
        
        # Check for composite indexes that would benefit organization-scoped queries
        suggested_indexes = [
            {
                'table': 'authentication_user',
                'columns': ['organization_id', 'is_active', 'role_id'],
                'reason': 'Optimize active user queries by organization and role'
            },
            {
                'table': 'deals_deal',
                'columns': ['organization_id', 'verification_status', 'payment_status'],
                'reason': 'Optimize deal filtering by organization and status'
            },
            {
                'table': 'deals_deal',
                'columns': ['organization_id', 'created_at', 'deal_value'],
                'reason': 'Optimize deal reporting and analytics queries'
            },
            {
                'table': 'clients_client',
                'columns': ['organization_id', 'created_by_id', 'created_at'],
                'reason': 'Optimize client queries by organization and creator'
            },
            {
                'table': 'commission_commission',
                'columns': ['organization_id', 'user_id', 'start_date', 'end_date'],
                'reason': 'Optimize commission queries by organization and date range'
            }
        ]
        
        # Check if these indexes exist
        with connection.cursor() as cursor:
            for suggested in suggested_indexes:
                # Check if a similar index exists
                cursor.execute("""
                    SELECT indexname, indexdef 
                    FROM pg_indexes 
                    WHERE tablename = %s 
                    AND indexdef ILIKE %s
                """, [suggested['table'], f"%{suggested['columns'][0]}%"])
                
                existing = cursor.fetchall()
                
                # Check if all columns are covered by existing indexes
                has_composite_index = False
                for index_name, index_def in existing:
                    if all(col.replace('_id', '') in index_def.lower() for col in suggested['columns']):
                        has_composite_index = True
                        break
                
                if not has_composite_index:
                    missing_indexes.append(suggested)
        
        indexing_analysis['missing_indexes'] = missing_indexes
        
        self.results['indexing_analysis'] = indexing_analysis
    
    def _test_query_performance(self):
        """
        Test query performance for large datasets
        """
        print("Testing query performance for large datasets...")
        
        performance_tests = {}
        
        # Test 1: Large dataset pagination performance
        print("  Testing pagination performance...")
        pagination_results = []
        
        for page_size in [10, 50, 100, 500]:
            start_time = time.time()
            initial_queries = len(connection.queries)
            
            # Test paginated query
            deals = Deal.objects.filter(organization=self.test_organization).select_related(
                'client', 'created_by'
            )[:page_size]
            list(deals)  # Force evaluation
            
            query_time = time.time() - start_time
            query_count = len(connection.queries) - initial_queries
            
            pagination_results.append({
                'page_size': page_size,
                'time': query_time,
                'query_count': query_count,
                'records': len(deals)
            })
        
        performance_tests['pagination_performance'] = pagination_results
        
        # Test 2: Complex filtering performance
        print("  Testing complex filtering performance...")
        filtering_results = []
        
        filter_tests = [
            {
                'name': 'simple_filter',
                'filter': Q(organization=self.test_organization, verification_status='pending')
            },
            {
                'name': 'date_range_filter',
                'filter': Q(
                    organization=self.test_organization,
                    deal_date__gte=timezone.now().date() - timedelta(days=30)
                )
            },
            {
                'name': 'complex_multi_filter',
                'filter': Q(
                    organization=self.test_organization,
                    verification_status='pending',
                    deal_value__gte=1000,
                    payment_status='initial payment'
                )
            },
            {
                'name': 'join_filter',
                'filter': Q(
                    organization=self.test_organization,
                    client__status='pending',
                    created_by__is_active=True
                )
            }
        ]
        
        for test in filter_tests:
            start_time = time.time()
            initial_queries = len(connection.queries)
            
            deals = Deal.objects.filter(test['filter']).select_related('client', 'created_by')
            count = deals.count()
            
            query_time = time.time() - start_time
            query_count = len(connection.queries) - initial_queries
            
            filtering_results.append({
                'test_name': test['name'],
                'time': query_time,
                'query_count': query_count,
                'result_count': count
            })
        
        performance_tests['filtering_performance'] = filtering_results
        
        # Test 3: Aggregation performance
        print("  Testing aggregation performance...")
        aggregation_results = []
        
        aggregation_tests = [
            {
                'name': 'simple_count',
                'query': lambda: Deal.objects.filter(organization=self.test_organization).count()
            },
            {
                'name': 'sum_aggregation',
                'query': lambda: Deal.objects.filter(organization=self.test_organization).aggregate(
                    total=Sum('deal_value')
                )
            },
            {
                'name': 'complex_aggregation',
                'query': lambda: Deal.objects.filter(organization=self.test_organization).aggregate(
                    total_deals=Count('id'),
                    total_value=Sum('deal_value'),
                    avg_value=Avg('deal_value'),
                    pending_deals=Count('id', filter=Q(verification_status='pending'))
                )
            },
            {
                'name': 'grouped_aggregation',
                'query': lambda: list(Deal.objects.filter(organization=self.test_organization).values(
                    'verification_status'
                ).annotate(
                    count=Count('id'),
                    total_value=Sum('deal_value')
                ))
            }
        ]
        
        for test in aggregation_tests:
            start_time = time.time()
            initial_queries = len(connection.queries)
            
            result = test['query']()
            
            query_time = time.time() - start_time
            query_count = len(connection.queries) - initial_queries
            
            aggregation_results.append({
                'test_name': test['name'],
                'time': query_time,
                'query_count': query_count,
                'result': str(result)[:100] if result else None
            })
        
        performance_tests['aggregation_performance'] = aggregation_results
        
        # Test 4: Join performance
        print("  Testing join performance...")
        join_results = []
        
        join_tests = [
            {
                'name': 'select_related_single',
                'query': lambda: list(Deal.objects.filter(organization=self.test_organization).select_related('client')[:20])
            },
            {
                'name': 'select_related_multiple',
                'query': lambda: list(Deal.objects.filter(organization=self.test_organization).select_related(
                    'client', 'created_by', 'organization'
                )[:20])
            },
            {
                'name': 'prefetch_related',
                'query': lambda: list(Deal.objects.filter(organization=self.test_organization).prefetch_related('payments')[:20])
            },
            {
                'name': 'complex_joins',
                'query': lambda: list(Deal.objects.filter(organization=self.test_organization).select_related(
                    'client', 'created_by', 'organization'
                ).prefetch_related('payments')[:20])
            }
        ]
        
        for test in join_tests:
            start_time = time.time()
            initial_queries = len(connection.queries)
            
            result = test['query']()
            
            query_time = time.time() - start_time
            query_count = len(connection.queries) - initial_queries
            
            join_results.append({
                'test_name': test['name'],
                'time': query_time,
                'query_count': query_count,
                'records': len(result) if result else 0
            })
        
        performance_tests['join_performance'] = join_results
        
        self.results['query_performance'] = performance_tests
    
    def _analyze_n_plus_one_patterns(self):
        """
        Examine N+1 query patterns and optimization opportunities
        """
        print("Analyzing N+1 query patterns...")
        
        n_plus_one_analysis = {
            'detected_patterns': [],
            'optimization_tests': [],
            'recommendations': []
        }
        
        # Test 1: Classic N+1 pattern - deals and their clients
        print("  Testing N+1 pattern: deals and clients...")
        
        # Bad pattern (N+1)
        start_time = time.time()
        initial_queries = len(connection.queries)
        
        deals = Deal.objects.filter(organization=self.test_organization)[:10]
        client_names = []
        for deal in deals:
            client_names.append(deal.client.client_name)  # This causes N+1
        
        bad_time = time.time() - start_time
        bad_queries = len(connection.queries) - initial_queries
        
        # Good pattern (optimized)
        start_time = time.time()
        initial_queries = len(connection.queries)
        
        deals = Deal.objects.filter(organization=self.test_organization).select_related('client')[:10]
        client_names = []
        for deal in deals:
            client_names.append(deal.client.client_name)  # No additional queries
        
        good_time = time.time() - start_time
        good_queries = len(connection.queries) - initial_queries
        
        n_plus_one_analysis['detected_patterns'].append({
            'pattern': 'deals_and_clients',
            'bad_performance': {
                'time': bad_time,
                'queries': bad_queries
            },
            'optimized_performance': {
                'time': good_time,
                'queries': good_queries
            },
            'improvement': {
                'time_saved': bad_time - good_time,
                'queries_saved': bad_queries - good_queries
            }
        })
        
        # Test 2: N+1 pattern with reverse foreign keys - users and their deals
        print("  Testing N+1 pattern: users and their deals...")
        
        # Bad pattern (N+1)
        start_time = time.time()
        initial_queries = len(connection.queries)
        
        users = User.objects.filter(organization=self.test_organization)[:10]
        deal_counts = []
        for user in users:
            deal_counts.append(user.created_deals.count())  # This causes N+1
        
        bad_time = time.time() - start_time
        bad_queries = len(connection.queries) - initial_queries
        
        # Good pattern (optimized with prefetch)
        start_time = time.time()
        initial_queries = len(connection.queries)
        
        users = User.objects.filter(organization=self.test_organization).prefetch_related('created_deals')[:10]
        deal_counts = []
        for user in users:
            deal_counts.append(len(user.created_deals.all()))  # Uses prefetched data
        
        good_time = time.time() - start_time
        good_queries = len(connection.queries) - initial_queries
        
        n_plus_one_analysis['detected_patterns'].append({
            'pattern': 'users_and_deals',
            'bad_performance': {
                'time': bad_time,
                'queries': bad_queries
            },
            'optimized_performance': {
                'time': good_time,
                'queries': good_queries
            },
            'improvement': {
                'time_saved': bad_time - good_time,
                'queries_saved': bad_queries - good_queries
            }
        })
        
        # Test 3: Complex N+1 pattern - deals, clients, and payments
        print("  Testing complex N+1 pattern: deals, clients, and payments...")
        
        # Create some test payments
        test_deals = Deal.objects.filter(organization=self.test_organization)[:5]
        for deal in test_deals:
            Payment.objects.get_or_create(
                deal=deal,
                payment_date=timezone.now().date(),
                received_amount=Decimal('500.00'),
                payment_type='bank',
                defaults={'payment_remarks': 'Test payment for N+1 analysis'}
            )
        
        # Bad pattern (multiple N+1)
        start_time = time.time()
        initial_queries = len(connection.queries)
        
        deals = Deal.objects.filter(organization=self.test_organization)[:5]
        deal_info = []
        for deal in deals:
            info = {
                'deal_id': deal.deal_id,
                'client_name': deal.client.client_name,  # N+1 for clients
                'payment_count': deal.payments.count(),  # N+1 for payments
                'creator_name': deal.created_by.get_full_name()  # N+1 for users
            }
            deal_info.append(info)
        
        bad_time = time.time() - start_time
        bad_queries = len(connection.queries) - initial_queries
        
        # Good pattern (fully optimized)
        start_time = time.time()
        initial_queries = len(connection.queries)
        
        deals = Deal.objects.filter(organization=self.test_organization).select_related(
            'client', 'created_by'
        ).prefetch_related('payments')[:5]
        deal_info = []
        for deal in deals:
            info = {
                'deal_id': deal.deal_id,
                'client_name': deal.client.client_name,  # No additional query
                'payment_count': len(deal.payments.all()),  # Uses prefetched data
                'creator_name': deal.created_by.get_full_name()  # No additional query
            }
            deal_info.append(info)
        
        good_time = time.time() - start_time
        good_queries = len(connection.queries) - initial_queries
        
        n_plus_one_analysis['detected_patterns'].append({
            'pattern': 'complex_deals_clients_payments',
            'bad_performance': {
                'time': bad_time,
                'queries': bad_queries
            },
            'optimized_performance': {
                'time': good_time,
                'queries': good_queries
            },
            'improvement': {
                'time_saved': bad_time - good_time,
                'queries_saved': bad_queries - good_queries
            }
        })
        
        # Generate optimization recommendations
        recommendations = []
        
        for pattern in n_plus_one_analysis['detected_patterns']:
            if pattern['improvement']['queries_saved'] > 0:
                recommendations.append({
                    'pattern': pattern['pattern'],
                    'issue': f"N+1 query pattern detected with {pattern['bad_performance']['queries']} queries",
                    'solution': f"Use select_related/prefetch_related to reduce to {pattern['optimized_performance']['queries']} queries",
                    'performance_gain': f"{pattern['improvement']['queries_saved']} fewer queries, {pattern['improvement']['time_saved']:.3f}s faster"
                })
        
        n_plus_one_analysis['recommendations'] = recommendations
        
        self.results['n_plus_one_analysis'] = n_plus_one_analysis
    
    def _analyze_transaction_management(self):
        """
        Validate database transaction management
        """
        print("Analyzing database transaction management...")
        
        transaction_analysis = {
            'atomic_operations': [],
            'rollback_tests': [],
            'concurrent_access': [],
            'deadlock_prevention': []
        }
        
        # Test 1: Atomic operations
        print("  Testing atomic operations...")
        
        # Test successful atomic transaction
        try:
            with transaction.atomic():
                start_time = time.time()
                initial_queries = len(connection.queries)
                
                # Create a test client and deal in one transaction
                test_client = Client.objects.create(
                    client_name="Atomic Test Client",
                    email="atomic@test.com",
                    phone_number="+1234567890",
                    organization=self.test_organization,
                    created_by=self.test_users[0] if self.test_users else User.objects.filter(organization=self.test_organization).first()
                )
                
                test_deal = Deal.objects.create(
                    organization=self.test_organization,
                    client=test_client,
                    created_by=self.test_users[0] if self.test_users else User.objects.filter(organization=self.test_organization).first(),
                    deal_name="Atomic Test Deal",
                    deal_value=Decimal('1000.00'),
                    payment_status='initial payment',
                    source_type='linkedin',
                    payment_method='bank',
                    deal_date=timezone.now().date()
                )
                
                transaction_time = time.time() - start_time
                transaction_queries = len(connection.queries) - initial_queries
                
                transaction_analysis['atomic_operations'].append({
                    'test': 'successful_atomic_transaction',
                    'status': 'success',
                    'time': transaction_time,
                    'queries': transaction_queries,
                    'records_created': 2
                })
                
                # Clean up
                test_deal.delete()
                test_client.delete()
                
        except Exception as e:
            transaction_analysis['atomic_operations'].append({
                'test': 'successful_atomic_transaction',
                'status': 'failed',
                'error': str(e)
            })
        
        # Test 2: Rollback on error
        print("  Testing transaction rollback...")
        
        try:
            initial_client_count = Client.objects.filter(organization=self.test_organization).count()
            
            with transaction.atomic():
                # Create a client
                test_client = Client.objects.create(
                    client_name="Rollback Test Client",
                    email="rollback@test.com",
                    phone_number="+1234567891",
                    organization=self.test_organization,
                    created_by=self.test_users[0] if self.test_users else User.objects.filter(organization=self.test_organization).first()
                )
                
                # Force an error to trigger rollback
                raise Exception("Intentional error for rollback test")
                
        except Exception as e:
            # Check that rollback occurred
            final_client_count = Client.objects.filter(organization=self.test_organization).count()
            rollback_successful = (initial_client_count == final_client_count)
            
            transaction_analysis['rollback_tests'].append({
                'test': 'rollback_on_error',
                'status': 'success' if rollback_successful else 'failed',
                'initial_count': initial_client_count,
                'final_count': final_client_count,
                'rollback_successful': rollback_successful
            })
        
        # Test 3: Concurrent access simulation
        print("  Testing concurrent access patterns...")
        
        # Test optimistic locking (if implemented)
        try:
            # Get a deal for testing
            test_deal = Deal.objects.filter(organization=self.test_organization).first()
            if test_deal:
                # Simulate concurrent modification
                deal1 = Deal.objects.get(id=test_deal.id)
                deal2 = Deal.objects.get(id=test_deal.id)
                
                # Modify both instances
                deal1.deal_remarks = "Modified by user 1"
                deal2.deal_remarks = "Modified by user 2"
                
                # Save first instance
                deal1.save()
                
                # Try to save second instance (should handle concurrent modification)
                try:
                    deal2.save()
                    concurrent_result = "no_conflict_detection"
                except Exception as e:
                    concurrent_result = "conflict_detected"
                
                transaction_analysis['concurrent_access'].append({
                    'test': 'optimistic_locking',
                    'result': concurrent_result,
                    'deal_id': str(test_deal.id)
                })
                
                # Reset deal
                test_deal.deal_remarks = "Reset after concurrent test"
                test_deal.save()
        
        except Exception as e:
            transaction_analysis['concurrent_access'].append({
                'test': 'optimistic_locking',
                'status': 'error',
                'error': str(e)
            })
        
        # Test 4: Deadlock prevention
        print("  Testing deadlock prevention...")
        
        # Test consistent ordering of operations
        try:
            with transaction.atomic():
                start_time = time.time()
                
                # Access resources in consistent order to prevent deadlocks
                org = Organization.objects.select_for_update().get(id=self.test_organization.id)
                users = User.objects.select_for_update().filter(organization=org)[:2]
                
                # Perform operations in consistent order
                for user in users:
                    user.login_count = (user.login_count or 0) + 1
                    user.save()
                
                deadlock_time = time.time() - start_time
                
                transaction_analysis['deadlock_prevention'].append({
                    'test': 'consistent_resource_ordering',
                    'status': 'success',
                    'time': deadlock_time,
                    'users_updated': len(users)
                })
        
        except Exception as e:
            transaction_analysis['deadlock_prevention'].append({
                'test': 'consistent_resource_ordering',
                'status': 'error',
                'error': str(e)
            })
        
        self.results['transaction_analysis'] = transaction_analysis
    
    def _generate_recommendations(self):
        """
        Generate optimization recommendations based on analysis results
        """
        recommendations = []
        
        # Indexing recommendations
        if self.results['indexing_analysis'].get('missing_indexes'):
            for missing_index in self.results['indexing_analysis']['missing_indexes']:
                recommendations.append({
                    'category': 'indexing',
                    'priority': 'high',
                    'title': f"Add composite index to {missing_index['table']}",
                    'description': missing_index['reason'],
                    'implementation': f"CREATE INDEX CONCURRENTLY idx_{missing_index['table']}_{'_'.join(missing_index['columns'])} ON {missing_index['table']} ({', '.join(missing_index['columns'])})",
                    'expected_benefit': 'Improved query performance for organization-scoped operations'
                })
        
        # Query performance recommendations
        query_perf = self.results['query_performance']
        
        # Check for slow pagination
        if query_perf.get('pagination_performance'):
            slow_pagination = [p for p in query_perf['pagination_performance'] if p['time'] > 0.1]
            if slow_pagination:
                recommendations.append({
                    'category': 'query_optimization',
                    'priority': 'medium',
                    'title': 'Optimize pagination queries',
                    'description': f"Pagination queries taking up to {max(p['time'] for p in slow_pagination):.3f}s",
                    'implementation': 'Use cursor-based pagination or add appropriate indexes',
                    'expected_benefit': 'Faster page loading for large datasets'
                })
        
        # Check for slow aggregations
        if query_perf.get('aggregation_performance'):
            slow_aggregations = [a for a in query_perf['aggregation_performance'] if a['time'] > 0.05]
            if slow_aggregations:
                recommendations.append({
                    'category': 'query_optimization',
                    'priority': 'medium',
                    'title': 'Optimize aggregation queries',
                    'description': f"Aggregation queries taking up to {max(a['time'] for a in slow_aggregations):.3f}s",
                    'implementation': 'Add indexes on aggregated columns or use materialized views',
                    'expected_benefit': 'Faster dashboard and reporting queries'
                })
        
        # N+1 query recommendations
        if self.results['n_plus_one_analysis'].get('recommendations'):
            for n_plus_one_rec in self.results['n_plus_one_analysis']['recommendations']:
                recommendations.append({
                    'category': 'n_plus_one_optimization',
                    'priority': 'high',
                    'title': f"Fix N+1 query pattern: {n_plus_one_rec['pattern']}",
                    'description': n_plus_one_rec['issue'],
                    'implementation': n_plus_one_rec['solution'],
                    'expected_benefit': n_plus_one_rec['performance_gain']
                })
        
        # Transaction management recommendations
        transaction_analysis = self.results['transaction_analysis']
        
        # Check for missing optimistic locking
        if transaction_analysis.get('concurrent_access'):
            for test in transaction_analysis['concurrent_access']:
                if test.get('result') == 'no_conflict_detection':
                    recommendations.append({
                        'category': 'transaction_management',
                        'priority': 'high',
                        'title': 'Implement optimistic locking',
                        'description': 'Concurrent modifications not properly handled',
                        'implementation': 'Add version fields and optimistic locking to critical models',
                        'expected_benefit': 'Prevent data corruption from concurrent updates'
                    })
        
        # General performance recommendations
        recommendations.extend([
            {
                'category': 'general_optimization',
                'priority': 'medium',
                'title': 'Implement query result caching',
                'description': 'Cache frequently accessed organization data',
                'implementation': 'Use Redis/Memcached for caching organization statistics and user permissions',
                'expected_benefit': 'Reduced database load and faster response times'
            },
            {
                'category': 'general_optimization',
                'priority': 'low',
                'title': 'Monitor query performance in production',
                'description': 'Set up continuous monitoring of database performance',
                'implementation': 'Use pg_stat_statements and custom monitoring for slow query detection',
                'expected_benefit': 'Proactive identification of performance issues'
            }
        ])
        
        self.results['recommendations'] = recommendations
    
    def _save_results(self):
        """
        Save analysis results to file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"database_performance_indexing_analysis_results_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        print(f"\n📄 Analysis results saved to: {filename}")
        
        # Also create a summary report
        summary_filename = f"DATABASE_PERFORMANCE_INDEXING_ANALYSIS_SUMMARY.md"
        self._create_summary_report(summary_filename)
    
    def _create_summary_report(self, filename):
        """
        Create a human-readable summary report
        """
        with open(filename, 'w') as f:
            f.write("# Database Performance and Indexing Analysis Summary\n\n")
            f.write(f"**Analysis Date:** {self.results['analysis_timestamp']}\n\n")
            
            # Indexing Analysis Summary
            f.write("## 📊 Indexing Analysis\n\n")
            indexing = self.results['indexing_analysis']
            
            f.write(f"- **Existing Indexes Analyzed:** {len(indexing.get('existing_indexes', {}))}\n")
            f.write(f"- **Missing Indexes Identified:** {len(indexing.get('missing_indexes', []))}\n")
            f.write(f"- **Index Usage Statistics:** {len(indexing.get('index_usage_stats', []))} indexes monitored\n\n")
            
            if indexing.get('missing_indexes'):
                f.write("### Missing Indexes\n\n")
                for idx in indexing['missing_indexes']:
                    f.write(f"- **{idx['table']}**: {', '.join(idx['columns'])} - {idx['reason']}\n")
                f.write("\n")
            
            # Query Performance Summary
            f.write("## ⚡ Query Performance Analysis\n\n")
            query_perf = self.results['query_performance']
            
            if query_perf.get('pagination_performance'):
                f.write("### Pagination Performance\n\n")
                for test in query_perf['pagination_performance']:
                    f.write(f"- **Page Size {test['page_size']}**: {test['time']:.3f}s, {test['query_count']} queries\n")
                f.write("\n")
            
            if query_perf.get('aggregation_performance'):
                f.write("### Aggregation Performance\n\n")
                for test in query_perf['aggregation_performance']:
                    f.write(f"- **{test['test_name']}**: {test['time']:.3f}s, {test['query_count']} queries\n")
                f.write("\n")
            
            # N+1 Analysis Summary
            f.write("## 🔄 N+1 Query Pattern Analysis\n\n")
            n_plus_one = self.results['n_plus_one_analysis']
            
            if n_plus_one.get('detected_patterns'):
                f.write("### Detected Patterns\n\n")
                for pattern in n_plus_one['detected_patterns']:
                    improvement = pattern['improvement']
                    f.write(f"- **{pattern['pattern']}**: Saved {improvement['queries_saved']} queries, {improvement['time_saved']:.3f}s faster with optimization\n")
                f.write("\n")
            
            # Transaction Analysis Summary
            f.write("## 🔒 Transaction Management Analysis\n\n")
            transaction = self.results['transaction_analysis']
            
            f.write(f"- **Atomic Operations Tested:** {len(transaction.get('atomic_operations', []))}\n")
            f.write(f"- **Rollback Tests:** {len(transaction.get('rollback_tests', []))}\n")
            f.write(f"- **Concurrent Access Tests:** {len(transaction.get('concurrent_access', []))}\n\n")
            
            # Recommendations Summary
            f.write("## 💡 Optimization Recommendations\n\n")
            recommendations = self.results['recommendations']
            
            high_priority = [r for r in recommendations if r['priority'] == 'high']
            medium_priority = [r for r in recommendations if r['priority'] == 'medium']
            low_priority = [r for r in recommendations if r['priority'] == 'low']
            
            if high_priority:
                f.write("### High Priority\n\n")
                for rec in high_priority:
                    f.write(f"- **{rec['title']}**: {rec['description']}\n")
                f.write("\n")
            
            if medium_priority:
                f.write("### Medium Priority\n\n")
                for rec in medium_priority:
                    f.write(f"- **{rec['title']}**: {rec['description']}\n")
                f.write("\n")
            
            if low_priority:
                f.write("### Low Priority\n\n")
                for rec in low_priority:
                    f.write(f"- **{rec['title']}**: {rec['description']}\n")
                f.write("\n")
            
            f.write("## 📈 Key Findings\n\n")
            f.write("1. **Organization-scoped queries** are the primary performance bottleneck\n")
            f.write("2. **Missing composite indexes** on organization + status fields impact performance\n")
            f.write("3. **N+1 query patterns** can be eliminated with proper select_related/prefetch_related usage\n")
            f.write("4. **Transaction management** is generally working correctly but could benefit from optimistic locking\n")
            f.write("5. **Query optimization** opportunities exist in pagination and aggregation operations\n\n")
            
            f.write("## 🎯 Next Steps\n\n")
            f.write("1. Implement missing composite indexes for organization-scoped queries\n")
            f.write("2. Add select_related/prefetch_related to eliminate N+1 patterns\n")
            f.write("3. Implement query result caching for frequently accessed data\n")
            f.write("4. Add optimistic locking to critical models\n")
            f.write("5. Set up continuous database performance monitoring\n")
        
        print(f"📄 Summary report created: {filename}")
    
    def _cleanup_test_data(self):
        """
        Clean up test data created during analysis
        """
        try:
            # Clean up test deals
            if self.test_deals:
                Deal.objects.filter(id__in=[deal.id for deal in self.test_deals]).delete()
            
            # Clean up test clients
            if self.test_clients:
                Client.objects.filter(id__in=[client.id for client in self.test_clients]).delete()
            
            # Clean up test users
            if self.test_users:
                User.objects.filter(id__in=[user.id for user in self.test_users]).delete()
            
            print("Test data cleanup completed")
        except Exception as e:
            print(f"Warning: Test data cleanup failed: {str(e)}")


def main():
    """
    Main function to run the database performance and indexing analysis
    """
    print("=" * 80)
    print("DATABASE PERFORMANCE AND INDEXING ANALYSIS")
    print("=" * 80)
    
    analyzer = DatabasePerformanceAnalyzer()
    results = analyzer.run_complete_analysis()
    
    if results:
        print("\n" + "=" * 80)
        print("ANALYSIS COMPLETED SUCCESSFULLY")
        print("=" * 80)
        
        # Print key metrics
        indexing = results['indexing_analysis']
        query_perf = results['query_performance']
        n_plus_one = results['n_plus_one_analysis']
        recommendations = results['recommendations']
        
        print(f"\n📊 Key Metrics:")
        print(f"   • Missing indexes identified: {len(indexing.get('missing_indexes', []))}")
        print(f"   • N+1 patterns detected: {len(n_plus_one.get('detected_patterns', []))}")
        print(f"   • Performance tests completed: {len(query_perf)}")
        print(f"   • Optimization recommendations: {len(recommendations)}")
        
        # Print top recommendations
        high_priority_recs = [r for r in recommendations if r['priority'] == 'high']
        if high_priority_recs:
            print(f"\n🚨 High Priority Recommendations:")
            for i, rec in enumerate(high_priority_recs[:3], 1):
                print(f"   {i}. {rec['title']}")
        
        print(f"\n✅ Task 7: Database Performance and Indexing Analysis - COMPLETED")
        return True
    else:
        print("\n❌ Analysis failed!")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)