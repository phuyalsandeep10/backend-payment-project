"""
Slow Query Optimization Management Command - Task 4.2.2

Django management command for analyzing and optimizing slow database queries.
"""

from django.core.management.base import BaseCommand, CommandError
from django.db import connection
from core.performance.slow_query_optimizer import (
    slow_query_analyzer,
    analyze_all_slow_queries,
    optimize_specific_query,
    capture_slow_query
)
import time
import json
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """
    Slow query optimization management command
    Task 4.2.2: Slow query analysis and optimization
    """
    
    help = 'Analyze and optimize slow database queries for better performance'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--action',
            choices=['analyze', 'capture', 'optimize', 'summary', 'export'],
            default='summary',
            help='Action to perform (default: summary)'
        )
        
        parser.add_argument(
            '--query',
            type=str,
            help='Specific query to analyze (for optimize action)'
        )
        
        parser.add_argument(
            '--threshold',
            type=float,
            default=1.0,
            help='Slow query threshold in seconds (default: 1.0)'
        )
        
        parser.add_argument(
            '--limit',
            type=int,
            default=20,
            help='Number of slow queries to show (default: 20)'
        )
        
        parser.add_argument(
            '--export-file',
            type=str,
            help='File path to export analysis results'
        )
        
        parser.add_argument(
            '--show-plans',
            action='store_true',
            help='Show execution plans in analysis'
        )
        
        parser.add_argument(
            '--priority',
            choices=['critical', 'high', 'medium', 'low', 'all'],
            default='all',
            help='Show only queries with specific priority (default: all)'
        )
        
        parser.add_argument(
            '--simulate-load',
            action='store_true',
            help='Simulate some slow queries for testing'
        )
    
    def handle(self, *args, **options):
        try:
            action = options['action']
            
            self.stdout.write(
                self.style.SUCCESS(f'🐌 Starting slow query optimization - Action: {action.upper()}')
            )
            
            # Set threshold
            slow_query_analyzer.slow_threshold = options['threshold']
            
            if action == 'summary':
                self._show_summary(options)
            elif action == 'analyze':
                self._analyze_slow_queries(options)
            elif action == 'capture':
                self._capture_test_queries(options)
            elif action == 'optimize':
                self._optimize_query(options)
            elif action == 'export':
                self._export_analysis(options)
            
            self.stdout.write(
                self.style.SUCCESS('✅ Slow query optimization completed successfully!')
            )
            
        except Exception as e:
            logger.error(f"Error in slow query optimization: {e}")
            raise CommandError(f'Slow query optimization failed: {str(e)}')
    
    def _show_summary(self, options):
        """Show summary of slow query analysis"""
        
        self.stdout.write("Loading slow query summary...")
        
        summary = slow_query_analyzer.get_slow_query_summary()
        
        self.stdout.write(f"\n🐌 Slow Query Summary")
        self.stdout.write('=' * 50)
        
        if summary['total_slow_queries'] == 0:
            self.stdout.write(self.style.SUCCESS("✅ No slow queries detected!"))
            self.stdout.write("Either your queries are well optimized or no queries have been captured yet.")
            self.stdout.write("\n💡 To capture queries, use --action=capture or --simulate-load")
            return
        
        # Basic statistics
        self.stdout.write(f"Total Slow Queries: {summary['total_slow_queries']:,}")
        self.stdout.write(f"Average Execution Time: {summary['avg_execution_time']:.3f}s")
        self.stdout.write(f"Total Time Wasted: {summary['total_time_wasted']:.2f}s")
        
        # Query types
        if summary.get('query_types'):
            self.stdout.write(f"\nQuery Types:")
            for query_type, count in summary['query_types'].items():
                self.stdout.write(f"  {query_type}: {count}")
        
        # Slowest query
        if summary.get('slowest_query'):
            slowest = summary['slowest_query']
            self.stdout.write(f"\n⏱️ Slowest Query:")
            self.stdout.write(f"  Max Time: {slowest.max_execution_time:.3f}s")
            self.stdout.write(f"  Avg Time: {slowest.avg_execution_time:.3f}s")
            self.stdout.write(f"  Executions: {slowest.execution_count}")
            self.stdout.write(f"  Query: {slowest.query[:100]}...")
        
        # Most frequent query
        if summary.get('most_frequent_query'):
            frequent = summary['most_frequent_query']
            self.stdout.write(f"\n🔄 Most Frequent Slow Query:")
            self.stdout.write(f"  Executions: {frequent.execution_count}")
            self.stdout.write(f"  Avg Time: {frequent.avg_execution_time:.3f}s")
            self.stdout.write(f"  Total Impact: {frequent.avg_execution_time * frequent.execution_count:.2f}s")
            self.stdout.write(f"  Query: {frequent.query[:100]}...")
        
        # Recommendations
        self.stdout.write(f"\n💡 Next Steps:")
        if summary['total_slow_queries'] > 0:
            self.stdout.write("  1. Run --action=analyze for detailed optimization recommendations")
            self.stdout.write("  2. Focus on high-impact queries first")
            self.stdout.write("  3. Use --action=optimize --query='...' for specific query optimization")
        
        if summary['total_time_wasted'] > 60:
            self.stdout.write("  ⚠️ High time waste detected - immediate optimization recommended")
    
    def _analyze_slow_queries(self, options):
        """Analyze slow queries with detailed recommendations"""
        
        limit = options['limit']
        priority_filter = options['priority']
        show_plans = options['show_plans']
        
        self.stdout.write(f"Analyzing slow queries (limit: {limit}, priority: {priority_filter})...")
        
        analysis_results = analyze_all_slow_queries()
        
        if not analysis_results:
            self.stdout.write(self.style.SUCCESS("✅ No slow queries to analyze!"))
            return
        
        # Filter by priority
        if priority_filter != 'all':
            analysis_results = [r for r in analysis_results if r['priority'] == priority_filter]
        
        # Limit results
        analysis_results = analysis_results[:limit]
        
        self.stdout.write(f"\n🔍 Detailed Slow Query Analysis")
        self.stdout.write('=' * 60)
        
        for i, result in enumerate(analysis_results, 1):
            query = result['query']
            stats = result['performance_stats']
            priority = result['priority']
            issues = result['issues']
            optimizations = result['optimizations']
            
            # Priority indicator
            priority_icon = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🟢'
            }.get(priority, '⚪')
            
            self.stdout.write(f"\n{priority_icon} Query #{i} - {priority.upper()} Priority")
            self.stdout.write(f"Query: {query[:100]}{'...' if len(query) > 100 else ''}")
            
            # Performance statistics
            self.stdout.write(f"Performance:")
            self.stdout.write(f"  Average Time: {stats['avg_execution_time']:.3f}s")
            self.stdout.write(f"  Max Time: {stats['max_execution_time']:.3f}s")
            self.stdout.write(f"  Executions: {stats['execution_count']}")
            self.stdout.write(f"  Total Impact: {stats['total_time_wasted']:.2f}s")
            
            # Issues identified
            if issues:
                self.stdout.write(f"Issues Identified ({len(issues)}):")
                for issue in issues[:3]:  # Show top 3 issues
                    self.stdout.write(f"  • {issue}")
                if len(issues) > 3:
                    self.stdout.write(f"  ... and {len(issues) - 3} more")
            
            # Optimization recommendations
            if optimizations:
                self.stdout.write(f"Optimization Recommendations ({len(optimizations)}):")
                for opt in optimizations[:2]:  # Show top 2 optimizations
                    impact_icon = '🔥' if opt.impact == 'high' else '⚡' if opt.impact == 'medium' else '💡'
                    self.stdout.write(f"  {impact_icon} {opt.description}")
                    self.stdout.write(f"    Expected: {opt.estimated_improvement}")
                    self.stdout.write(f"    Complexity: {opt.complexity}")
                
                if len(optimizations) > 2:
                    self.stdout.write(f"  ... and {len(optimizations) - 2} more recommendations")
            
            # Execution plan (if requested)
            if show_plans and result.get('execution_plan'):
                plan = result['execution_plan']
                self.stdout.write(f"Execution Plan:")
                self.stdout.write(f"  Total Cost: {plan.total_cost:.2f}")
                self.stdout.write(f"  Execution Time: {plan.execution_time:.3f}ms")
                
                if plan.table_scans:
                    self.stdout.write(f"  Table Scans: {len(plan.table_scans)}")
                if plan.bottlenecks:
                    self.stdout.write(f"  Bottlenecks: {len(plan.bottlenecks)}")
            
            self.stdout.write("-" * 60)
        
        # Summary recommendations
        critical_count = len([r for r in analysis_results if r['priority'] == 'critical'])
        high_count = len([r for r in analysis_results if r['priority'] == 'high'])
        
        self.stdout.write(f"\n📊 Analysis Summary:")
        self.stdout.write(f"  Analyzed: {len(analysis_results)} queries")
        if critical_count > 0:
            self.stdout.write(f"  🔴 Critical: {critical_count} (immediate attention required)")
        if high_count > 0:
            self.stdout.write(f"  🟠 High: {high_count} (optimize soon)")
        
        self.stdout.write(f"\n💡 Recommendations:")
        self.stdout.write("  1. Start with critical and high priority queries")
        self.stdout.write("  2. Focus on queries with highest total impact")
        self.stdout.write("  3. Create missing indexes first (easy wins)")
        self.stdout.write("  4. Use --action=optimize for specific query help")
    
    def _capture_test_queries(self, options):
        """Capture test queries to demonstrate functionality"""
        
        if options['simulate_load']:
            self._simulate_slow_queries()
        else:
            self.stdout.write("Capturing slow queries from recent database activity...")
            
            # This would integrate with actual query logging
            # For now, show how to capture queries manually
            
            self.stdout.write("\n📝 Manual Query Capture:")
            self.stdout.write("To capture slow queries, you can:")
            self.stdout.write("1. Enable query logging in PostgreSQL")
            self.stdout.write("2. Use Django's db logging to capture queries")
            self.stdout.write("3. Integrate with application monitoring")
            
            self.stdout.write("\n💡 Example integration in Django views:")
            self.stdout.write("""
from django.db import connection
from core.performance.slow_query_optimizer import capture_slow_query
import time

# In your view:
start_time = time.time()
# ... your query here ...
execution_time = time.time() - start_time
if execution_time > 1.0:  # 1 second threshold
    capture_slow_query(str(connection.queries[-1]['sql']), execution_time)
            """)
    
    def _simulate_slow_queries(self):
        """Simulate slow queries for testing"""
        
        self.stdout.write("Simulating slow queries for testing purposes...")
        
        # Simulate various types of slow queries
        test_queries = [
            {
                'query': "SELECT * FROM deals_deal WHERE organization_id = 1",
                'time': 2.5,
                'description': "Unoptimized SELECT * query"
            },
            {
                'query': "SELECT d.* FROM deals_deal d WHERE d.deal_name LIKE '%test%' ORDER BY created_at",
                'time': 5.2,
                'description': "Query with LIKE and no LIMIT"
            },
            {
                'query': """
                    SELECT c.client_name, COUNT(d.id) 
                    FROM clients_client c 
                    LEFT JOIN deals_deal d ON c.id = d.client_id 
                    WHERE UPPER(c.client_name) = 'TEST' 
                    GROUP BY c.client_name
                """,
                'time': 3.8,
                'description': "Query with function in WHERE clause"
            },
            {
                'query': """
                    SELECT * FROM deals_deal 
                    WHERE client_id IN (
                        SELECT id FROM clients_client 
                        WHERE organization_id = 1 AND is_active = true
                    )
                """,
                'time': 4.1,
                'description': "Subquery that could be a JOIN"
            },
            {
                'query': """
                    SELECT d1.*, d2.deal_name as related_deal 
                    FROM deals_deal d1, deals_deal d2 
                    WHERE d1.client_id = d2.client_id 
                    AND d1.id != d2.id 
                    AND d1.organization_id = 1
                """,
                'time': 8.7,
                'description': "Cartesian product join"
            }
        ]
        
        for i, test_query in enumerate(test_queries, 1):
            self.stdout.write(f"  Simulating query {i}: {test_query['description']}")
            
            # Capture the slow query multiple times to simulate frequency
            for _ in range(3):
                capture_slow_query(test_query['query'], test_query['time'])
        
        self.stdout.write(f"\n✅ Simulated {len(test_queries)} different slow query patterns")
        self.stdout.write("You can now run --action=analyze to see optimization recommendations")
    
    def _optimize_query(self, options):
        """Optimize a specific query"""
        
        query = options.get('query')
        if not query:
            raise CommandError("--query parameter is required for optimize action")
        
        self.stdout.write(f"Optimizing specific query...")
        self.stdout.write(f"Query: {query[:100]}{'...' if len(query) > 100 else ''}")
        
        optimizations = optimize_specific_query(query)
        
        if not optimizations:
            self.stdout.write(self.style.SUCCESS("✅ No obvious optimizations found for this query!"))
            return
        
        self.stdout.write(f"\n🔧 Query Optimization Recommendations")
        self.stdout.write('=' * 60)
        
        for i, opt in enumerate(optimizations, 1):
            impact_icon = '🔥' if opt.impact == 'high' else '⚡' if opt.impact == 'medium' else '💡'
            complexity_color = (
                self.style.ERROR if opt.complexity == 'hard' else
                self.style.WARNING if opt.complexity == 'medium' else
                self.style.SUCCESS
            )
            
            self.stdout.write(f"\n{impact_icon} Optimization #{i} - {opt.optimization_type.upper()}")
            self.stdout.write(f"Description: {opt.description}")
            self.stdout.write(f"Impact: {opt.impact.upper()}")
            self.stdout.write(complexity_color(f"Complexity: {opt.complexity.upper()}"))
            self.stdout.write(f"Expected Improvement: {opt.estimated_improvement}")
            
            if opt.optimized_query != opt.original_query:
                self.stdout.write(f"\nSuggested Query:")
                self.stdout.write(f"  {opt.optimized_query}")
        
        # General recommendations
        self.stdout.write(f"\n💡 Implementation Tips:")
        self.stdout.write("  1. Start with easy, high-impact optimizations")
        self.stdout.write("  2. Test optimizations in development first")
        self.stdout.write("  3. Measure performance before and after changes")
        self.stdout.write("  4. Consider adding appropriate indexes")
        self.stdout.write("  5. Monitor query execution plans")
    
    def _export_analysis(self, options):
        """Export detailed analysis to file"""
        
        export_file = options.get('export_file')
        if not export_file:
            # Generate default filename
            from django.utils import timezone
            timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
            export_file = f'slow_query_analysis_{timestamp}.json'
        
        self.stdout.write(f"Exporting slow query analysis to {export_file}...")
        
        try:
            analysis_results = analyze_all_slow_queries()
            summary = slow_query_analyzer.get_slow_query_summary()
            
            export_data = {
                'timestamp': timezone.now().isoformat(),
                'threshold': slow_query_analyzer.slow_threshold,
                'summary': {
                    'total_slow_queries': summary['total_slow_queries'],
                    'avg_execution_time': summary['avg_execution_time'],
                    'total_time_wasted': summary['total_time_wasted'],
                    'query_types': summary.get('query_types', {})
                },
                'detailed_analysis': analysis_results,
                'optimization_rules': slow_query_analyzer._load_optimization_rules()
            }
            
            with open(export_file, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            self.stdout.write(f"\n✅ Analysis exported to: {export_file}")
            
            # Show summary
            self.stdout.write(f"\n📊 Export Summary:")
            self.stdout.write(f"  Slow Queries Analyzed: {len(analysis_results)}")
            
            priority_counts = {}
            for result in analysis_results:
                priority = result['priority']
                priority_counts[priority] = priority_counts.get(priority, 0) + 1
            
            for priority, count in priority_counts.items():
                icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(priority, '⚪')
                self.stdout.write(f"  {icon} {priority.title()}: {count}")
            
        except Exception as e:
            raise CommandError(f"Failed to export analysis: {str(e)}")
