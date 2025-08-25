"""
Connection Pool Optimization Management Command - Task 4.2.3

Django management command for optimizing database connection pool settings
and monitoring connection health.
"""

from django.core.management.base import BaseCommand, CommandError
from core.performance.connection_pool_optimizer import (
    db_connection_monitor,
    connection_pool_optimizer,
    get_connection_metrics,
    analyze_pool_performance,
    get_optimal_config,
    perform_health_check
)
import time
import json
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """
    Connection pool optimization management command
    Task 4.2.3: Connection pool optimization automation
    """
    
    help = 'Optimize database connection pool settings for better performance'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--action',
            choices=['analyze', 'optimize', 'health', 'monitor', 'export'],
            default='health',
            help='Action to perform (default: health)'
        )
        
        parser.add_argument(
            '--apply-config',
            action='store_true',
            help='Apply the optimized configuration (not just dry run)'
        )
        
        parser.add_argument(
            '--monitoring-duration',
            type=int,
            default=300,
            help='Duration to monitor connections in seconds (default: 300)'
        )
        
        parser.add_argument(
            '--export-file',
            type=str,
            help='File path to export analysis results'
        )
        
        parser.add_argument(
            '--max-connections',
            type=int,
            help='Override max connections setting'
        )
        
        parser.add_argument(
            '--min-connections',
            type=int,
            help='Override min connections setting'
        )
        
        parser.add_argument(
            '--show-history',
            action='store_true',
            help='Show connection metrics history'
        )
    
    def handle(self, *args, **options):
        try:
            action = options['action']
            
            self.stdout.write(
                self.style.SUCCESS(f'🔗 Starting connection pool optimization - Action: {action.upper()}')
            )
            
            if action == 'health':
                self._health_check(options)
            elif action == 'analyze':
                self._analyze_performance(options)
            elif action == 'optimize':
                self._optimize_configuration(options)
            elif action == 'monitor':
                self._monitor_connections(options)
            elif action == 'export':
                self._export_analysis(options)
            
            self.stdout.write(
                self.style.SUCCESS('✅ Connection pool optimization completed successfully!')
            )
            
        except Exception as e:
            logger.error(f"Error in connection pool optimization: {e}")
            raise CommandError(f'Connection pool optimization failed: {str(e)}')
    
    def _health_check(self, options):
        """Perform connection pool health check"""
        
        self.stdout.write("Performing connection pool health check...")
        
        # Get health check results
        health_result = perform_health_check()
        current_metrics = get_connection_metrics()
        
        self.stdout.write(f"\n🏥 Connection Pool Health Check")
        self.stdout.write('=' * 50)
        
        # Overall status
        status = health_result['status']
        status_icon = {
            'healthy': '✅',
            'warning': '⚠️',
            'critical': '🔴',
            'error': '❌'
        }.get(status, '⚪')
        
        self.stdout.write(f"Overall Status: {status_icon} {status.upper()}")
        
        # Connection test results
        if 'connection_test_time' in health_result:
            test_time = health_result['connection_test_time']
            if test_time < 0.1:
                time_status = self.style.SUCCESS(f"{test_time:.3f}s")
            elif test_time < 0.5:
                time_status = self.style.WARNING(f"{test_time:.3f}s")
            else:
                time_status = self.style.ERROR(f"{test_time:.3f}s")
            
            self.stdout.write(f"Connection Test: {time_status}")
        
        # Current metrics
        self.stdout.write(f"\nCurrent Metrics:")
        self.stdout.write(f"  Total Connections: {current_metrics.total_connections}")
        self.stdout.write(f"  Active Connections: {current_metrics.active_connections}")
        self.stdout.write(f"  Idle Connections: {current_metrics.idle_connections}")
        
        if current_metrics.max_connections_used > 0:
            self.stdout.write(f"  Peak Usage: {current_metrics.max_connections_used}")
        
        if current_metrics.connection_wait_time > 0:
            wait_time = current_metrics.connection_wait_time
            if wait_time < 0.1:
                wait_status = self.style.SUCCESS(f"{wait_time:.3f}s")
            elif wait_time < 0.5:
                wait_status = self.style.WARNING(f"{wait_time:.3f}s")
            else:
                wait_status = self.style.ERROR(f"{wait_time:.3f}s")
            
            self.stdout.write(f"  Avg Connection Wait: {wait_status}")
        
        if current_metrics.avg_query_time > 0:
            query_time = current_metrics.avg_query_time
            if query_time < 0.1:
                query_status = self.style.SUCCESS(f"{query_time:.3f}s")
            elif query_time < 0.5:
                query_status = self.style.WARNING(f"{query_time:.3f}s")
            else:
                query_status = self.style.ERROR(f"{query_time:.3f}s")
            
            self.stdout.write(f"  Avg Query Time: {query_status}")
        
        # Health issues
        health_issues = health_result.get('health_issues', [])
        if health_issues:
            self.stdout.write(f"\n⚠️ Health Issues Detected:")
            for issue in health_issues:
                self.stdout.write(f"  • {issue}")
        else:
            self.stdout.write(f"\n✅ No health issues detected")
        
        # Connection errors
        if current_metrics.connection_errors:
            self.stdout.write(f"\n❌ Recent Connection Errors:")
            for error in current_metrics.connection_errors[-3:]:  # Show last 3 errors
                self.stdout.write(f"  • {error}")
        
        # Quick recommendations
        if status != 'healthy':
            self.stdout.write(f"\n💡 Quick Actions:")
            self.stdout.write("  1. Run --action=analyze for detailed performance analysis")
            self.stdout.write("  2. Check database server resources")
            self.stdout.write("  3. Review application connection usage patterns")
            
            if health_issues:
                self.stdout.write("  4. Address specific health issues listed above")
    
    def _analyze_performance(self, options):
        """Analyze connection pool performance"""
        
        show_history = options['show_history']
        
        self.stdout.write("Analyzing connection pool performance...")
        
        analysis = analyze_pool_performance()
        
        if analysis['status'] == 'insufficient_data':
            self.stdout.write(self.style.WARNING("⚠️ Insufficient data for analysis"))
            self.stdout.write("Connection monitoring needs more time to collect metrics.")
            self.stdout.write("Try running the health check first, then wait a few minutes.")
            return
        
        self.stdout.write(f"\n📊 Connection Pool Performance Analysis")
        self.stdout.write('=' * 60)
        
        # Performance rating
        rating = analysis['performance_rating']
        rating_icon = {
            'optimal': '✅',
            'needs_tuning': '⚡',
            'under_provisioned': '🔴',
            'over_provisioned': '🟡'
        }.get(rating, '⚪')
        
        self.stdout.write(f"Performance Rating: {rating_icon} {rating.upper().replace('_', ' ')}")
        
        # Current metrics
        metrics = analysis['current_metrics']
        self.stdout.write(f"\nConnection Statistics:")
        self.stdout.write(f"  Average Total: {metrics['avg_total_connections']:.1f}")
        self.stdout.write(f"  Peak Usage: {metrics['max_total_connections']:.0f}")
        self.stdout.write(f"  Average Active: {metrics['avg_active_connections']:.1f}")
        self.stdout.write(f"  Average Idle: {metrics['avg_idle_connections']:.1f}")
        
        utilization = metrics['utilization_rate']
        if utilization < 50:
            util_status = self.style.SUCCESS(f"{utilization:.1f}%")
        elif utilization < 80:
            util_status = self.style.WARNING(f"{utilization:.1f}%")
        else:
            util_status = self.style.ERROR(f"{utilization:.1f}%")
        
        self.stdout.write(f"  Utilization Rate: {util_status}")
        
        # Performance indicators
        conn_wait = metrics.get('avg_connection_wait', 0)
        if conn_wait > 0:
            if conn_wait < 0.1:
                wait_status = self.style.SUCCESS(f"{conn_wait:.3f}s")
            elif conn_wait < 0.5:
                wait_status = self.style.WARNING(f"{conn_wait:.3f}s")
            else:
                wait_status = self.style.ERROR(f"{conn_wait:.3f}s")
            
            self.stdout.write(f"  Avg Connection Wait: {wait_status}")
        
        query_time = metrics.get('avg_query_time', 0)
        if query_time > 0:
            if query_time < 0.1:
                query_status = self.style.SUCCESS(f"{query_time:.3f}s")
            elif query_time < 0.5:
                query_status = self.style.WARNING(f"{query_time:.3f}s")
            else:
                query_status = self.style.ERROR(f"{query_time:.3f}s")
            
            self.stdout.write(f"  Avg Query Time: {query_status}")
        
        # Issues identified
        issues = analysis.get('issues', [])
        if issues:
            self.stdout.write(f"\n⚠️ Issues Identified:")
            for issue in issues:
                self.stdout.write(f"  • {issue}")
        
        # Recommendations
        recommendations = analysis.get('recommendations', [])
        if recommendations:
            self.stdout.write(f"\n💡 Recommendations:")
            for rec in recommendations:
                self.stdout.write(f"  • {rec}")
        
        # Analysis metadata
        self.stdout.write(f"\nAnalysis Details:")
        self.stdout.write(f"  Period: {analysis['analysis_period_hours']} hours")
        self.stdout.write(f"  Samples: {analysis['samples_analyzed']}")
        
        # Connection history trends
        if show_history:
            self._show_connection_history()
        
        # Next steps
        self.stdout.write(f"\n🚀 Next Steps:")
        if rating in ['under_provisioned', 'needs_tuning']:
            self.stdout.write("  1. Run --action=optimize to get configuration recommendations")
            self.stdout.write("  2. Consider applying optimized configuration")
        elif rating == 'over_provisioned':
            self.stdout.write("  1. Consider reducing connection pool size")
            self.stdout.write("  2. Monitor for any performance impact")
        else:
            self.stdout.write("  1. Continue monitoring performance")
            self.stdout.write("  2. Review periodically as load patterns change")
    
    def _optimize_configuration(self, options):
        """Generate and optionally apply optimized configuration"""
        
        apply_config = options['apply_config']
        max_conn_override = options.get('max_connections')
        min_conn_override = options.get('min_connections')
        
        self.stdout.write("Generating optimized connection pool configuration...")
        
        # Get optimal configuration
        optimal_config = get_optimal_config()
        
        # Apply overrides
        if max_conn_override:
            optimal_config.max_connections = max_conn_override
            self.stdout.write(f"Override applied: max_connections = {max_conn_override}")
        
        if min_conn_override:
            optimal_config.min_connections = min_conn_override
            self.stdout.write(f"Override applied: min_connections = {min_conn_override}")
        
        self.stdout.write(f"\n🔧 Optimal Connection Pool Configuration")
        self.stdout.write('=' * 55)
        
        # Show current vs optimal
        current_config = connection_pool_optimizer.current_config
        
        self.stdout.write(f"Max Connections:")
        self.stdout.write(f"  Current: {current_config.max_connections}")
        self.stdout.write(f"  Optimal: {optimal_config.max_connections}")
        
        self.stdout.write(f"Min Connections:")
        self.stdout.write(f"  Current: {current_config.min_connections}")
        self.stdout.write(f"  Optimal: {optimal_config.min_connections}")
        
        self.stdout.write(f"Connection Max Age:")
        self.stdout.write(f"  Current: {current_config.connection_max_age}s")
        self.stdout.write(f"  Optimal: {optimal_config.connection_max_age}s")
        
        self.stdout.write(f"Connection Timeout:")
        self.stdout.write(f"  Current: {current_config.connection_timeout}s")
        self.stdout.write(f"  Optimal: {optimal_config.connection_timeout}s")
        
        self.stdout.write(f"Pool Recycle:")
        self.stdout.write(f"  Current: {current_config.pool_recycle}s")
        self.stdout.write(f"  Optimal: {optimal_config.pool_recycle}s")
        
        self.stdout.write(f"Pool Pre-ping:")
        self.stdout.write(f"  Current: {current_config.pool_pre_ping}")
        self.stdout.write(f"  Optimal: {optimal_config.pool_pre_ping}")
        
        # Apply configuration (dry run by default)
        result = connection_pool_optimizer.apply_configuration(optimal_config, dry_run=not apply_config)
        
        self.stdout.write(f"\n⚙️ Configuration Application:")
        
        if result['status'] == 'dry_run':
            self.stdout.write(self.style.WARNING("🔍 DRY RUN MODE - Configuration not applied"))
            self.stdout.write("Use --apply-config flag to apply the configuration")
        elif result['status'] == 'success':
            self.stdout.write(self.style.SUCCESS("✅ Configuration ready for application"))
        elif result['status'] == 'error':
            self.stdout.write(self.style.ERROR(f"❌ Configuration error: {result['message']}"))
        
        # Show Django configuration
        if 'django_config' in result:
            self.stdout.write(f"\n📝 Django Database Configuration:")
            django_config = result['django_config']
            
            self.stdout.write("Add to your settings.py:")
            self.stdout.write("```python")
            self.stdout.write("DATABASES = {")
            self.stdout.write("    'default': {")
            for key, value in django_config.items():
                if key == 'OPTIONS':
                    self.stdout.write(f"        '{key}': {{")
                    for opt_key, opt_value in value.items():
                        self.stdout.write(f"            '{opt_key}': {opt_value},")
                    self.stdout.write("        },")
                else:
                    self.stdout.write(f"        '{key}': {repr(value) if isinstance(value, str) else value},")
            self.stdout.write("    }")
            self.stdout.write("}")
            self.stdout.write("```")
        
        # Show implementation instructions
        if 'instructions' in result:
            self.stdout.write(f"\n📋 Implementation Instructions:")
            for i, instruction in enumerate(result['instructions'], 1):
                self.stdout.write(f"  {i}. {instruction}")
        
        # Configuration recommendations
        config_recs = connection_pool_optimizer.get_configuration_recommendations()
        if config_recs:
            self.stdout.write(f"\n💡 Additional Recommendations:")
            for rec in config_recs:
                self.stdout.write(f"  • {rec}")
    
    def _monitor_connections(self, options):
        """Monitor connections in real-time"""
        
        duration = options['monitoring_duration']
        
        self.stdout.write(f"Monitoring database connections for {duration} seconds...")
        self.stdout.write("Press Ctrl+C to stop early\n")
        
        try:
            start_time = time.time()
            
            while time.time() - start_time < duration:
                current_metrics = get_connection_metrics()
                
                elapsed = int(time.time() - start_time)
                
                # Clear line and show current stats
                print(f"\r[{elapsed:3d}s] Total: {current_metrics.total_connections:2d} | "
                      f"Active: {current_metrics.active_connections:2d} | "
                      f"Idle: {current_metrics.idle_connections:2d} | "
                      f"Peak: {current_metrics.max_connections_used:2d}", end='')
                
                time.sleep(2)  # Update every 2 seconds
            
            print()  # New line after monitoring
            
        except KeyboardInterrupt:
            print("\nMonitoring stopped by user")
        
        # Final summary
        final_metrics = get_connection_metrics()
        self.stdout.write(f"\n📊 Monitoring Summary:")
        self.stdout.write(f"  Duration: {duration}s")
        self.stdout.write(f"  Final Total Connections: {final_metrics.total_connections}")
        self.stdout.write(f"  Peak Connections Used: {final_metrics.max_connections_used}")
        self.stdout.write(f"  Current Active: {final_metrics.active_connections}")
        self.stdout.write(f"  Current Idle: {final_metrics.idle_connections}")
    
    def _show_connection_history(self):
        """Show connection metrics history"""
        
        history = db_connection_monitor.get_metrics_history(6)  # Last 6 hours
        
        if not history:
            self.stdout.write("No connection history available")
            return
        
        self.stdout.write(f"\n📈 Connection History (Last 6 Hours):")
        self.stdout.write("Time      | Total | Active | Idle  | Peak")
        self.stdout.write("-" * 45)
        
        for metrics in history[-10:]:  # Show last 10 entries
            timestamp = metrics.timestamp.strftime("%H:%M:%S")
            self.stdout.write(
                f"{timestamp} | {metrics.total_connections:5d} | "
                f"{metrics.active_connections:6d} | {metrics.idle_connections:5d} | "
                f"{metrics.max_connections_used:4d}"
            )
    
    def _export_analysis(self, options):
        """Export connection pool analysis to file"""
        
        export_file = options.get('export_file')
        if not export_file:
            from django.utils import timezone
            timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
            export_file = f'connection_pool_analysis_{timestamp}.json'
        
        self.stdout.write(f"Exporting connection pool analysis to {export_file}...")
        
        try:
            # Collect all analysis data
            health_check = perform_health_check()
            performance_analysis = analyze_pool_performance()
            current_metrics = get_connection_metrics()
            optimal_config = get_optimal_config()
            metrics_history = db_connection_monitor.get_metrics_history(24)
            
            export_data = {
                'timestamp': timezone.now().isoformat(),
                'health_check': health_check,
                'performance_analysis': performance_analysis,
                'current_metrics': {
                    'total_connections': current_metrics.total_connections,
                    'active_connections': current_metrics.active_connections,
                    'idle_connections': current_metrics.idle_connections,
                    'max_connections_used': current_metrics.max_connections_used,
                    'connection_wait_time': current_metrics.connection_wait_time,
                    'avg_query_time': current_metrics.avg_query_time,
                    'failed_connections': current_metrics.failed_connections
                },
                'optimal_configuration': {
                    'max_connections': optimal_config.max_connections,
                    'min_connections': optimal_config.min_connections,
                    'connection_max_age': optimal_config.connection_max_age,
                    'connection_timeout': optimal_config.connection_timeout,
                    'pool_recycle': optimal_config.pool_recycle,
                    'pool_pre_ping': optimal_config.pool_pre_ping
                },
                'metrics_history_count': len(metrics_history),
                'system_info': {
                    'memory_gb': db_connection_monitor.system_memory_gb,
                    'cpu_cores': db_connection_monitor.cpu_cores
                }
            }
            
            with open(export_file, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            self.stdout.write(f"\n✅ Analysis exported to: {export_file}")
            
            # Show export summary
            self.stdout.write(f"\n📊 Export Summary:")
            self.stdout.write(f"  Health Status: {health_check.get('status', 'unknown')}")
            self.stdout.write(f"  Performance Rating: {performance_analysis.get('performance_rating', 'unknown')}")
            self.stdout.write(f"  Current Connections: {current_metrics.total_connections}")
            self.stdout.write(f"  Optimal Max Connections: {optimal_config.max_connections}")
            self.stdout.write(f"  History Samples: {len(metrics_history)}")
            
        except Exception as e:
            raise CommandError(f"Failed to export analysis: {str(e)}")
