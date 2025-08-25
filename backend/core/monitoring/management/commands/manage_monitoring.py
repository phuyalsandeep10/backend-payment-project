"""
Management command for monitoring and alerting operations
"""

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from datetime import timedelta
import json

from core_config.performance_monitor import performance_monitor
from core_config.alerting_system import alerting_system

class Command(BaseCommand):
    help = 'Manage monitoring and alerting system'

    def add_arguments(self, parser):
        parser.add_argument(
            'action',
            choices=[
                'status', 'summary', 'alerts', 'test-alert', 'cleanup',
                'export-metrics', 'reset-counters', 'health-check'
            ],
            help='Action to perform'
        )
        
        parser.add_argument(
            '--hours',
            type=int,
            default=24,
            help='Time period in hours for reports (default: 24)'
        )
        
        parser.add_argument(
            '--rule-name',
            type=str,
            help='Alert rule name for testing'
        )
        
        parser.add_argument(
            '--output-file',
            type=str,
            help='Output file for exporting metrics'
        )
        
        parser.add_argument(
            '--severity',
            choices=['info', 'warning', 'critical'],
            help='Filter alerts by severity'
        )

    def handle(self, *args, **options):
        action = options['action']
        
        try:
            if action == 'status':
                self.show_system_status()
            
            elif action == 'summary':
                self.show_performance_summary(options['hours'])
            
            elif action == 'alerts':
                self.show_alerts(options['hours'], options.get('severity'))
            
            elif action == 'test-alert':
                self.test_alert_rule(options.get('rule_name'))
            
            elif action == 'cleanup':
                self.cleanup_old_data()
            
            elif action == 'export-metrics':
                self.export_metrics(options['hours'], options.get('output_file'))
            
            elif action == 'reset-counters':
                self.reset_performance_counters()
            
            elif action == 'health-check':
                self.perform_health_check()
            
        except Exception as e:
            raise CommandError(f'Error executing {action}: {str(e)}')

    def show_system_status(self):
        """Show current system monitoring status"""
        self.stdout.write(self.style.SUCCESS('=== Monitoring System Status ==='))
        
        # Performance monitor status
        self.stdout.write(f'Total Queries: {performance_monitor.total_queries}')
        self.stdout.write(f'Slow Queries: {performance_monitor.slow_queries}')
        self.stdout.write(f'Total API Calls: {performance_monitor.total_api_calls}')
        self.stdout.write(f'Slow API Calls: {performance_monitor.slow_api_calls}')
        
        # Calculate rates
        if performance_monitor.total_queries > 0:
            slow_query_rate = (performance_monitor.slow_queries / performance_monitor.total_queries) * 100
            self.stdout.write(f'Slow Query Rate: {slow_query_rate:.2f}%')
        
        if performance_monitor.total_api_calls > 0:
            slow_api_rate = (performance_monitor.slow_api_calls / performance_monitor.total_api_calls) * 100
            self.stdout.write(f'Slow API Rate: {slow_api_rate:.2f}%')
        
        # System metrics
        if performance_monitor.system_metrics:
            latest_metrics = list(performance_monitor.system_metrics)[-1]
            self.stdout.write(f'\\nLatest System Metrics:')
            self.stdout.write(f'  CPU: {latest_metrics.get("cpu_percent", 0):.1f}%')
            self.stdout.write(f'  Memory: {latest_metrics.get("memory_percent", 0):.1f}%')
            self.stdout.write(f'  Disk: {latest_metrics.get("disk_percent", 0):.1f}%')
        
        # Alerting system status
        self.stdout.write(f'\\n=== Alerting System Status ===')
        self.stdout.write(f'Active Alert Rules: {len(alerting_system.alert_rules)}')
        self.stdout.write(f'Active Cooldowns: {len(alerting_system.alert_cooldowns)}')
        
        # Recent alerts
        recent_alerts = alerting_system.get_alert_history(hours=1)
        self.stdout.write(f'Alerts (Last Hour): {len(recent_alerts)}')

    def show_performance_summary(self, hours):
        """Show performance summary for specified period"""
        self.stdout.write(self.style.SUCCESS(f'=== Performance Summary ({hours}h) ==='))
        
        summary = performance_monitor.get_performance_summary(hours=hours)
        
        # Query performance
        query_perf = summary.get('query_performance', {})
        self.stdout.write(f'\\nQuery Performance:')
        self.stdout.write(f'  Total Queries: {query_perf.get("total", 0)}')
        self.stdout.write(f'  Slow Queries: {query_perf.get("slow_queries", 0)}')
        self.stdout.write(f'  Average Time: {query_perf.get("avg_time", 0):.3f}s')
        self.stdout.write(f'  Max Time: {query_perf.get("max_time", 0):.3f}s')
        self.stdout.write(f'  Slow Query Rate: {query_perf.get("slow_query_rate", 0):.2f}%')
        
        # API performance
        api_perf = summary.get('api_performance', {})
        self.stdout.write(f'\\nAPI Performance:')
        self.stdout.write(f'  Total API Calls: {api_perf.get("total", 0)}')
        self.stdout.write(f'  Slow API Calls: {api_perf.get("slow_calls", 0)}')
        self.stdout.write(f'  Average Time: {api_perf.get("avg_time", 0):.3f}s')
        self.stdout.write(f'  Max Time: {api_perf.get("max_time", 0):.3f}s')
        self.stdout.write(f'  Error Rate: {api_perf.get("error_rate", 0):.2f}%')
        
        # System metrics
        system_metrics = summary.get('system_metrics', {})
        if system_metrics:
            self.stdout.write(f'\\nSystem Metrics:')
            self.stdout.write(f'  CPU: {system_metrics.get("cpu_percent", 0):.1f}%')
            self.stdout.write(f'  Memory: {system_metrics.get("memory_percent", 0):.1f}%')
            self.stdout.write(f'  Disk: {system_metrics.get("disk_percent", 0):.1f}%')
        
        # Alerts
        alerts = summary.get('alerts', [])
        self.stdout.write(f'\\nAlerts: {len(alerts)}')
        if alerts:
            for alert in alerts[-5:]:  # Show last 5 alerts
                self.stdout.write(f'  [{alert["severity"].upper()}] {alert["message"]}')

    def show_alerts(self, hours, severity=None):
        """Show alerts for specified period"""
        self.stdout.write(self.style.SUCCESS(f'=== Alerts ({hours}h) ==='))
        
        alerts = alerting_system.get_alert_history(hours=hours, severity=severity)
        
        if not alerts:
            self.stdout.write('No alerts found for the specified period.')
            return
        
        # Group by severity
        by_severity = {}
        for alert in alerts:
            sev = alert['severity']
            if sev not in by_severity:
                by_severity[sev] = []
            by_severity[sev].append(alert)
        
        # Show summary
        self.stdout.write(f'Total Alerts: {len(alerts)}')
        for sev, sev_alerts in by_severity.items():
            self.stdout.write(f'  {sev.upper()}: {len(sev_alerts)}')
        
        # Show recent alerts
        self.stdout.write(f'\\nRecent Alerts:')
        for alert in alerts[:20]:  # Show first 20
            timestamp = alert['timestamp'][:19]  # Remove microseconds
            self.stdout.write(f'  [{timestamp}] [{alert["severity"].upper()}] {alert["message"]}')

    def test_alert_rule(self, rule_name):
        """Test a specific alert rule"""
        if not rule_name:
            raise CommandError('Rule name is required for testing')
        
        self.stdout.write(self.style.SUCCESS(f'=== Testing Alert Rule: {rule_name} ==='))
        
        result = alerting_system.test_alert_rule(rule_name)
        
        if 'error' in result:
            self.stdout.write(self.style.ERROR(f'Error: {result["error"]}'))
            return
        
        self.stdout.write(f'Rule Name: {result["rule_name"]}')
        self.stdout.write(f'Condition Met: {result["condition_met"]}')
        self.stdout.write(f'Severity: {result["severity"]}')
        self.stdout.write(f'Message: {result["message"]}')
        self.stdout.write(f'In Cooldown: {result["in_cooldown"]}')
        
        if result["condition_met"]:
            self.stdout.write(self.style.WARNING('⚠️  Alert condition is currently MET'))
        else:
            self.stdout.write(self.style.SUCCESS('✅ Alert condition is not met'))

    def cleanup_old_data(self):
        """Clean up old monitoring data"""
        self.stdout.write(self.style.SUCCESS('=== Cleaning Up Old Data ==='))
        
        # Clean performance monitor data
        old_query_count = len(performance_monitor.query_metrics)
        old_api_count = len(performance_monitor.api_metrics)
        old_system_count = len(performance_monitor.system_metrics)
        
        performance_monitor.clear_old_metrics()
        
        new_query_count = len(performance_monitor.query_metrics)
        new_api_count = len(performance_monitor.api_metrics)
        new_system_count = len(performance_monitor.system_metrics)
        
        self.stdout.write(f'Query Metrics: {old_query_count} → {new_query_count}')
        self.stdout.write(f'API Metrics: {old_api_count} → {new_api_count}')
        self.stdout.write(f'System Metrics: {old_system_count} → {new_system_count}')
        
        # Clean alerting system data
        alerting_system._cleanup_old_alerts()
        
        self.stdout.write(self.style.SUCCESS('Cleanup completed'))

    def export_metrics(self, hours, output_file):
        """Export metrics to JSON file"""
        self.stdout.write(self.style.SUCCESS(f'=== Exporting Metrics ({hours}h) ==='))
        
        # Get performance summary
        performance_summary = performance_monitor.get_performance_summary(hours=hours)
        
        # Get alert history
        alert_history = alerting_system.get_alert_history(hours=hours)
        
        # Get performance trends
        trends = performance_monitor.get_performance_trends(hours=hours)
        
        # Combine all data
        export_data = {
            'export_timestamp': timezone.now().isoformat(),
            'period_hours': hours,
            'performance_summary': performance_summary,
            'alert_history': alert_history,
            'performance_trends': trends,
            'system_info': {
                'total_queries': performance_monitor.total_queries,
                'slow_queries': performance_monitor.slow_queries,
                'total_api_calls': performance_monitor.total_api_calls,
                'slow_api_calls': performance_monitor.slow_api_calls,
                'active_alert_rules': len(alerting_system.alert_rules)
            }
        }
        
        # Write to file
        if not output_file:
            timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
            output_file = f'monitoring_export_{timestamp}.json'
        
        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        self.stdout.write(f'Metrics exported to: {output_file}')
        self.stdout.write(f'Export size: {len(json.dumps(export_data))} bytes')

    def reset_performance_counters(self):
        """Reset performance counters"""
        self.stdout.write(self.style.WARNING('=== Resetting Performance Counters ==='))
        
        old_queries = performance_monitor.total_queries
        old_slow_queries = performance_monitor.slow_queries
        old_api_calls = performance_monitor.total_api_calls
        old_slow_api_calls = performance_monitor.slow_api_calls
        
        performance_monitor.total_queries = 0
        performance_monitor.slow_queries = 0
        performance_monitor.total_api_calls = 0
        performance_monitor.slow_api_calls = 0
        performance_monitor.error_metrics.clear()
        
        self.stdout.write(f'Reset counters:')
        self.stdout.write(f'  Total Queries: {old_queries} → 0')
        self.stdout.write(f'  Slow Queries: {old_slow_queries} → 0')
        self.stdout.write(f'  Total API Calls: {old_api_calls} → 0')
        self.stdout.write(f'  Slow API Calls: {old_slow_api_calls} → 0')
        
        self.stdout.write(self.style.SUCCESS('Performance counters reset'))

    def perform_health_check(self):
        """Perform comprehensive health check"""
        self.stdout.write(self.style.SUCCESS('=== System Health Check ==='))
        
        issues = []
        warnings = []
        
        # Check system metrics
        if performance_monitor.system_metrics:
            latest_metrics = list(performance_monitor.system_metrics)[-1]
            
            cpu_percent = latest_metrics.get('cpu_percent', 0)
            memory_percent = latest_metrics.get('memory_percent', 0)
            disk_percent = latest_metrics.get('disk_percent', 0)
            
            if cpu_percent > 90:
                issues.append(f'Critical CPU usage: {cpu_percent:.1f}%')
            elif cpu_percent > 80:
                warnings.append(f'High CPU usage: {cpu_percent:.1f}%')
            
            if memory_percent > 90:
                issues.append(f'Critical memory usage: {memory_percent:.1f}%')
            elif memory_percent > 80:
                warnings.append(f'High memory usage: {memory_percent:.1f}%')
            
            if disk_percent > 95:
                issues.append(f'Critical disk usage: {disk_percent:.1f}%')
            elif disk_percent > 90:
                warnings.append(f'High disk usage: {disk_percent:.1f}%')
        
        # Check performance rates
        if performance_monitor.total_queries > 0:
            slow_query_rate = (performance_monitor.slow_queries / performance_monitor.total_queries) * 100
            if slow_query_rate > 30:
                issues.append(f'High slow query rate: {slow_query_rate:.1f}%')
            elif slow_query_rate > 15:
                warnings.append(f'Elevated slow query rate: {slow_query_rate:.1f}%')
        
        # Check recent alerts
        recent_critical_alerts = alerting_system.get_alert_history(hours=1, severity='critical')
        if recent_critical_alerts:
            issues.append(f'{len(recent_critical_alerts)} critical alerts in the last hour')
        
        recent_alerts = alerting_system.get_alert_history(hours=1)
        if len(recent_alerts) > 10:
            warnings.append(f'High alert volume: {len(recent_alerts)} alerts in the last hour')
        
        # Report results
        if not issues and not warnings:
            self.stdout.write(self.style.SUCCESS('✅ System health: GOOD'))
        else:
            if issues:
                self.stdout.write(self.style.ERROR('❌ Critical Issues:'))
                for issue in issues:
                    self.stdout.write(f'  - {issue}')
            
            if warnings:
                self.stdout.write(self.style.WARNING('⚠️  Warnings:'))
                for warning in warnings:
                    self.stdout.write(f'  - {warning}')
        
        # Show recommendations
        self.stdout.write(f'\\n=== Recommendations ===')
        if issues or warnings:
            self.stdout.write('Consider the following actions:')
            if any('CPU' in item for item in issues + warnings):
                self.stdout.write('  - Investigate high CPU usage processes')
            if any('memory' in item for item in issues + warnings):
                self.stdout.write('  - Check for memory leaks or optimize memory usage')
            if any('disk' in item for item in issues + warnings):
                self.stdout.write('  - Clean up old files or expand disk space')
            if any('query' in item for item in issues + warnings):
                self.stdout.write('  - Optimize slow database queries')
        else:
            self.stdout.write('System is running optimally. Continue monitoring.')