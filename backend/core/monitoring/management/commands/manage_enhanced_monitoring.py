"""
Enhanced Monitoring Management Command - Task 6.2.2

Django management command for managing enhanced performance monitoring,
including thresholds, baselines, alerts, and configuration.
"""

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
import json
import sys
from datetime import timedelta

from core.monitoring.enhanced_performance_monitor import enhanced_performance_monitor


class Command(BaseCommand):
    help = 'Manage enhanced performance monitoring system'

    def add_arguments(self, parser):
        parser.add_argument(
            '--action',
            type=str,
            choices=[
                'status', 'dashboard', 'alerts', 'thresholds', 'baseline',
                'trends', 'health', 'config', 'reset', 'test'
            ],
            required=True,
            help='Action to perform'
        )
        
        parser.add_argument(
            '--metric',
            type=str,
            help='Specific metric name for metric-related actions'
        )
        
        parser.add_argument(
            '--threshold-type',
            type=str,
            choices=['warning', 'critical'],
            help='Threshold type for threshold operations'
        )
        
        parser.add_argument(
            '--threshold-value',
            type=float,
            help='Threshold value to set'
        )
        
        parser.add_argument(
            '--hours',
            type=int,
            default=24,
            help='Time period in hours for data analysis (default: 24)'
        )
        
        parser.add_argument(
            '--enable',
            action='store_true',
            help='Enable monitoring/alerting/threshold'
        )
        
        parser.add_argument(
            '--disable',
            action='store_true',
            help='Disable monitoring/alerting/threshold'
        )
        
        parser.add_argument(
            '--baseline-duration',
            type=int,
            default=60,
            help='Duration in minutes for baseline establishment (default: 60)'
        )
        
        parser.add_argument(
            '--output-format',
            type=str,
            choices=['text', 'json'],
            default='text',
            help='Output format (default: text)'
        )
        
        parser.add_argument(
            '--severity',
            type=str,
            choices=['warning', 'critical'],
            help='Filter alerts by severity'
        )
        
        parser.add_argument(
            '--active-only',
            action='store_true',
            help='Show only active alerts'
        )

    def handle(self, *args, **options):
        action = options['action']
        
        try:
            if action == 'status':
                self.handle_status(options)
            elif action == 'dashboard':
                self.handle_dashboard(options)
            elif action == 'alerts':
                self.handle_alerts(options)
            elif action == 'thresholds':
                self.handle_thresholds(options)
            elif action == 'baseline':
                self.handle_baseline(options)
            elif action == 'trends':
                self.handle_trends(options)
            elif action == 'health':
                self.handle_health(options)
            elif action == 'config':
                self.handle_config(options)
            elif action == 'reset':
                self.handle_reset(options)
            elif action == 'test':
                self.handle_test(options)
        
        except Exception as e:
            raise CommandError(f'Command failed: {str(e)}')

    def handle_status(self, options):
        """Show enhanced monitoring status"""
        self.stdout.write(self.style.SUCCESS('🔍 Enhanced Performance Monitoring Status'))
        self.stdout.write('=' * 60)
        
        # Monitoring status
        status_info = {
            'Monitoring Enabled': enhanced_performance_monitor.monitoring_enabled,
            'Alert Enabled': enhanced_performance_monitor.alert_enabled,
            'Trend Analysis Enabled': enhanced_performance_monitor.trend_analysis_enabled,
            'Monitoring Interval': f"{enhanced_performance_monitor.monitoring_interval}s",
            'Baseline Established': bool(enhanced_performance_monitor.baseline_metrics),
            'Active Alerts': len(enhanced_performance_monitor.active_alerts),
            'Total Thresholds': len(enhanced_performance_monitor.thresholds),
            'Enabled Thresholds': sum(1 for t in enhanced_performance_monitor.thresholds.values() if t.enabled),
            'Application Metrics Collected': len(enhanced_performance_monitor.application_metrics),
            'Performance Trends': len(enhanced_performance_monitor.performance_trends),
        }
        
        for key, value in status_info.items():
            status = '✅' if value else '❌' if isinstance(value, bool) else '📊'
            self.stdout.write(f"{status} {key}: {value}")
        
        if options['output_format'] == 'json':
            self.stdout.write('\nJSON Output:')
            self.stdout.write(json.dumps(status_info, indent=2, default=str))

    def handle_dashboard(self, options):
        """Show performance dashboard summary"""
        hours = options['hours']
        
        self.stdout.write(self.style.SUCCESS(f'📊 Performance Dashboard - Last {hours} Hours'))
        self.stdout.write('=' * 60)
        
        dashboard_data = enhanced_performance_monitor.get_performance_dashboard_data(hours)
        
        if options['output_format'] == 'json':
            self.stdout.write(json.dumps(dashboard_data, indent=2, default=str))
        else:
            # Text summary
            current_metrics = dashboard_data.get('current_metrics', {})
            averages = dashboard_data.get('averages', {})
            trends = dashboard_data.get('trends', {})
            
            self.stdout.write('\n📈 Current Metrics:')
            for metric, value in current_metrics.items():
                if isinstance(value, (int, float)):
                    self.stdout.write(f"  {metric}: {value:.2f}")
            
            self.stdout.write('\n📊 Average Performance:')
            for metric, values in averages.items():
                if isinstance(values, dict) and 'mean' in values:
                    self.stdout.write(f"  {metric}: {values['mean']:.2f} (min: {values['min']:.2f}, max: {values['max']:.2f})")
            
            self.stdout.write('\n📈 Performance Trends:')
            for metric, trend in trends.items():
                direction = trend['trend_direction']
                change = trend['change_percent']
                emoji = '📈' if direction == 'improving' else '📉' if direction == 'degrading' else '➡️'
                self.stdout.write(f"  {emoji} {metric}: {direction} ({change:+.1f}%)")

    def handle_alerts(self, options):
        """Manage performance alerts"""
        hours = options['hours']
        severity = options['severity']
        active_only = options['active_only']
        
        self.stdout.write(self.style.WARNING(f'🚨 Performance Alerts - Last {hours} Hours'))
        self.stdout.write('=' * 60)
        
        # Get alerts
        if active_only:
            alerts = list(enhanced_performance_monitor.active_alerts.values())
            self.stdout.write(f"Active Alerts: {len(alerts)}")
        else:
            cutoff_time = timezone.now() - timedelta(hours=hours)
            alerts = [
                alert for alert in enhanced_performance_monitor.alert_history
                if alert.timestamp > cutoff_time
            ]
            self.stdout.write(f"Total Alerts in {hours}h: {len(alerts)}")
        
        # Apply severity filter
        if severity:
            alerts = [alert for alert in alerts if alert.severity == severity]
            self.stdout.write(f"Filtered by severity '{severity}': {len(alerts)}")
        
        if options['output_format'] == 'json':
            alerts_data = [
                {
                    'alert_id': alert.alert_id,
                    'metric_name': alert.metric_name,
                    'severity': alert.severity,
                    'current_value': alert.current_value,
                    'threshold_value': alert.threshold_value,
                    'message': alert.message,
                    'timestamp': alert.timestamp.isoformat()
                }
                for alert in alerts
            ]
            self.stdout.write(json.dumps(alerts_data, indent=2))
        else:
            # Group alerts by metric
            alerts_by_metric = {}
            for alert in alerts:
                if alert.metric_name not in alerts_by_metric:
                    alerts_by_metric[alert.metric_name] = []
                alerts_by_metric[alert.metric_name].append(alert)
            
            for metric_name, metric_alerts in alerts_by_metric.items():
                self.stdout.write(f"\n📊 {metric_name} ({len(metric_alerts)} alerts):")
                for alert in sorted(metric_alerts, key=lambda a: a.timestamp, reverse=True)[:5]:
                    severity_emoji = '🔴' if alert.severity == 'critical' else '🟡'
                    self.stdout.write(
                        f"  {severity_emoji} {alert.timestamp.strftime('%m/%d %H:%M')} - "
                        f"{alert.message}"
                    )

    def handle_thresholds(self, options):
        """Manage performance thresholds"""
        metric = options['metric']
        threshold_type = options['threshold_type']
        threshold_value = options['threshold_value']
        enable = options['enable']
        disable = options['disable']
        
        if not metric and not threshold_value and not enable and not disable:
            # Show all thresholds
            self.stdout.write(self.style.SUCCESS('⚡ Performance Thresholds'))
            self.stdout.write('=' * 60)
            
            for name, threshold in enhanced_performance_monitor.thresholds.items():
                status = '✅ Enabled' if threshold.enabled else '❌ Disabled'
                self.stdout.write(f"\n📊 {name} ({status}):")
                self.stdout.write(f"  Warning: {threshold.warning_threshold}")
                self.stdout.write(f"  Critical: {threshold.critical_threshold}")
                self.stdout.write(f"  Comparison: {threshold.comparison}")
                self.stdout.write(f"  Consecutive violations: {threshold.consecutive_violations}")
                self.stdout.write(f"  Cooldown: {threshold.cooldown_minutes} minutes")
            
            return
        
        if not metric:
            raise CommandError('--metric is required for threshold modifications')
        
        # Update threshold
        updates = {}
        
        if threshold_type and threshold_value:
            if threshold_type == 'warning':
                updates['warning_threshold'] = threshold_value
            elif threshold_type == 'critical':
                updates['critical_threshold'] = threshold_value
        
        if enable:
            updates['enabled'] = True
        elif disable:
            updates['enabled'] = False
        
        if updates:
            enhanced_performance_monitor.update_threshold(metric, **updates)
            self.stdout.write(
                self.style.SUCCESS(f'✅ Updated threshold for {metric}: {updates}')
            )
        else:
            # Show specific threshold
            if metric in enhanced_performance_monitor.thresholds:
                threshold = enhanced_performance_monitor.thresholds[metric]
                self.stdout.write(f"📊 Threshold: {metric}")
                self.stdout.write(f"  Enabled: {threshold.enabled}")
                self.stdout.write(f"  Warning: {threshold.warning_threshold}")
                self.stdout.write(f"  Critical: {threshold.critical_threshold}")
                self.stdout.write(f"  Comparison: {threshold.comparison}")
            else:
                self.stdout.write(self.style.ERROR(f'❌ Threshold not found: {metric}'))

    def handle_baseline(self, options):
        """Manage performance baseline"""
        duration = options['baseline_duration']
        
        if not enhanced_performance_monitor.baseline_metrics:
            self.stdout.write(self.style.WARNING('📊 No Performance Baseline Established'))
            
            # Offer to establish baseline
            if len(enhanced_performance_monitor.application_metrics) >= duration:
                try:
                    baseline = enhanced_performance_monitor.establish_performance_baseline(duration)
                    self.stdout.write(
                        self.style.SUCCESS(f'✅ Baseline established with {duration} minutes of data')
                    )
                    
                    if options['output_format'] == 'json':
                        self.stdout.write(json.dumps(baseline, indent=2))
                    else:
                        for metric, value in baseline.items():
                            self.stdout.write(f"  {metric}: {value:.3f}")
                            
                except ValueError as e:
                    self.stdout.write(self.style.ERROR(f'❌ {str(e)}'))
            else:
                self.stdout.write(
                    f'❌ Need at least {duration} minutes of data. '
                    f'Currently have {len(enhanced_performance_monitor.application_metrics)} data points.'
                )
        else:
            self.stdout.write(self.style.SUCCESS('📊 Current Performance Baseline'))
            self.stdout.write('=' * 60)
            
            if options['output_format'] == 'json':
                self.stdout.write(json.dumps(enhanced_performance_monitor.baseline_metrics, indent=2))
            else:
                for metric, value in enhanced_performance_monitor.baseline_metrics.items():
                    self.stdout.write(f"  {metric}: {value:.3f}")

    def handle_trends(self, options):
        """Show performance trends analysis"""
        self.stdout.write(self.style.SUCCESS('📈 Performance Trends Analysis'))
        self.stdout.write('=' * 60)
        
        trends = enhanced_performance_monitor.performance_trends
        
        if not trends:
            self.stdout.write('❌ No trend data available')
            return
        
        if options['output_format'] == 'json':
            trends_data = {
                name: {
                    'metric_name': trend.metric_name,
                    'current_avg': trend.current_avg,
                    'previous_avg': trend.previous_avg,
                    'change_percent': trend.change_percent,
                    'trend_direction': trend.trend_direction,
                    'confidence': trend.confidence
                }
                for name, trend in trends.items()
            }
            self.stdout.write(json.dumps(trends_data, indent=2))
        else:
            # Group by trend direction
            improving = []
            degrading = []
            stable = []
            
            for name, trend in trends.items():
                if trend.trend_direction == 'improving':
                    improving.append((name, trend))
                elif trend.trend_direction == 'degrading':
                    degrading.append((name, trend))
                else:
                    stable.append((name, trend))
            
            if improving:
                self.stdout.write('\n📈 Improving Metrics:')
                for name, trend in improving:
                    self.stdout.write(
                        f"  ✅ {name}: {trend.change_percent:+.1f}% "
                        f"(confidence: {trend.confidence:.2f})"
                    )
            
            if degrading:
                self.stdout.write('\n📉 Degrading Metrics:')
                for name, trend in degrading:
                    self.stdout.write(
                        f"  ❌ {name}: {trend.change_percent:+.1f}% "
                        f"(confidence: {trend.confidence:.2f})"
                    )
            
            if stable:
                self.stdout.write('\n➡️  Stable Metrics:')
                for name, trend in stable:
                    self.stdout.write(
                        f"  ✓ {name}: {trend.change_percent:+.1f}% "
                        f"(confidence: {trend.confidence:.2f})"
                    )

    def handle_health(self, options):
        """Show system health status"""
        self.stdout.write(self.style.SUCCESS('🏥 System Health Status'))
        self.stdout.write('=' * 60)
        
        dashboard_data = enhanced_performance_monitor.get_performance_dashboard_data(1)  # Last hour
        current_metrics = dashboard_data.get('current_metrics', {})
        
        if not current_metrics:
            self.stdout.write(self.style.ERROR('❌ No current metrics available'))
            return
        
        health_issues = []
        warnings = []
        
        # Check each threshold
        for name, threshold in enhanced_performance_monitor.thresholds.items():
            if not threshold.enabled:
                continue
            
            metric_value = current_metrics.get(threshold.metric_name)
            if metric_value is None:
                continue
            
            if threshold.comparison == 'greater':
                if metric_value > threshold.critical_threshold:
                    health_issues.append(f"{threshold.metric_name}: {metric_value:.2f} > {threshold.critical_threshold} (CRITICAL)")
                elif metric_value > threshold.warning_threshold:
                    warnings.append(f"{threshold.metric_name}: {metric_value:.2f} > {threshold.warning_threshold} (WARNING)")
            elif threshold.comparison == 'less':
                if metric_value < threshold.critical_threshold:
                    health_issues.append(f"{threshold.metric_name}: {metric_value:.2f} < {threshold.critical_threshold} (CRITICAL)")
                elif metric_value < threshold.warning_threshold:
                    warnings.append(f"{threshold.metric_name}: {metric_value:.2f} < {threshold.warning_threshold} (WARNING)")
        
        # Overall health status
        if health_issues:
            self.stdout.write(self.style.ERROR('🔴 SYSTEM HEALTH: CRITICAL'))
            self.stdout.write('\nCritical Issues:')
            for issue in health_issues:
                self.stdout.write(f"  🔴 {issue}")
        elif warnings:
            self.stdout.write(self.style.WARNING('🟡 SYSTEM HEALTH: WARNING'))
            self.stdout.write('\nWarnings:')
            for warning in warnings:
                self.stdout.write(f"  🟡 {warning}")
        else:
            self.stdout.write(self.style.SUCCESS('🟢 SYSTEM HEALTH: HEALTHY'))
        
        # Show key metrics
        self.stdout.write('\n📊 Current Metrics:')
        key_metrics = ['response_time_p95', 'throughput_rps', 'error_rate', 'memory_usage_mb', 'cpu_usage_percent']
        for metric in key_metrics:
            value = current_metrics.get(metric)
            if value is not None:
                self.stdout.write(f"  {metric}: {value:.2f}")

    def handle_config(self, options):
        """Show monitoring configuration"""
        self.stdout.write(self.style.SUCCESS('⚙️ Enhanced Monitoring Configuration'))
        self.stdout.write('=' * 60)
        
        config = {
            'monitoring_enabled': enhanced_performance_monitor.monitoring_enabled,
            'alert_enabled': enhanced_performance_monitor.alert_enabled,
            'trend_analysis_enabled': enhanced_performance_monitor.trend_analysis_enabled,
            'monitoring_interval_seconds': enhanced_performance_monitor.monitoring_interval,
            'metrics_retention_hours': enhanced_performance_monitor.METRICS_RETENTION_HOURS,
            'regression_sensitivity': enhanced_performance_monitor.regression_sensitivity,
            'slow_query_threshold': enhanced_performance_monitor.SLOW_QUERY_THRESHOLD,
            'slow_api_threshold': enhanced_performance_monitor.SLOW_API_THRESHOLD,
            'data_structures': {
                'application_metrics': len(enhanced_performance_monitor.application_metrics),
                'alert_history': len(enhanced_performance_monitor.alert_history),
                'active_alerts': len(enhanced_performance_monitor.active_alerts),
                'performance_trends': len(enhanced_performance_monitor.performance_trends),
                'thresholds': len(enhanced_performance_monitor.thresholds)
            }
        }
        
        if options['output_format'] == 'json':
            self.stdout.write(json.dumps(config, indent=2))
        else:
            for category, values in config.items():
                if isinstance(values, dict):
                    self.stdout.write(f"\n{category}:")
                    for key, value in values.items():
                        self.stdout.write(f"  {key}: {value}")
                else:
                    self.stdout.write(f"{category}: {values}")

    def handle_reset(self, options):
        """Reset monitoring data (use with caution)"""
        self.stdout.write(self.style.WARNING('🔄 Resetting Enhanced Monitoring Data'))
        
        # Confirm action
        confirm = input('This will clear all monitoring data. Continue? (yes/no): ')
        if confirm.lower() != 'yes':
            self.stdout.write('Operation cancelled.')
            return
        
        # Reset data structures
        enhanced_performance_monitor.application_metrics.clear()
        enhanced_performance_monitor.alert_history.clear()
        enhanced_performance_monitor.active_alerts.clear()
        enhanced_performance_monitor.performance_trends.clear()
        enhanced_performance_monitor.threshold_violations.clear()
        enhanced_performance_monitor.baseline_metrics.clear()
        
        self.stdout.write(self.style.SUCCESS('✅ Monitoring data reset complete'))

    def handle_test(self, options):
        """Run monitoring system tests"""
        self.stdout.write(self.style.SUCCESS('🧪 Testing Enhanced Monitoring System'))
        self.stdout.write('=' * 60)
        
        tests_passed = 0
        total_tests = 0
        
        # Test 1: Check if monitoring is running
        total_tests += 1
        if enhanced_performance_monitor.monitoring_enabled:
            self.stdout.write('✅ Test 1: Monitoring system is enabled')
            tests_passed += 1
        else:
            self.stdout.write('❌ Test 1: Monitoring system is disabled')
        
        # Test 2: Check data collection
        total_tests += 1
        if len(enhanced_performance_monitor.application_metrics) > 0:
            self.stdout.write(f'✅ Test 2: Metrics collection active ({len(enhanced_performance_monitor.application_metrics)} data points)')
            tests_passed += 1
        else:
            self.stdout.write('❌ Test 2: No metrics data collected')
        
        # Test 3: Check threshold configuration
        total_tests += 1
        enabled_thresholds = sum(1 for t in enhanced_performance_monitor.thresholds.values() if t.enabled)
        if enabled_thresholds > 0:
            self.stdout.write(f'✅ Test 3: Thresholds configured ({enabled_thresholds} enabled)')
            tests_passed += 1
        else:
            self.stdout.write('❌ Test 3: No thresholds enabled')
        
        # Test 4: Check alerting system
        total_tests += 1
        if enhanced_performance_monitor.alert_enabled:
            self.stdout.write('✅ Test 4: Alerting system is enabled')
            tests_passed += 1
        else:
            self.stdout.write('❌ Test 4: Alerting system is disabled')
        
        # Summary
        self.stdout.write(f'\n📊 Test Results: {tests_passed}/{total_tests} tests passed')
        if tests_passed == total_tests:
            self.stdout.write(self.style.SUCCESS('🎉 All tests passed!'))
        else:
            self.stdout.write(self.style.WARNING('⚠️ Some tests failed. Check configuration.'))
