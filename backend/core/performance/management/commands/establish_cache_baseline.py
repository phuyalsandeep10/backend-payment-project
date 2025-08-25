"""
Cache Baseline Establishment Command - Task 4.1.1

Django management command to establish cache performance baselines
and generate comprehensive baseline reports.
"""

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from core.performance.cache_performance_monitor import (
    cache_performance_collector,
    cache_instrumentation
)
import time
import json
import os
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """
    Establish cache performance baselines
    Task 4.1.1: Baseline establishment automation
    """
    
    help = 'Establish cache performance baselines and generate baseline reports'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--duration',
            type=int,
            default=300,
            help='Duration in seconds to collect baseline data (default: 300)'
        )
        
        parser.add_argument(
            '--output',
            type=str,
            help='Output file path for baseline report (optional)'
        )
        
        parser.add_argument(
            '--auto-start',
            action='store_true',
            help='Automatically start cache monitoring if not active'
        )
        
        parser.add_argument(
            '--simulate-load',
            action='store_true',
            help='Simulate cache load for baseline establishment'
        )
        
        parser.add_argument(
            '--export-format',
            choices=['json', 'csv'],
            default='json',
            help='Export format for baseline report (default: json)'
        )
        
        parser.add_argument(
            '--quiet',
            action='store_true',
            help='Suppress progress output'
        )
    
    def handle(self, *args, **options):
        try:
            self.stdout.write(
                self.style.SUCCESS('🚀 Starting cache baseline establishment - Task 4.1.1')
            )
            
            # Check if monitoring is active
            if not cache_instrumentation._instrumented:
                if options['auto_start']:
                    self.stdout.write('Starting cache monitoring...')
                    cache_instrumentation.instrument_cache()
                else:
                    raise CommandError(
                        'Cache monitoring is not active. Use --auto-start to enable it.'
                    )
            
            # Reset existing metrics for clean baseline
            cache_performance_collector.reset_metrics()
            self.stdout.write('Reset existing cache metrics for clean baseline')
            
            # Simulate load if requested
            if options['simulate_load']:
                self._simulate_cache_load()
            
            # Collect baseline data
            duration = options['duration']
            self._collect_baseline_data(duration, options['quiet'])
            
            # Generate and export baseline report
            report = self._generate_baseline_report(options)
            
            # Output summary
            self._output_baseline_summary(report)
            
            self.stdout.write(
                self.style.SUCCESS('✅ Cache baseline establishment completed successfully!')
            )
            
        except Exception as e:
            logger.error(f"Error establishing cache baseline: {e}")
            raise CommandError(f'Failed to establish cache baseline: {str(e)}')
    
    def _simulate_cache_load(self):
        """Simulate cache operations for baseline establishment"""
        from django.core.cache import cache
        import random
        import string
        
        self.stdout.write('Simulating cache load for baseline establishment...')
        
        # Generate sample data
        sample_keys = [
            'user_profile_*',
            'deal_list_org_*',
            'client_data_*',
            'commission_calc_*',
            'dashboard_stats_*',
            'notification_count_*',
            'permission_check_*'
        ]
        
        # Simulate cache operations
        operations_count = 1000
        for i in range(operations_count):
            key_pattern = random.choice(sample_keys)
            key = key_pattern.replace('*', str(random.randint(1, 100)))
            
            # Random operation type
            operation = random.choice(['set', 'get', 'get', 'get'])  # More gets than sets
            
            if operation == 'set':
                # Generate random data
                data = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(100, 1000)))
                cache.set(key, data, timeout=random.randint(60, 3600))
            else:
                # Get operation (might hit or miss)
                cache.get(key)
            
            # Small delay to simulate realistic usage
            if i % 100 == 0:
                time.sleep(0.1)
                if not i % 200:
                    self.stdout.write(f'  Simulated {i} operations...')
        
        self.stdout.write(f'Completed {operations_count} simulated cache operations')
        time.sleep(2)  # Allow final operations to be recorded
    
    def _collect_baseline_data(self, duration, quiet):
        """Collect cache performance data for specified duration"""
        
        if not quiet:
            self.stdout.write(f'Collecting baseline data for {duration} seconds...')
        
        start_time = time.time()
        last_report_time = start_time
        
        while time.time() - start_time < duration:
            current_time = time.time()
            
            # Progress reporting every 30 seconds
            if not quiet and current_time - last_report_time >= 30:
                elapsed = current_time - start_time
                remaining = duration - elapsed
                
                # Get current stats
                stats = cache_performance_collector.get_baseline_stats(1)  # Last minute
                
                self.stdout.write(
                    f'  Progress: {elapsed:.0f}s elapsed, {remaining:.0f}s remaining '
                    f'(Operations: {stats.total_operations}, Hit Rate: {stats.hit_rate:.1%})'
                )
                last_report_time = current_time
            
            time.sleep(5)  # Check every 5 seconds
        
        if not quiet:
            self.stdout.write('Baseline data collection completed')
    
    def _generate_baseline_report(self, options):
        """Generate comprehensive baseline report"""
        
        self.stdout.write('Generating baseline report...')
        
        # Generate the baseline report
        report = cache_performance_collector.export_baseline_report()
        
        # Save to file if output path specified
        output_path = options.get('output')
        if output_path:
            self._save_report(report, output_path, options['export_format'])
        else:
            # Generate default filename
            timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
            filename = f'cache_baseline_{timestamp}.json'
            self._save_report(report, filename, options['export_format'])
        
        return report
    
    def _save_report(self, report, filename, format_type):
        """Save baseline report to file"""
        
        try:
            if format_type == 'json':
                with open(filename, 'w') as f:
                    json.dump(report, f, indent=2, default=str)
            elif format_type == 'csv':
                self._save_report_as_csv(report, filename)
            
            self.stdout.write(f'Baseline report saved to: {filename}')
            
        except Exception as e:
            logger.error(f"Error saving baseline report: {e}")
            raise CommandError(f'Failed to save baseline report: {str(e)}')
    
    def _save_report_as_csv(self, report, filename):
        """Save baseline report in CSV format"""
        import csv
        
        # Change extension to .csv
        if not filename.endswith('.csv'):
            filename = os.path.splitext(filename)[0] + '.csv'
        
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write baseline stats
            writer.writerow(['Metric', 'Value'])
            stats = report['baseline_stats']
            for key, value in stats.items():
                writer.writerow([key.replace('_', ' ').title(), value])
            
            writer.writerow([])  # Empty row
            
            # Write slow operations
            writer.writerow(['Slow Operations'])
            if report['slow_operations']:
                writer.writerow(['Operation', 'Key', 'Execution Time', 'Data Size', 'Timestamp'])
                for op in report['slow_operations']:
                    writer.writerow([
                        op['operation'],
                        op['key'],
                        f"{op['execution_time']:.3f}s",
                        op['data_size'],
                        op['timestamp']
                    ])
            
            writer.writerow([])  # Empty row
            
            # Write key analytics
            writer.writerow(['Key Pattern Analytics'])
            if report['key_analytics']:
                writer.writerow(['Pattern', 'Hit Rate', 'Hit Count', 'Miss Count', 'Avg Time', 'Data Size'])
                for pattern, stats in report['key_analytics'].items():
                    writer.writerow([
                        pattern,
                        f"{stats['hit_rate']:.2%}",
                        stats['hit_count'],
                        stats['miss_count'],
                        f"{stats['avg_time']:.3f}s",
                        stats['data_size']
                    ])
    
    def _output_baseline_summary(self, report):
        """Output baseline summary to console"""
        
        self.stdout.write(self.style.SUCCESS('\n📊 Cache Baseline Summary'))
        self.stdout.write('=' * 50)
        
        stats = report['baseline_stats']
        
        # Key metrics
        self.stdout.write(f"Total Operations: {stats['total_operations']:,}")
        self.stdout.write(f"Hit Rate: {stats['hit_rate']:.1%}")
        self.stdout.write(f"Average Response Time: {stats['avg_response_time']:.3f}s")
        self.stdout.write(f"Operations/Second: {stats['operations_per_second']:.1f}")
        self.stdout.write(f"Data Transferred: {self._format_bytes(stats['total_data_transferred'])}")
        
        # Performance insights
        self.stdout.write(f"\n🔍 Performance Insights:")
        
        if stats['hit_rate'] >= 0.8:
            self.stdout.write(self.style.SUCCESS("✅ Excellent cache hit rate"))
        elif stats['hit_rate'] >= 0.6:
            self.stdout.write(self.style.WARNING("⚠️  Moderate cache hit rate"))
        else:
            self.stdout.write(self.style.ERROR("❌ Poor cache hit rate - needs optimization"))
        
        if stats['avg_response_time'] <= 0.01:
            self.stdout.write(self.style.SUCCESS("✅ Excellent response times"))
        elif stats['avg_response_time'] <= 0.05:
            self.stdout.write(self.style.WARNING("⚠️  Moderate response times"))
        else:
            self.stdout.write(self.style.ERROR("❌ Slow response times - needs optimization"))
        
        # Slow operations
        slow_ops = report['slow_operations']
        if slow_ops:
            self.stdout.write(f"\n⏰ Slow Operations: {len(slow_ops)} detected")
            for op in slow_ops[:3]:  # Show top 3
                self.stdout.write(f"  - {op['operation']} on {op['key']}: {op['execution_time']:.3f}s")
        else:
            self.stdout.write(f"\n✅ No slow operations detected")
        
        # Key analytics
        key_analytics = report['key_analytics']
        if key_analytics:
            self.stdout.write(f"\n🔑 Key Patterns: {len(key_analytics)} analyzed")
            
            # Find patterns with low hit rates
            low_hit_patterns = [
                (pattern, stats) for pattern, stats in key_analytics.items()
                if stats['hit_rate'] < 0.5
            ]
            
            if low_hit_patterns:
                self.stdout.write("  Patterns with low hit rates:")
                for pattern, stats in low_hit_patterns[:3]:
                    self.stdout.write(f"    - {pattern}: {stats['hit_rate']:.1%}")
        
        # Recommendations
        recommendations = report.get('recommendations', [])
        if recommendations:
            self.stdout.write(f"\n💡 Recommendations:")
            for rec in recommendations:
                self.stdout.write(f"  - {rec}")
        
        self.stdout.write('=' * 50)
    
    def _format_bytes(self, bytes_count):
        """Format bytes for human readability"""
        if bytes_count == 0:
            return '0 B'
        
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_count < 1024.0:
                return f"{bytes_count:.1f} {unit}"
            bytes_count /= 1024.0
        
        return f"{bytes_count:.1f} TB"
