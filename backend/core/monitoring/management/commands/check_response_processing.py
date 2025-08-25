"""
Management command to check response processing metrics and health
"""

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from datetime import timedelta
import json

from core_config.response_processing_monitor import response_processing_monitor


class Command(BaseCommand):
    help = 'Check response processing metrics and health status'

    def add_arguments(self, parser):
        parser.add_argument(
            '--hours',
            type=int,
            default=1,
            help='Number of hours to analyze (default: 1)'
        )
        parser.add_argument(
            '--format',
            choices=['json', 'table'],
            default='table',
            help='Output format (default: table)'
        )
        parser.add_argument(
            '--show-errors',
            action='store_true',
            help='Show detailed error information'
        )
        parser.add_argument(
            '--show-slow-renders',
            action='store_true',
            help='Show slow render details'
        )
        parser.add_argument(
            '--clear-old',
            action='store_true',
            help='Clear old metrics after displaying results'
        )

    def handle(self, *args, **options):
        hours = options['hours']
        output_format = options['format']
        show_errors = options['show_errors']
        show_slow_renders = options['show_slow_renders']
        clear_old = options['clear_old']

        try:
            # Get comprehensive metrics
            metrics = response_processing_monitor.get_performance_metrics(hours=hours)
            
            if output_format == 'json':
                self.stdout.write(json.dumps(metrics, indent=2))
                return

            # Display table format
            self.stdout.write(
                self.style.SUCCESS(f'\n=== Response Processing Metrics (Last {hours} hour{"s" if hours != 1 else ""}) ===')
            )
            
            # Overall statistics
            overall = metrics['overall_stats']
            self.stdout.write(f'\nOverall Statistics:')
            self.stdout.write(f'  Total Responses: {overall["total_responses"]}')
            self.stdout.write(f'  Template Responses: {overall["template_responses"]}')
            self.stdout.write(f'  DRF Responses: {overall["drf_responses"]}')
            self.stdout.write(f'  HTTP Responses: {overall["http_responses"]}')
            self.stdout.write(f'  Render Success Rate: {overall["render_success_rate"]:.1f}%')
            self.stdout.write(f'  Content Not Rendered Errors: {overall["content_not_rendered_count"]}')
            
            # Response type summary
            response_types = metrics['response_types']
            if response_types['total_responses'] > 0:
                self.stdout.write(f'\nResponse Types (Last {hours} hour{"s" if hours != 1 else ""}):')
                for resp_type, count in response_types['response_types'].items():
                    percentage = (count / response_types['total_responses']) * 100
                    self.stdout.write(f'  {resp_type}: {count} ({percentage:.1f}%)')
                
                # Render performance
                render_perf = response_types['render_performance']
                if render_perf:
                    self.stdout.write(f'\nRender Performance:')
                    self.stdout.write(f'  Average Render Time: {render_perf["avg_render_time"]:.3f}s')
                    self.stdout.write(f'  Slow Renders: {render_perf["slow_renders"]} ({render_perf["slow_render_rate"]:.1f}%)')
                    self.stdout.write(f'  Min/Max Render Time: {render_perf["min_render_time"]:.3f}s / {render_perf["max_render_time"]:.3f}s')
            
            # Template rendering summary
            template_metrics = metrics['template_rendering']
            if template_metrics['total_renders'] > 0:
                self.stdout.write(f'\nTemplate Rendering:')
                self.stdout.write(f'  Total Renders: {template_metrics["total_renders"]}')
                self.stdout.write(f'  Success Rate: {template_metrics["success_rate"]:.1f}%')
                self.stdout.write(f'  Failed Renders: {template_metrics["failed_renders"]}')
                
                template_perf = template_metrics['performance']
                self.stdout.write(f'  Average Render Time: {template_perf["avg_render_time"]:.3f}s')
                self.stdout.write(f'  Slow Renders: {template_perf["slow_renders"]} ({template_perf["slow_render_rate"]:.1f}%)')
            
            # Error summary
            errors = metrics['errors']
            if errors['total_errors'] > 0:
                self.stdout.write(f'\nErrors:')
                self.stdout.write(f'  Total Errors: {errors["total_errors"]}')
                self.stdout.write(f'  ContentNotRenderedErrors: {errors["content_not_rendered_errors"]}')
                self.stdout.write(f'  Error Rate: {errors["error_rate_per_hour"]:.1f} errors/hour')
                
                if errors['error_types']:
                    self.stdout.write(f'  Error Types:')
                    for error_type, count in errors['error_types'].items():
                        self.stdout.write(f'    {error_type}: {count}')
            
            # Show detailed error information if requested
            if show_errors and errors['total_errors'] > 0:
                self.stdout.write(f'\n=== Recent ContentNotRenderedErrors ===')
                cnr_errors = errors['cnr_error_details']
                for i, error in enumerate(cnr_errors[:5], 1):  # Show last 5
                    self.stdout.write(f'\n{i}. {error["timestamp"]}')
                    self.stdout.write(f'   Endpoint: {error["method"]} {error["endpoint"]}')
                    self.stdout.write(f'   Middleware: {error["middleware_name"]}')
                    if error.get('user_id'):
                        self.stdout.write(f'   User ID: {error["user_id"]}')
            
            # Show slow render details if requested
            if show_slow_renders:
                slow_renders = response_processing_monitor.get_slow_renders(limit=10)
                if slow_renders:
                    self.stdout.write(f'\n=== Slowest Renders ===')
                    for i, render in enumerate(slow_renders[:5], 1):  # Show top 5
                        self.stdout.write(f'\n{i}. {render["name"]} ({render["type"]})')
                        self.stdout.write(f'   Render Time: {render["render_time"]:.3f}s')
                        self.stdout.write(f'   Timestamp: {render["timestamp"]}')
                        if render["type"] == "response":
                            self.stdout.write(f'   Response Type: {render["response_type"]}')
                        elif render["type"] == "template":
                            self.stdout.write(f'   Success: {render["success"]}')
            
            # Health assessment
            self.stdout.write(f'\n=== Health Assessment ===')
            health_status = 'HEALTHY'
            issues = []
            
            if errors['content_not_rendered_errors'] > 0:
                health_status = 'CRITICAL'
                issues.append(f'ContentNotRenderedError occurrences: {errors["content_not_rendered_errors"]}')
            
            if response_types.get('render_performance', {}).get('slow_render_rate', 0) > 20:
                if health_status == 'HEALTHY':
                    health_status = 'WARNING'
                issues.append(f'High slow render rate: {response_types["render_performance"]["slow_render_rate"]:.1f}%')
            
            if template_metrics.get('success_rate', 100) < 95:
                if health_status == 'HEALTHY':
                    health_status = 'WARNING'
                issues.append(f'Low template render success rate: {template_metrics["success_rate"]:.1f}%')
            
            # Display health status with appropriate styling
            if health_status == 'HEALTHY':
                self.stdout.write(self.style.SUCCESS(f'Status: {health_status}'))
            elif health_status == 'WARNING':
                self.stdout.write(self.style.WARNING(f'Status: {health_status}'))
            else:
                self.stdout.write(self.style.ERROR(f'Status: {health_status}'))
            
            if issues:
                self.stdout.write('Issues:')
                for issue in issues:
                    self.stdout.write(f'  - {issue}')
            
            # Clear old metrics if requested
            if clear_old:
                response_processing_monitor.clear_old_metrics()
                self.stdout.write(self.style.SUCCESS('\nOld metrics cleared successfully.'))
            
            self.stdout.write('')  # Empty line at end
            
        except Exception as e:
            raise CommandError(f'Error checking response processing metrics: {str(e)}')

    def format_duration(self, seconds):
        """Format duration in a human-readable way"""
        if seconds < 1:
            return f'{seconds*1000:.0f}ms'
        elif seconds < 60:
            return f'{seconds:.1f}s'
        else:
            minutes = int(seconds // 60)
            remaining_seconds = seconds % 60
            return f'{minutes}m {remaining_seconds:.1f}s'