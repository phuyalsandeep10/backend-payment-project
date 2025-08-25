"""
Cache Invalidation Optimization Command - Task 4.1.2

Django management command to optimize cache invalidation performance
and tune batch sizes for large organizations.
"""

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from core.performance.cache_invalidation_optimizer import (
    cache_invalidation_manager,
    SmartCacheInvalidation
)
from core.performance.cache_invalidation_monitor import (
    _calculate_efficiency_metrics,
    _generate_invalidation_recommendations
)
import time
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """
    Optimize cache invalidation performance
    Task 4.1.2: Invalidation optimization automation
    """
    
    help = 'Optimize cache invalidation performance and batch sizes'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--organization-id',
            type=int,
            help='Optimize for specific organization'
        )
        
        parser.add_argument(
            '--batch-size',
            type=int,
            default=200,
            help='Optimal batch size to set (default: 200)'
        )
        
        parser.add_argument(
            '--test-performance',
            action='store_true',
            help='Run performance tests to determine optimal settings'
        )
        
        parser.add_argument(
            '--clear-queues',
            action='store_true',
            help='Clear all invalidation queues before optimization'
        )
        
        parser.add_argument(
            '--benchmark-batch-sizes',
            action='store_true',
            help='Benchmark different batch sizes to find optimal values'
        )
        
        parser.add_argument(
            '--show-analytics',
            action='store_true',
            help='Show current invalidation analytics'
        )
    
    def handle(self, *args, **options):
        try:
            self.stdout.write(
                self.style.SUCCESS('🔧 Starting cache invalidation optimization - Task 4.1.2')
            )
            
            # Show current analytics if requested
            if options['show_analytics']:
                self._show_current_analytics()
            
            # Clear queues if requested
            if options['clear_queues']:
                self._clear_queues()
            
            # Run performance tests
            if options['test_performance']:
                self._test_invalidation_performance()
            
            # Benchmark batch sizes
            if options['benchmark_batch_sizes']:
                optimal_batch_size = self._benchmark_batch_sizes(options['organization_id'])
                if optimal_batch_size:
                    options['batch_size'] = optimal_batch_size
            
            # Optimize organization settings
            if options['organization_id']:
                self._optimize_organization(options['organization_id'], options['batch_size'])
            else:
                self._optimize_global_settings(options['batch_size'])
            
            # Final recommendations
            self._show_optimization_results()
            
            self.stdout.write(
                self.style.SUCCESS('✅ Cache invalidation optimization completed successfully!')
            )
            
        except Exception as e:
            logger.error(f"Error optimizing cache invalidation: {e}")
            raise CommandError(f'Failed to optimize cache invalidation: {str(e)}')
    
    def _show_current_analytics(self):
        """Show current invalidation analytics"""
        
        self.stdout.write(self.style.SUCCESS('\n📊 Current Invalidation Analytics'))
        self.stdout.write('=' * 60)
        
        metrics = cache_invalidation_manager.get_invalidation_metrics()
        queue_status = cache_invalidation_manager.get_queue_status()
        
        # Basic metrics
        self.stdout.write(f"Total Invalidations: {metrics.total_invalidations:,}")
        self.stdout.write(f"Batch Invalidations: {metrics.batch_invalidations:,}")
        self.stdout.write(f"Individual Invalidations: {metrics.individual_invalidations:,}")
        self.stdout.write(f"Failed Invalidations: {metrics.failed_invalidations:,}")
        self.stdout.write(f"Total Keys Invalidated: {metrics.total_keys_invalidated:,}")
        
        # Efficiency metrics
        efficiency = _calculate_efficiency_metrics(metrics)
        self.stdout.write(f"\nEfficiency Metrics:")
        self.stdout.write(f"  Success Rate: {efficiency['success_rate']:.1f}%")
        self.stdout.write(f"  Batch Efficiency: {efficiency['batch_efficiency']:.1f}%")
        self.stdout.write(f"  Time Efficiency: {efficiency['time_efficiency']:.1f}%")
        self.stdout.write(f"  Overall Efficiency: {efficiency['overall_efficiency']:.1f}%")
        
        # Queue status
        self.stdout.write(f"\nQueue Status:")
        self.stdout.write(f"  High Priority: {queue_status['high_priority']:,}")
        self.stdout.write(f"  Medium Priority: {queue_status['medium_priority']:,}")
        self.stdout.write(f"  Low Priority: {queue_status['low_priority']:,}")
        self.stdout.write(f"  Total Queued: {queue_status['total_queued']:,}")
        
        # Recommendations
        recommendations = _generate_invalidation_recommendations(metrics, queue_status)
        if recommendations:
            self.stdout.write(f"\n💡 Recommendations:")
            for rec in recommendations:
                self.stdout.write(f"  - {rec}")
        
        self.stdout.write('=' * 60)
    
    def _clear_queues(self):
        """Clear invalidation queues"""
        
        self.stdout.write("Clearing invalidation queues...")
        queue_status_before = cache_invalidation_manager.get_queue_status()
        
        cache_invalidation_manager.clear_queues()
        
        self.stdout.write(
            f"Cleared {queue_status_before['total_queued']:,} queued invalidations"
        )
    
    def _test_invalidation_performance(self):
        """Test invalidation performance with different approaches"""
        
        self.stdout.write("Testing invalidation performance...")
        
        # Test individual vs batch performance
        test_keys = [f"test_key_{i}" for i in range(100)]
        
        # Test individual invalidations
        start_time = time.time()
        for key in test_keys:
            cache_invalidation_manager.invalidate_immediate(keys=[key])
        individual_time = time.time() - start_time
        
        # Test batch invalidation
        start_time = time.time()
        result = cache_invalidation_manager.invalidate_immediate(keys=test_keys)
        batch_time = time.time() - start_time
        
        # Results
        self.stdout.write(f"\nPerformance Test Results:")
        self.stdout.write(f"  Individual Invalidations (100 keys): {individual_time:.3f}s")
        self.stdout.write(f"  Batch Invalidation (100 keys): {batch_time:.3f}s")
        
        if individual_time > 0:
            improvement = ((individual_time - batch_time) / individual_time) * 100
            self.stdout.write(f"  Performance Improvement: {improvement:.1f}%")
        
        return batch_time < individual_time
    
    def _benchmark_batch_sizes(self, organization_id: Optional[int]) -> Optional[int]:
        """Benchmark different batch sizes to find optimal value"""
        
        self.stdout.write("Benchmarking batch sizes...")
        
        test_keys = [f"benchmark_key_{i}" for i in range(1000)]
        batch_sizes = [50, 100, 200, 500, 1000]
        results = {}
        
        for batch_size in batch_sizes:
            self.stdout.write(f"  Testing batch size: {batch_size}")
            
            # Test multiple runs for accuracy
            times = []
            for run in range(3):
                start_time = time.time()
                
                # Simulate batch invalidation
                for i in range(0, len(test_keys), batch_size):
                    batch_keys = test_keys[i:i + batch_size]
                    cache_invalidation_manager.invalidate_immediate(keys=batch_keys)
                
                times.append(time.time() - start_time)
            
            avg_time = sum(times) / len(times)
            results[batch_size] = avg_time
            
            self.stdout.write(f"    Average time: {avg_time:.3f}s")
        
        # Find optimal batch size
        optimal_batch_size = min(results, key=results.get)
        optimal_time = results[optimal_batch_size]
        
        self.stdout.write(f"\nBenchmark Results:")
        for batch_size, time_taken in sorted(results.items()):
            marker = " ← OPTIMAL" if batch_size == optimal_batch_size else ""
            self.stdout.write(f"  Batch size {batch_size}: {time_taken:.3f}s{marker}")
        
        self.stdout.write(f"\nRecommended batch size: {optimal_batch_size}")
        
        return optimal_batch_size
    
    def _optimize_organization(self, organization_id: int, batch_size: int):
        """Optimize invalidation settings for specific organization"""
        
        self.stdout.write(f"Optimizing invalidation for organization {organization_id}...")
        
        # Set organization-specific batch size
        cache_invalidation_manager.optimize_organization_settings(
            organization_id, batch_size
        )
        
        self.stdout.write(f"Set batch size to {batch_size} for organization {organization_id}")
        
        # Test organization-specific invalidation
        test_result = cache_invalidation_manager.invalidate_organization_cache(
            organization_id, selective=True
        )
        
        if test_result['success']:
            self.stdout.write(
                f"Test invalidation completed: {test_result['keys_invalidated']} keys "
                f"in {test_result['execution_time']:.3f}s"
            )
        else:
            self.stdout.write(
                self.style.WARNING(f"Test invalidation failed: {test_result['error']}")
            )
    
    def _optimize_global_settings(self, batch_size: int):
        """Optimize global invalidation settings"""
        
        self.stdout.write("Optimizing global invalidation settings...")
        
        # Update manager settings
        old_batch_size = cache_invalidation_manager.max_batch_size
        cache_invalidation_manager.max_batch_size = batch_size
        
        self.stdout.write(f"Updated global max batch size: {old_batch_size} → {batch_size}")
        
        # Optimize batch delay
        old_delay = cache_invalidation_manager.batch_delay
        
        # Calculate optimal delay based on batch size
        # Larger batches need slightly more delay to prevent overwhelming cache
        optimal_delay = min(0.05 + (batch_size / 10000), 0.5)  # 50ms to 500ms
        cache_invalidation_manager.batch_delay = optimal_delay
        
        self.stdout.write(f"Updated batch delay: {old_delay:.3f}s → {optimal_delay:.3f}s")
    
    def _show_optimization_results(self):
        """Show optimization results and recommendations"""
        
        self.stdout.write(self.style.SUCCESS('\n🎯 Optimization Results'))
        self.stdout.write('=' * 50)
        
        metrics = cache_invalidation_manager.get_invalidation_metrics()
        queue_status = cache_invalidation_manager.get_queue_status()
        
        # Current efficiency
        efficiency = _calculate_efficiency_metrics(metrics)
        overall_score = efficiency['overall_efficiency']
        
        if overall_score >= 80:
            status = self.style.SUCCESS(f"EXCELLENT ({overall_score:.1f}%)")
        elif overall_score >= 60:
            status = self.style.WARNING(f"GOOD ({overall_score:.1f}%)")
        else:
            status = self.style.ERROR(f"NEEDS IMPROVEMENT ({overall_score:.1f}%)")
        
        self.stdout.write(f"Overall Efficiency Score: {status}")
        
        # Configuration summary
        self.stdout.write(f"\nCurrent Configuration:")
        self.stdout.write(f"  Max Batch Size: {cache_invalidation_manager.max_batch_size:,}")
        self.stdout.write(f"  Batch Delay: {cache_invalidation_manager.batch_delay:.3f}s")
        self.stdout.write(f"  Queue Size Limit: {cache_invalidation_manager.max_queue_size:,}")
        
        # Organization-specific settings
        if cache_invalidation_manager.organization_batch_sizes:
            self.stdout.write(f"\nOrganization-Specific Batch Sizes:")
            for org_id, batch_size in cache_invalidation_manager.organization_batch_sizes.items():
                self.stdout.write(f"  Organization {org_id}: {batch_size:,}")
        
        # Performance tips
        self.stdout.write(f"\n💡 Performance Tips:")
        self.stdout.write("  - Use batch invalidation for multiple keys")
        self.stdout.write("  - Schedule low-priority invalidations during off-peak hours")
        self.stdout.write("  - Monitor queue levels to prevent bottlenecks")
        self.stdout.write("  - Use selective organization invalidation when possible")
        
        # Monitoring recommendations
        self.stdout.write(f"\n📊 Monitoring Recommendations:")
        self.stdout.write("  - Check invalidation analytics regularly")
        self.stdout.write("  - Monitor queue health status")
        self.stdout.write("  - Set up alerts for high failure rates")
        self.stdout.write("  - Review batch sizes quarterly")
        
        self.stdout.write('=' * 50)
