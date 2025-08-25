"""
Database Index Analysis Management Command - Task 4.2.1

Django management command for analyzing missing database indexes
and creating optimal indexes for query performance.
"""

from django.core.management.base import BaseCommand, CommandError
from django.db import connection
from core.performance.database_index_analyzer import (
    database_index_analyzer,
    analyze_missing_indexes,
    generate_index_creation_sql,
    export_index_report
)
import time
import json
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """
    Database index analysis and optimization command
    Task 4.2.1: Index analysis automation
    """
    
    help = 'Analyze database indexes and create missing indexes for optimal performance'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--action',
            choices=['analyze', 'create', 'export', 'status'],
            default='analyze',
            help='Action to perform (default: analyze)'
        )
        
        parser.add_argument(
            '--priority',
            choices=['high', 'medium', 'low', 'all'],
            default='all',
            help='Priority level of indexes to create (default: all)'
        )
        
        parser.add_argument(
            '--table',
            type=str,
            help='Specific table to analyze (optional)'
        )
        
        parser.add_argument(
            '--export-file',
            type=str,
            help='File path to export analysis report'
        )
        
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show SQL commands without executing them'
        )
        
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force creation of indexes without confirmation'
        )
        
        parser.add_argument(
            '--concurrent',
            action='store_true',
            default=True,
            help='Use CONCURRENTLY for index creation (default: True)'
        )
        
        parser.add_argument(
            '--show-existing',
            action='store_true',
            help='Show existing indexes for comparison'
        )
    
    def handle(self, *args, **options):
        try:
            action = options['action']
            
            self.stdout.write(
                self.style.SUCCESS(f'📊 Starting database index analysis - Action: {action.upper()}')
            )
            
            if action == 'analyze':
                self._analyze_indexes(options)
            elif action == 'create':
                self._create_indexes(options)
            elif action == 'export':
                self._export_analysis(options)
            elif action == 'status':
                self._show_index_status(options)
            
            self.stdout.write(
                self.style.SUCCESS('✅ Database index operation completed successfully!')
            )
            
        except Exception as e:
            logger.error(f"Error in database index command: {e}")
            raise CommandError(f'Database index operation failed: {str(e)}')
    
    def _analyze_indexes(self, options):
        """Analyze missing database indexes"""
        
        self.stdout.write("Analyzing database indexes...")
        
        start_time = time.time()
        recommendations = analyze_missing_indexes()
        analysis_time = time.time() - start_time
        
        if not recommendations:
            self.stdout.write(self.style.SUCCESS("✅ No missing indexes found - database is well optimized!"))
            return
        
        # Group by priority
        high_priority = [r for r in recommendations if r.impact == 'high']
        medium_priority = [r for r in recommendations if r.impact == 'medium']
        low_priority = [r for r in recommendations if r.impact == 'low']
        
        self.stdout.write(f"\n📋 Index Analysis Results ({analysis_time:.2f}s)")
        self.stdout.write('=' * 60)
        
        self.stdout.write(f"Total Recommendations: {len(recommendations)}")
        self.stdout.write(f"  High Priority: {len(high_priority)}")
        self.stdout.write(f"  Medium Priority: {len(medium_priority)}")
        self.stdout.write(f"  Low Priority: {len(low_priority)}")
        
        # Show high priority recommendations in detail
        if high_priority:
            self.stdout.write(f"\n🔥 High Priority Recommendations:")
            for rec in high_priority:
                columns_str = ', '.join(rec.columns)
                rows_info = f" ({rec.estimated_rows:,} rows)" if rec.estimated_rows > 0 else ""
                
                self.stdout.write(f"  📌 {rec.table_name}.{columns_str}{rows_info}")
                self.stdout.write(f"     Reason: {rec.reason}")
                self.stdout.write(f"     Pattern: {rec.query_pattern}")
                
                if rec.existing_indexes:
                    self.stdout.write(f"     Existing: {', '.join(rec.existing_indexes[:3])}")
                self.stdout.write("")
        
        # Show medium priority summary
        if medium_priority:
            self.stdout.write(f"\n⚡ Medium Priority Recommendations:")
            for rec in medium_priority[:5]:  # Show first 5
                columns_str = ', '.join(rec.columns)
                self.stdout.write(f"  • {rec.table_name}.{columns_str} - {rec.reason}")
            
            if len(medium_priority) > 5:
                self.stdout.write(f"  ... and {len(medium_priority) - 5} more")
        
        # Show creation commands
        if not options.get('dry_run'):
            self.stdout.write(f"\n💡 Next Steps:")
            self.stdout.write("  1. Review recommendations above")
            self.stdout.write("  2. Run with --action=create --priority=high to create high priority indexes")
            self.stdout.write("  3. Monitor query performance after index creation")
            self.stdout.write("  4. Use --export-file to save detailed analysis")
    
    def _create_indexes(self, options):
        """Create recommended database indexes"""
        
        priority = options['priority']
        dry_run = options['dry_run']
        force = options['force']
        concurrent = options['concurrent']
        
        self.stdout.write(f"Creating {priority} priority indexes...")
        
        if dry_run:
            self.stdout.write(self.style.WARNING("DRY RUN MODE - No indexes will be created"))
        
        # Get recommendations and SQL
        recommendations = analyze_missing_indexes()
        sql_statements = generate_index_creation_sql()
        
        # Filter by priority
        if priority == 'all':
            statements_to_execute = (
                sql_statements['high_priority'] + 
                sql_statements['medium_priority'] + 
                sql_statements['low_priority']
            )
            priority_filter = lambda r: True
        else:
            statements_to_execute = sql_statements[f'{priority}_priority']
            priority_filter = lambda r: r.impact == priority
        
        filtered_recommendations = [r for r in recommendations if priority_filter(r)]
        
        if not statements_to_execute:
            self.stdout.write(self.style.SUCCESS(f"✅ No {priority} priority indexes to create"))
            return
        
        self.stdout.write(f"\nFound {len(statements_to_execute)} indexes to create:")
        
        # Show what will be created
        for i, (sql, rec) in enumerate(zip(statements_to_execute, filtered_recommendations)):
            columns_str = ', '.join(rec.columns)
            rows_info = f" ({rec.estimated_rows:,} rows)" if rec.estimated_rows > 0 else ""
            
            self.stdout.write(f"  {i+1}. {rec.table_name}.{columns_str}{rows_info}")
            if dry_run:
                self.stdout.write(f"     SQL: {sql}")
        
        if dry_run:
            return
        
        # Confirm creation unless force is used
        if not force and len(statements_to_execute) > 0:
            confirm = input(f"\nCreate {len(statements_to_execute)} indexes? This may take several minutes (y/N): ")
            if confirm.lower() not in ['y', 'yes']:
                self.stdout.write("Index creation cancelled")
                return
        
        # Create indexes
        self.stdout.write(f"\n🔨 Creating indexes...")
        
        created_count = 0
        failed_count = 0
        
        for i, (sql, rec) in enumerate(zip(statements_to_execute, filtered_recommendations)):
            columns_str = ', '.join(rec.columns)
            
            try:
                self.stdout.write(f"  Creating index {i+1}/{len(statements_to_execute)}: {rec.table_name}.{columns_str}")
                
                start_time = time.time()
                
                with connection.cursor() as cursor:
                    cursor.execute(sql)
                
                creation_time = time.time() - start_time
                self.stdout.write(f"    ✅ Created in {creation_time:.2f}s")
                
                created_count += 1
                
            except Exception as e:
                self.stdout.write(f"    ❌ Failed: {str(e)}")
                failed_count += 1
                logger.error(f"Failed to create index for {rec.table_name}.{columns_str}: {e}")
        
        # Summary
        self.stdout.write(f"\n📊 Index Creation Summary:")
        self.stdout.write(f"  Created: {created_count}")
        self.stdout.write(f"  Failed: {failed_count}")
        self.stdout.write(f"  Total: {len(statements_to_execute)}")
        
        if created_count > 0:
            self.stdout.write(f"\n💡 Recommendations:")
            self.stdout.write("  - Monitor query performance improvements")
            self.stdout.write("  - Run ANALYZE on affected tables")
            self.stdout.write("  - Check for any application impact")
    
    def _export_analysis(self, options):
        """Export detailed index analysis"""
        
        export_file = options.get('export_file')
        if not export_file:
            # Generate default filename
            from django.utils import timezone
            timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
            export_file = f'database_index_analysis_{timestamp}.json'
        
        self.stdout.write(f"Exporting index analysis to {export_file}...")
        
        try:
            report = export_index_report(export_file)
            
            # Show summary
            summary = report['summary']
            self.stdout.write(f"\n📊 Analysis Summary:")
            self.stdout.write(f"  Total Recommendations: {summary['total_recommendations']}")
            self.stdout.write(f"  High Priority: {summary['high_priority']}")
            self.stdout.write(f"  Medium Priority: {summary['medium_priority']}")
            self.stdout.write(f"  Low Priority: {summary['low_priority']}")
            self.stdout.write(f"  Composite Indexes: {summary['composite_indexes']}")
            
            self.stdout.write(f"\n✅ Analysis exported to: {export_file}")
            
            # Show top recommendations
            recommendations = report['recommendations']
            high_priority_recs = [r for r in recommendations if r['impact'] == 'high']
            
            if high_priority_recs:
                self.stdout.write(f"\n🔥 Top High Priority Recommendations:")
                for rec in high_priority_recs[:5]:
                    columns_str = ', '.join(rec['columns'])
                    self.stdout.write(f"  • {rec['table_name']}.{columns_str}")
                    self.stdout.write(f"    {rec['reason']}")
            
        except Exception as e:
            raise CommandError(f"Failed to export analysis: {str(e)}")
    
    def _show_index_status(self, options):
        """Show current database index status"""
        
        show_existing = options['show_existing']
        
        self.stdout.write("Loading database index status...")
        
        # Load existing indexes and table stats
        database_index_analyzer._load_existing_indexes()
        database_index_analyzer._load_table_statistics()
        
        existing_indexes = database_index_analyzer.existing_indexes
        table_stats = database_index_analyzer.table_stats
        
        self.stdout.write(f"\n📊 Database Index Status")
        self.stdout.write('=' * 50)
        
        # Overall statistics
        total_tables = len(table_stats)
        total_indexes = sum(len(indexes) for indexes in existing_indexes.values())
        total_rows = sum(stats.get('total_rows', 0) for stats in table_stats.values())
        
        self.stdout.write(f"Total Tables: {total_tables}")
        self.stdout.write(f"Total Indexes: {total_indexes}")
        self.stdout.write(f"Total Rows: {total_rows:,}")
        
        # Largest tables
        if table_stats:
            self.stdout.write(f"\n📈 Largest Tables:")
            sorted_tables = sorted(table_stats.items(), 
                                 key=lambda x: x[1].get('total_rows', 0), 
                                 reverse=True)
            
            for table, stats in sorted_tables[:10]:
                total_rows = stats.get('total_rows', 0)
                index_count = len(existing_indexes.get(table, []))
                write_ratio = stats.get('write_ratio', 0)
                
                activity = "High" if write_ratio > 1.0 else "Medium" if write_ratio > 0.1 else "Low"
                
                self.stdout.write(
                    f"  {table:30} {total_rows:>10,} rows  "
                    f"{index_count:>2} indexes  Activity: {activity}"
                )
        
        # Show existing indexes if requested
        if show_existing:
            self.stdout.write(f"\n🔍 Existing Indexes by Table:")
            
            for table in sorted(existing_indexes.keys()):
                indexes = existing_indexes[table]
                if not indexes:
                    continue
                
                self.stdout.write(f"\n  {table}:")
                for idx in indexes:
                    columns = ', '.join(idx['columns']) if idx['columns'] else 'unknown'
                    self.stdout.write(f"    • {idx['name']}: ({columns})")
        
        # Performance recommendations
        self.stdout.write(f"\n💡 Quick Analysis:")
        
        # Tables with no indexes (excluding primary keys)
        unindexed_tables = []
        for table, indexes in existing_indexes.items():
            # Count non-primary key indexes
            non_pk_indexes = [idx for idx in indexes if not idx['name'].endswith('_pkey')]
            if len(non_pk_indexes) == 0:
                stats = table_stats.get(table, {})
                if stats.get('total_rows', 0) > 1000:  # Only consider tables with significant data
                    unindexed_tables.append(table)
        
        if unindexed_tables:
            self.stdout.write(f"  ⚠️  Tables with minimal indexing: {len(unindexed_tables)}")
            for table in unindexed_tables[:5]:
                rows = table_stats.get(table, {}).get('total_rows', 0)
                self.stdout.write(f"    • {table} ({rows:,} rows)")
        
        # High-activity tables that might need index optimization
        high_activity_tables = []
        for table, stats in table_stats.items():
            if stats.get('write_ratio', 0) > 1.0 and stats.get('total_rows', 0) > 10000:
                high_activity_tables.append(table)
        
        if high_activity_tables:
            self.stdout.write(f"  📊 High-activity large tables: {len(high_activity_tables)}")
            self.stdout.write("    Consider monitoring index performance on these tables")
        
        self.stdout.write(f"\n🔬 For detailed analysis, run: --action=analyze")
        self.stdout.write(f"📁 For exportable report, run: --action=export")
