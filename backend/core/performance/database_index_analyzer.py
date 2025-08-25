"""
Database Index Analyzer - Task 4.2.1

Analyzes query patterns, identifies missing indexes, and provides
recommendations for optimal database performance.
"""

import logging
import time
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from django.db import connection, models
from django.db.models import Q, Count, Max, Min
from django.utils import timezone
from django.apps import apps
import re
import json

logger = logging.getLogger(__name__)


@dataclass
class IndexRecommendation:
    """Database index recommendation"""
    table_name: str
    columns: List[str]
    index_type: str = 'BTREE'  # BTREE, HASH, GIN, GIST
    reason: str = ""
    impact: str = "medium"  # high, medium, low
    query_pattern: str = ""
    estimated_rows: int = 0
    frequency: int = 0
    is_composite: bool = False
    existing_indexes: List[str] = field(default_factory=list)


@dataclass
class QueryAnalysis:
    """Query analysis result"""
    query_hash: str
    query_pattern: str
    table_names: List[str]
    where_columns: List[str]
    order_columns: List[str] 
    join_columns: List[str]
    execution_count: int = 0
    avg_execution_time: float = 0.0
    last_seen: datetime = field(default_factory=timezone.now)


class DatabaseIndexAnalyzer:
    """
    Comprehensive database index analysis system
    Task 4.2.1: Core index analysis functionality
    """
    
    def __init__(self):
        self.query_patterns = defaultdict(QueryAnalysis)
        self.existing_indexes = {}
        self.table_stats = {}
        
        # Analysis configuration
        self.min_query_frequency = 5  # Minimum frequency to consider for indexing
        self.slow_query_threshold = 0.1  # 100ms threshold for slow queries
        
        # Common PRS system query patterns
        self.common_patterns = {
            'organization_scoped': [
                'organization_id',
                'organization_id, created_at',
                'organization_id, status',
                'organization_id, is_active'
            ],
            'user_related': [
                'created_by_id',
                'created_by_id, created_at',
                'user_id',
                'user_id, organization_id'
            ],
            'temporal': [
                'created_at',
                'updated_at',
                'created_at DESC',
                'updated_at DESC'
            ],
            'status_based': [
                'status',
                'is_active',
                'payment_status',
                'approval_status'
            ]
        }
    
    def analyze_missing_indexes(self) -> List[IndexRecommendation]:
        """
        Analyze and recommend missing database indexes
        Task 4.2.1: Missing index identification
        """
        
        logger.info("Starting database index analysis...")
        
        recommendations = []
        
        # Get existing indexes
        self._load_existing_indexes()
        
        # Get table statistics
        self._load_table_statistics()
        
        # Analyze models for potential indexes
        recommendations.extend(self._analyze_model_indexes())
        
        # Analyze query patterns (if available)
        recommendations.extend(self._analyze_query_patterns())
        
        # Analyze organization-scoped queries
        recommendations.extend(self._analyze_organization_indexes())
        
        # Sort recommendations by impact
        recommendations.sort(key=lambda r: {'high': 3, 'medium': 2, 'low': 1}[r.impact], reverse=True)
        
        logger.info(f"Generated {len(recommendations)} index recommendations")
        return recommendations
    
    def _load_existing_indexes(self):
        """Load existing database indexes"""
        
        try:
            with connection.cursor() as cursor:
                # PostgreSQL query to get all indexes
                cursor.execute("""
                    SELECT 
                        schemaname,
                        tablename,
                        indexname,
                        indexdef
                    FROM pg_indexes 
                    WHERE schemaname = 'public'
                    ORDER BY tablename, indexname
                """)
                
                for schema, table, index_name, index_def in cursor.fetchall():
                    if table not in self.existing_indexes:
                        self.existing_indexes[table] = []
                    
                    self.existing_indexes[table].append({
                        'name': index_name,
                        'definition': index_def,
                        'columns': self._extract_columns_from_index_def(index_def)
                    })
                    
        except Exception as e:
            logger.error(f"Error loading existing indexes: {e}")
            self.existing_indexes = {}
    
    def _load_table_statistics(self):
        """Load table statistics for better recommendations"""
        
        try:
            with connection.cursor() as cursor:
                # Get table row counts and sizes
                cursor.execute("""
                    SELECT 
                        schemaname,
                        tablename,
                        n_tup_ins as inserts,
                        n_tup_upd as updates,
                        n_tup_del as deletes,
                        n_live_tup as live_rows,
                        n_dead_tup as dead_rows
                    FROM pg_stat_user_tables
                    WHERE schemaname = 'public'
                    ORDER BY n_live_tup DESC
                """)
                
                for schema, table, inserts, updates, deletes, live_rows, dead_rows in cursor.fetchall():
                    self.table_stats[table] = {
                        'inserts': inserts or 0,
                        'updates': updates or 0,
                        'deletes': deletes or 0,
                        'live_rows': live_rows or 0,
                        'dead_rows': dead_rows or 0,
                        'total_rows': (live_rows or 0) + (dead_rows or 0),
                        'write_ratio': (inserts + updates + deletes) / max(live_rows or 1, 1)
                    }
                    
        except Exception as e:
            logger.error(f"Error loading table statistics: {e}")
            self.table_stats = {}
    
    def _analyze_model_indexes(self) -> List[IndexRecommendation]:
        """Analyze Django models for missing indexes"""
        
        recommendations = []
        
        # Get all Django models
        for model in apps.get_models():
            table_name = model._meta.db_table
            
            if not table_name or table_name.startswith('django_') or table_name.startswith('auth_'):
                continue  # Skip system tables
            
            # Analyze foreign keys
            recommendations.extend(self._analyze_foreign_key_indexes(model, table_name))
            
            # Analyze common query patterns
            recommendations.extend(self._analyze_common_pattern_indexes(model, table_name))
            
            # Analyze unique constraints
            recommendations.extend(self._analyze_unique_constraint_indexes(model, table_name))
            
            # Analyze composite indexes
            recommendations.extend(self._analyze_composite_indexes(model, table_name))
        
        return recommendations
    
    def _analyze_foreign_key_indexes(self, model: models.Model, table_name: str) -> List[IndexRecommendation]:
        """Analyze foreign key indexes"""
        
        recommendations = []
        
        for field in model._meta.get_fields():
            if isinstance(field, models.ForeignKey):
                column_name = f"{field.name}_id"
                
                # Check if index exists
                if not self._has_index(table_name, [column_name]):
                    
                    # Get table stats for impact assessment
                    stats = self.table_stats.get(table_name, {})
                    impact = self._assess_impact(stats.get('total_rows', 0), 'foreign_key')
                    
                    recommendations.append(IndexRecommendation(
                        table_name=table_name,
                        columns=[column_name],
                        reason=f"Foreign key {field.name} frequently used in joins",
                        impact=impact,
                        query_pattern="JOIN and WHERE clauses",
                        estimated_rows=stats.get('total_rows', 0),
                        existing_indexes=self._get_existing_index_names(table_name)
                    ))
        
        return recommendations
    
    def _analyze_common_pattern_indexes(self, model: models.Model, table_name: str) -> List[IndexRecommendation]:
        """Analyze indexes for common query patterns"""
        
        recommendations = []
        model_fields = {f.name: f for f in model._meta.get_fields()}
        
        # Organization-scoped queries
        if 'organization' in model_fields or 'organization_id' in model_fields:
            org_column = 'organization_id'
            
            if not self._has_index(table_name, [org_column]):
                stats = self.table_stats.get(table_name, {})
                
                recommendations.append(IndexRecommendation(
                    table_name=table_name,
                    columns=[org_column],
                    reason="Organization-scoped queries are very common in PRS system",
                    impact="high",
                    query_pattern="WHERE organization_id = ?",
                    estimated_rows=stats.get('total_rows', 0),
                    frequency=100,  # High frequency assumption
                    existing_indexes=self._get_existing_index_names(table_name)
                ))
            
            # Combined organization + temporal indexes
            for time_field in ['created_at', 'updated_at']:
                if time_field in model_fields:
                    composite_columns = [org_column, time_field]
                    
                    if not self._has_index(table_name, composite_columns):
                        recommendations.append(IndexRecommendation(
                            table_name=table_name,
                            columns=composite_columns,
                            reason=f"Organization filtering with {time_field} ordering",
                            impact="high",
                            query_pattern=f"WHERE organization_id = ? ORDER BY {time_field}",
                            is_composite=True,
                            existing_indexes=self._get_existing_index_names(table_name)
                        ))
        
        # User-related queries
        for user_field in ['created_by', 'user', 'assigned_to']:
            if user_field in model_fields:
                user_column = f"{user_field}_id"
                
                if not self._has_index(table_name, [user_column]):
                    recommendations.append(IndexRecommendation(
                        table_name=table_name,
                        columns=[user_column],
                        reason=f"User filtering on {user_field} field",
                        impact="medium",
                        query_pattern=f"WHERE {user_column} = ?",
                        existing_indexes=self._get_existing_index_names(table_name)
                    ))
        
        # Status-based queries
        for status_field in ['status', 'is_active', 'payment_status', 'approval_status']:
            if status_field in model_fields:
                
                if not self._has_index(table_name, [status_field]):
                    # Status fields usually have low cardinality
                    field_type = type(model_fields[status_field])
                    
                    if field_type in [models.BooleanField]:
                        impact = "low"  # Boolean fields have very low cardinality
                    else:
                        impact = "medium"
                    
                    recommendations.append(IndexRecommendation(
                        table_name=table_name,
                        columns=[status_field],
                        reason=f"Status filtering on {status_field}",
                        impact=impact,
                        query_pattern=f"WHERE {status_field} = ?",
                        existing_indexes=self._get_existing_index_names(table_name)
                    ))
        
        # Temporal queries
        for time_field in ['created_at', 'updated_at']:
            if time_field in model_fields:
                
                if not self._has_index(table_name, [time_field]):
                    recommendations.append(IndexRecommendation(
                        table_name=table_name,
                        columns=[time_field],
                        reason=f"Date range queries and ordering by {time_field}",
                        impact="medium",
                        query_pattern=f"WHERE {time_field} >= ? ORDER BY {time_field}",
                        existing_indexes=self._get_existing_index_names(table_name)
                    ))
        
        return recommendations
    
    def _analyze_unique_constraint_indexes(self, model: models.Model, table_name: str) -> List[IndexRecommendation]:
        """Analyze indexes for unique constraints"""
        
        recommendations = []
        
        for field in model._meta.get_fields():
            if hasattr(field, 'unique') and field.unique and not field.primary_key:
                column_name = field.name
                
                if not self._has_index(table_name, [column_name]):
                    recommendations.append(IndexRecommendation(
                        table_name=table_name,
                        columns=[column_name],
                        reason=f"Unique constraint on {column_name}",
                        impact="medium",
                        query_pattern=f"WHERE {column_name} = ? (unique lookup)",
                        existing_indexes=self._get_existing_index_names(table_name)
                    ))
        
        return recommendations
    
    def _analyze_composite_indexes(self, model: models.Model, table_name: str) -> List[IndexRecommendation]:
        """Analyze potential composite indexes"""
        
        recommendations = []
        model_fields = {f.name: f for f in model._meta.get_fields()}
        
        # Common composite patterns for PRS system
        composite_patterns = [
            # Deal-specific patterns
            (['organization_id', 'client_id'], "Organization and client filtering"),
            (['organization_id', 'payment_status'], "Organization deals by payment status"),
            (['client_id', 'created_at'], "Client deals chronological"),
            (['created_by_id', 'created_at'], "User activity chronological"),
            
            # General patterns
            (['organization_id', 'is_active'], "Active records by organization"),
            (['organization_id', 'status'], "Status filtering by organization"),
        ]
        
        for columns, reason in composite_patterns:
            # Check if all columns exist in the model
            actual_columns = []
            for col in columns:
                if col in model_fields:
                    actual_columns.append(col)
                elif col.endswith('_id') and col[:-3] in model_fields:
                    actual_columns.append(col)
            
            if len(actual_columns) == len(columns):
                if not self._has_index(table_name, actual_columns):
                    stats = self.table_stats.get(table_name, {})
                    
                    recommendations.append(IndexRecommendation(
                        table_name=table_name,
                        columns=actual_columns,
                        reason=reason,
                        impact=self._assess_impact(stats.get('total_rows', 0), 'composite'),
                        query_pattern=f"WHERE {' = ? AND '.join(actual_columns)} = ?",
                        is_composite=True,
                        existing_indexes=self._get_existing_index_names(table_name)
                    ))
        
        return recommendations
    
    def _analyze_query_patterns(self) -> List[IndexRecommendation]:
        """Analyze actual query patterns (if captured)"""
        
        # This would analyze captured query logs
        # For now, return empty list as query logging needs to be implemented
        return []
    
    def _analyze_organization_indexes(self) -> List[IndexRecommendation]:
        """Analyze organization-scoped query optimizations"""
        
        recommendations = []
        
        # Focus on tables that likely have organization_id
        org_tables = ['deals_deal', 'clients_client', 'authentication_user', 'notifications_notification']
        
        for table in org_tables:
            if table in self.existing_indexes:
                stats = self.table_stats.get(table, {})
                
                # Recommend organization + status composite indexes
                if not self._has_index(table, ['organization_id', 'created_at']):
                    recommendations.append(IndexRecommendation(
                        table_name=table,
                        columns=['organization_id', 'created_at'],
                        reason="Large organization chronological queries",
                        impact="high" if stats.get('total_rows', 0) > 10000 else "medium",
                        query_pattern="WHERE organization_id = ? ORDER BY created_at DESC",
                        is_composite=True,
                        estimated_rows=stats.get('total_rows', 0),
                        frequency=50,
                        existing_indexes=self._get_existing_index_names(table)
                    ))
        
        return recommendations
    
    def _has_index(self, table_name: str, columns: List[str]) -> bool:
        """Check if table has an index covering the specified columns"""
        
        table_indexes = self.existing_indexes.get(table_name, [])
        
        for index in table_indexes:
            index_columns = index['columns']
            
            # Exact match or index covers these columns as prefix
            if (index_columns == columns or 
                (len(columns) <= len(index_columns) and 
                 index_columns[:len(columns)] == columns)):
                return True
        
        return False
    
    def _get_existing_index_names(self, table_name: str) -> List[str]:
        """Get list of existing index names for a table"""
        
        table_indexes = self.existing_indexes.get(table_name, [])
        return [idx['name'] for idx in table_indexes]
    
    def _extract_columns_from_index_def(self, index_def: str) -> List[str]:
        """Extract column names from index definition"""
        
        try:
            # Extract columns from PostgreSQL index definition
            # Example: CREATE INDEX idx_name ON table_name (col1, col2)
            match = re.search(r'\((.*?)\)', index_def)
            if match:
                columns_str = match.group(1)
                # Split by comma and clean up
                columns = [col.strip().strip('"') for col in columns_str.split(',')]
                return columns
        except Exception as e:
            logger.warning(f"Error extracting columns from index definition: {e}")
        
        return []
    
    def _assess_impact(self, row_count: int, index_type: str) -> str:
        """Assess the impact of an index recommendation"""
        
        # Base impact on table size and index type
        if row_count > 100000:  # Large tables
            if index_type in ['foreign_key', 'organization_scoped']:
                return "high"
            elif index_type == 'composite':
                return "high"
            else:
                return "medium"
        elif row_count > 10000:  # Medium tables
            if index_type in ['foreign_key', 'organization_scoped']:
                return "medium"
            else:
                return "low"
        else:  # Small tables
            return "low"
    
    def generate_index_sql(self, recommendations: List[IndexRecommendation]) -> Dict[str, List[str]]:
        """
        Generate SQL statements for creating recommended indexes
        Task 4.2.1: Index creation SQL generation
        """
        
        sql_statements = {
            'high_priority': [],
            'medium_priority': [],
            'low_priority': []
        }
        
        for rec in recommendations:
            # Generate index name
            table_short = rec.table_name.replace('_', '')[:10]
            columns_short = '_'.join(rec.columns)[:20]
            index_name = f"idx_{table_short}_{columns_short}"
            
            # Generate SQL
            columns_sql = ', '.join(rec.columns)
            
            if rec.is_composite and len(rec.columns) > 1:
                # For composite indexes, consider column order
                sql = f"CREATE INDEX CONCURRENTLY {index_name} ON {rec.table_name} ({columns_sql});"
            else:
                sql = f"CREATE INDEX CONCURRENTLY {index_name} ON {rec.table_name} ({columns_sql});"
            
            # Add to appropriate priority list
            sql_statements[f"{rec.impact}_priority"].append(sql)
        
        return sql_statements
    
    def export_index_analysis(self, filename: Optional[str] = None) -> Dict[str, Any]:
        """
        Export comprehensive index analysis report
        Task 4.2.1: Analysis reporting
        """
        
        recommendations = self.analyze_missing_indexes()
        sql_statements = self.generate_index_sql(recommendations)
        
        report = {
            'timestamp': timezone.now().isoformat(),
            'summary': {
                'total_recommendations': len(recommendations),
                'high_priority': len([r for r in recommendations if r.impact == 'high']),
                'medium_priority': len([r for r in recommendations if r.impact == 'medium']),
                'low_priority': len([r for r in recommendations if r.impact == 'low']),
                'composite_indexes': len([r for r in recommendations if r.is_composite])
            },
            'existing_indexes': dict(self.existing_indexes),
            'table_statistics': dict(self.table_stats),
            'recommendations': [
                {
                    'table_name': rec.table_name,
                    'columns': rec.columns,
                    'index_type': rec.index_type,
                    'reason': rec.reason,
                    'impact': rec.impact,
                    'query_pattern': rec.query_pattern,
                    'is_composite': rec.is_composite,
                    'estimated_rows': rec.estimated_rows,
                    'existing_indexes': rec.existing_indexes
                }
                for rec in recommendations
            ],
            'sql_statements': sql_statements,
            'implementation_notes': [
                "Use CONCURRENTLY option to avoid locking tables during index creation",
                "Implement high-priority indexes first",
                "Monitor query performance before and after index creation",
                "Consider index maintenance overhead on write-heavy tables"
            ]
        }
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(report, f, indent=2, default=str)
                logger.info(f"Index analysis report exported to {filename}")
            except Exception as e:
                logger.error(f"Error exporting index analysis report: {e}")
        
        return report


# Global database index analyzer instance
database_index_analyzer = DatabaseIndexAnalyzer()


# Utility functions
def analyze_missing_indexes() -> List[IndexRecommendation]:
    """Convenience function to analyze missing indexes"""
    return database_index_analyzer.analyze_missing_indexes()


def generate_index_creation_sql() -> Dict[str, List[str]]:
    """Generate SQL for creating recommended indexes"""
    recommendations = database_index_analyzer.analyze_missing_indexes()
    return database_index_analyzer.generate_index_sql(recommendations)


def export_index_report(filename: str) -> Dict[str, Any]:
    """Export comprehensive index analysis report"""
    return database_index_analyzer.export_index_analysis(filename)
