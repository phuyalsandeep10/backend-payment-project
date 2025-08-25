"""
Slow Query Optimizer - Task 4.2.2

Identifies, analyzes, and optimizes slow database queries for improved performance.
Includes query rewriting suggestions and execution plan analysis.
"""

import logging
import time
import re
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from django.db import connection
from django.utils import timezone
import hashlib
import json

logger = logging.getLogger(__name__)


@dataclass
class SlowQuery:
    """Slow query analysis result"""
    query_hash: str
    query: str
    execution_time: float
    execution_count: int = 1
    avg_execution_time: float = 0.0
    max_execution_time: float = 0.0
    min_execution_time: float = 0.0
    first_seen: datetime = field(default_factory=timezone.now)
    last_seen: datetime = field(default_factory=timezone.now)
    table_names: List[str] = field(default_factory=list)
    query_type: str = "SELECT"  # SELECT, INSERT, UPDATE, DELETE
    rows_examined: int = 0
    rows_returned: int = 0


@dataclass
class QueryOptimization:
    """Query optimization recommendation"""
    original_query: str
    optimized_query: str
    optimization_type: str
    description: str
    estimated_improvement: str
    impact: str = "medium"  # high, medium, low
    complexity: str = "easy"  # easy, medium, hard


@dataclass
class ExecutionPlan:
    """Query execution plan analysis"""
    query_hash: str
    plan: Dict[str, Any]
    total_cost: float
    execution_time: float
    node_types: List[str]
    table_scans: List[str]
    index_scans: List[str]
    joins: List[str]
    bottlenecks: List[str]


class SlowQueryAnalyzer:
    """
    Comprehensive slow query analysis and optimization system
    Task 4.2.2: Core slow query optimization functionality
    """
    
    def __init__(self, slow_threshold: float = 1.0):
        self.slow_threshold = slow_threshold  # Seconds
        self.slow_queries = {}  # query_hash -> SlowQuery
        self.query_history = deque(maxlen=10000)
        self.optimization_rules = self._load_optimization_rules()
        
        # Query pattern analyzers
        self.common_issues = {
            'missing_indexes': [],
            'inefficient_joins': [],
            'suboptimal_where_clauses': [],
            'unnecessary_columns': [],
            'n_plus_one_queries': []
        }
    
    def capture_slow_query(self, query: str, execution_time: float, **kwargs) -> str:
        """
        Capture and analyze a slow query
        Task 4.2.2: Slow query capture and tracking
        """
        
        if execution_time < self.slow_threshold:
            return ""  # Not slow enough to track
        
        # Normalize query for pattern matching
        normalized_query = self._normalize_query(query)
        query_hash = hashlib.md5(normalized_query.encode()).hexdigest()
        
        # Update or create slow query record
        if query_hash in self.slow_queries:
            slow_query = self.slow_queries[query_hash]
            slow_query.execution_count += 1
            slow_query.last_seen = timezone.now()
            
            # Update timing statistics
            total_time = slow_query.avg_execution_time * (slow_query.execution_count - 1) + execution_time
            slow_query.avg_execution_time = total_time / slow_query.execution_count
            slow_query.max_execution_time = max(slow_query.max_execution_time, execution_time)
            slow_query.min_execution_time = min(slow_query.min_execution_time, execution_time)
        else:
            slow_query = SlowQuery(
                query_hash=query_hash,
                query=query,
                execution_time=execution_time,
                avg_execution_time=execution_time,
                max_execution_time=execution_time,
                min_execution_time=execution_time,
                table_names=self._extract_table_names(query),
                query_type=self._get_query_type(query),
                rows_examined=kwargs.get('rows_examined', 0),
                rows_returned=kwargs.get('rows_returned', 0)
            )
            self.slow_queries[query_hash] = slow_query
        
        # Add to history
        self.query_history.append({
            'query_hash': query_hash,
            'execution_time': execution_time,
            'timestamp': timezone.now()
        })
        
        logger.warning(f"Slow query detected: {execution_time:.3f}s - {query[:100]}...")
        return query_hash
    
    def analyze_slow_queries(self) -> List[Dict[str, Any]]:
        """
        Analyze all captured slow queries for optimization opportunities
        Task 4.2.2: Comprehensive slow query analysis
        """
        
        analysis_results = []
        
        for query_hash, slow_query in self.slow_queries.items():
            # Skip if not frequently slow
            if slow_query.execution_count < 2 and slow_query.avg_execution_time < self.slow_threshold * 2:
                continue
            
            try:
                # Analyze execution plan
                execution_plan = self._analyze_execution_plan(slow_query.query)
                
                # Generate optimizations
                optimizations = self._generate_query_optimizations(slow_query, execution_plan)
                
                # Identify specific issues
                issues = self._identify_query_issues(slow_query, execution_plan)
                
                analysis_result = {
                    'query_hash': query_hash,
                    'query': slow_query.query,
                    'performance_stats': {
                        'avg_execution_time': slow_query.avg_execution_time,
                        'max_execution_time': slow_query.max_execution_time,
                        'execution_count': slow_query.execution_count,
                        'total_time_wasted': slow_query.avg_execution_time * slow_query.execution_count
                    },
                    'execution_plan': execution_plan,
                    'optimizations': optimizations,
                    'issues': issues,
                    'priority': self._calculate_priority(slow_query, execution_plan, issues)
                }
                
                analysis_results.append(analysis_result)
                
            except Exception as e:
                logger.error(f"Error analyzing slow query {query_hash}: {e}")
        
        # Sort by priority
        analysis_results.sort(key=lambda x: {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}[x['priority']], reverse=True)
        
        return analysis_results
    
    def optimize_query(self, query: str) -> List[QueryOptimization]:
        """
        Generate specific optimizations for a query
        Task 4.2.2: Query optimization generation
        """
        
        optimizations = []
        
        # Analyze query structure
        query_lower = query.lower().strip()
        
        # SELECT * optimization
        if 'select *' in query_lower:
            optimizations.append(QueryOptimization(
                original_query=query,
                optimized_query=self._optimize_select_star(query),
                optimization_type="column_selection",
                description="Replace SELECT * with specific columns",
                estimated_improvement="20-50% faster, reduced memory usage",
                impact="medium",
                complexity="easy"
            ))
        
        # Missing WHERE clause optimization
        if 'where' not in query_lower and 'select' in query_lower:
            optimizations.append(QueryOptimization(
                original_query=query,
                optimized_query=query + " WHERE [add appropriate conditions]",
                optimization_type="where_clause",
                description="Add WHERE clause to limit result set",
                estimated_improvement="Potentially 90%+ faster",
                impact="high",
                complexity="medium"
            ))
        
        # LIMIT optimization
        if 'limit' not in query_lower and 'select' in query_lower:
            optimizations.append(QueryOptimization(
                original_query=query,
                optimized_query=query + " LIMIT 100",
                optimization_type="result_limiting",
                description="Add LIMIT clause if full result set not needed",
                estimated_improvement="30-80% faster for large tables",
                impact="medium",
                complexity="easy"
            ))
        
        # Subquery optimization
        if 'in (select' in query_lower:
            optimizations.append(QueryOptimization(
                original_query=query,
                optimized_query=self._optimize_in_subquery(query),
                optimization_type="subquery_to_join",
                description="Convert IN subquery to JOIN",
                estimated_improvement="40-70% faster",
                impact="high",
                complexity="medium"
            ))
        
        # OR condition optimization
        if ' or ' in query_lower:
            optimizations.append(QueryOptimization(
                original_query=query,
                optimized_query=self._optimize_or_conditions(query),
                optimization_type="or_to_union",
                description="Convert OR conditions to UNION where appropriate",
                estimated_improvement="30-60% faster",
                impact="medium",
                complexity="medium"
            ))
        
        # Function in WHERE clause optimization
        function_pattern = r'WHERE\s+\w+\([^)]+\)\s*[=<>]'
        if re.search(function_pattern, query_lower):
            optimizations.append(QueryOptimization(
                original_query=query,
                optimized_query=query,  # Would need specific logic
                optimization_type="function_optimization",
                description="Avoid functions in WHERE clause predicates",
                estimated_improvement="50-200% faster",
                impact="high",
                complexity="hard"
            ))
        
        # JOIN order optimization
        if 'join' in query_lower:
            join_optimization = self._analyze_join_optimization(query)
            if join_optimization:
                optimizations.append(join_optimization)
        
        return optimizations
    
    def _normalize_query(self, query: str) -> str:
        """Normalize query for pattern matching"""
        
        # Remove extra whitespace
        normalized = re.sub(r'\s+', ' ', query.strip())
        
        # Replace numeric literals with placeholders
        normalized = re.sub(r'\b\d+\b', '?', normalized)
        
        # Replace string literals with placeholders
        normalized = re.sub(r"'[^']*'", "'?'", normalized)
        
        # Standardize case for keywords
        keywords = ['SELECT', 'FROM', 'WHERE', 'JOIN', 'LEFT', 'RIGHT', 'INNER', 'OUTER', 
                   'GROUP BY', 'ORDER BY', 'HAVING', 'LIMIT', 'OFFSET']
        
        for keyword in keywords:
            pattern = r'\b' + keyword.lower() + r'\b'
            normalized = re.sub(pattern, keyword, normalized, flags=re.IGNORECASE)
        
        return normalized
    
    def _extract_table_names(self, query: str) -> List[str]:
        """Extract table names from query"""
        
        tables = []
        
        # Simple regex patterns for common table references
        patterns = [
            r'FROM\s+(\w+)',
            r'JOIN\s+(\w+)',
            r'UPDATE\s+(\w+)',
            r'INSERT\s+INTO\s+(\w+)',
            r'DELETE\s+FROM\s+(\w+)'
        ]
        
        query_upper = query.upper()
        
        for pattern in patterns:
            matches = re.findall(pattern, query_upper)
            tables.extend(matches)
        
        return list(set(tables))  # Remove duplicates
    
    def _get_query_type(self, query: str) -> str:
        """Get query type from SQL"""
        
        query_upper = query.upper().strip()
        
        if query_upper.startswith('SELECT'):
            return 'SELECT'
        elif query_upper.startswith('INSERT'):
            return 'INSERT'
        elif query_upper.startswith('UPDATE'):
            return 'UPDATE'
        elif query_upper.startswith('DELETE'):
            return 'DELETE'
        else:
            return 'OTHER'
    
    def _analyze_execution_plan(self, query: str) -> Optional[ExecutionPlan]:
        """Analyze query execution plan"""
        
        try:
            with connection.cursor() as cursor:
                # Get execution plan
                explain_query = f"EXPLAIN (FORMAT JSON, ANALYZE) {query}"
                cursor.execute(explain_query)
                plan_result = cursor.fetchone()
                
                if plan_result:
                    plan_data = plan_result[0][0]  # PostgreSQL returns nested array
                    
                    return ExecutionPlan(
                        query_hash=hashlib.md5(query.encode()).hexdigest(),
                        plan=plan_data,
                        total_cost=plan_data.get('Total Cost', 0),
                        execution_time=plan_data.get('Actual Total Time', 0),
                        node_types=self._extract_node_types(plan_data),
                        table_scans=self._extract_table_scans(plan_data),
                        index_scans=self._extract_index_scans(plan_data),
                        joins=self._extract_joins(plan_data),
                        bottlenecks=self._identify_bottlenecks(plan_data)
                    )
        except Exception as e:
            logger.error(f"Error analyzing execution plan: {e}")
        
        return None
    
    def _extract_node_types(self, plan: Dict) -> List[str]:
        """Extract node types from execution plan"""
        
        node_types = []
        
        def extract_recursive(node):
            if isinstance(node, dict):
                if 'Node Type' in node:
                    node_types.append(node['Node Type'])
                
                # Recurse into child plans
                if 'Plans' in node:
                    for child_plan in node['Plans']:
                        extract_recursive(child_plan)
        
        extract_recursive(plan)
        return list(set(node_types))
    
    def _extract_table_scans(self, plan: Dict) -> List[str]:
        """Extract table scan operations from execution plan"""
        
        scans = []
        
        def extract_recursive(node):
            if isinstance(node, dict):
                node_type = node.get('Node Type', '')
                
                if 'Seq Scan' in node_type:
                    relation = node.get('Relation Name', 'unknown')
                    scans.append(f"Sequential scan on {relation}")
                
                if 'Plans' in node:
                    for child_plan in node['Plans']:
                        extract_recursive(child_plan)
        
        extract_recursive(plan)
        return scans
    
    def _extract_index_scans(self, plan: Dict) -> List[str]:
        """Extract index scan operations from execution plan"""
        
        scans = []
        
        def extract_recursive(node):
            if isinstance(node, dict):
                node_type = node.get('Node Type', '')
                
                if 'Index Scan' in node_type:
                    index = node.get('Index Name', 'unknown')
                    relation = node.get('Relation Name', 'unknown')
                    scans.append(f"Index scan using {index} on {relation}")
                
                if 'Plans' in node:
                    for child_plan in node['Plans']:
                        extract_recursive(child_plan)
        
        extract_recursive(plan)
        return scans
    
    def _extract_joins(self, plan: Dict) -> List[str]:
        """Extract join operations from execution plan"""
        
        joins = []
        
        def extract_recursive(node):
            if isinstance(node, dict):
                node_type = node.get('Node Type', '')
                
                if 'Join' in node_type:
                    join_type = node.get('Join Type', 'unknown')
                    joins.append(f"{node_type} ({join_type})")
                
                if 'Plans' in node:
                    for child_plan in node['Plans']:
                        extract_recursive(child_plan)
        
        extract_recursive(plan)
        return joins
    
    def _identify_bottlenecks(self, plan: Dict) -> List[str]:
        """Identify performance bottlenecks in execution plan"""
        
        bottlenecks = []
        
        def analyze_recursive(node):
            if isinstance(node, dict):
                node_type = node.get('Node Type', '')
                actual_time = node.get('Actual Total Time', 0)
                rows = node.get('Actual Rows', 0)
                
                # Sequential scans on large tables
                if 'Seq Scan' in node_type and rows > 10000:
                    relation = node.get('Relation Name', 'unknown')
                    bottlenecks.append(f"Large sequential scan on {relation} ({rows:,} rows)")
                
                # Expensive operations
                if actual_time > 1000:  # More than 1 second
                    bottlenecks.append(f"Expensive {node_type}: {actual_time:.1f}ms")
                
                # Nested loops with high iterations
                if 'Nested Loop' in node_type and node.get('Actual Loops', 1) > 1000:
                    loops = node.get('Actual Loops', 1)
                    bottlenecks.append(f"High-iteration nested loop: {loops:,} iterations")
                
                if 'Plans' in node:
                    for child_plan in node['Plans']:
                        analyze_recursive(child_plan)
        
        analyze_recursive(plan)
        return bottlenecks
    
    def _generate_query_optimizations(self, slow_query: SlowQuery, execution_plan: Optional[ExecutionPlan]) -> List[QueryOptimization]:
        """Generate optimizations for a specific slow query"""
        
        optimizations = self.optimize_query(slow_query.query)
        
        # Add execution plan based optimizations
        if execution_plan:
            # Sequential scan optimizations
            for scan in execution_plan.table_scans:
                if 'Sequential scan' in scan:
                    optimizations.append(QueryOptimization(
                        original_query=slow_query.query,
                        optimized_query="[Add appropriate index]",
                        optimization_type="index_creation",
                        description=f"Create index to avoid {scan}",
                        estimated_improvement="50-90% faster",
                        impact="high",
                        complexity="easy"
                    ))
            
            # Join optimizations
            for join in execution_plan.joins:
                if 'Nested Loop' in join:
                    optimizations.append(QueryOptimization(
                        original_query=slow_query.query,
                        optimized_query="[Optimize join conditions]",
                        optimization_type="join_optimization",
                        description="Optimize nested loop join with better indexes",
                        estimated_improvement="40-80% faster",
                        impact="high",
                        complexity="medium"
                    ))
        
        return optimizations
    
    def _identify_query_issues(self, slow_query: SlowQuery, execution_plan: Optional[ExecutionPlan]) -> List[str]:
        """Identify specific issues with a slow query"""
        
        issues = []
        query_lower = slow_query.query.lower()
        
        # Common anti-patterns
        if 'select *' in query_lower:
            issues.append("Using SELECT * instead of specific columns")
        
        if 'where' not in query_lower and slow_query.query_type == 'SELECT':
            issues.append("No WHERE clause - potentially scanning entire table")
        
        if 'limit' not in query_lower and slow_query.query_type == 'SELECT':
            issues.append("No LIMIT clause - potentially returning large result set")
        
        if 'order by' in query_lower and 'limit' not in query_lower:
            issues.append("ORDER BY without LIMIT may be inefficient")
        
        # Function usage in WHERE
        if re.search(r'where.*\w+\([^)]+\)', query_lower):
            issues.append("Function calls in WHERE clause prevent index usage")
        
        # Execution plan issues
        if execution_plan:
            if execution_plan.table_scans:
                issues.append(f"Sequential table scans detected: {len(execution_plan.table_scans)}")
            
            if execution_plan.bottlenecks:
                issues.extend(execution_plan.bottlenecks)
        
        # Query frequency issues
        if slow_query.execution_count > 100:
            issues.append(f"High frequency query ({slow_query.execution_count} executions)")
        
        return issues
    
    def _calculate_priority(self, slow_query: SlowQuery, execution_plan: Optional[ExecutionPlan], issues: List[str]) -> str:
        """Calculate optimization priority"""
        
        score = 0
        
        # Time impact
        total_time_wasted = slow_query.avg_execution_time * slow_query.execution_count
        if total_time_wasted > 300:  # 5 minutes total
            score += 3
        elif total_time_wasted > 60:  # 1 minute total
            score += 2
        else:
            score += 1
        
        # Frequency impact
        if slow_query.execution_count > 100:
            score += 2
        elif slow_query.execution_count > 10:
            score += 1
        
        # Execution time impact
        if slow_query.avg_execution_time > 10:  # 10 seconds
            score += 3
        elif slow_query.avg_execution_time > 5:   # 5 seconds
            score += 2
        elif slow_query.avg_execution_time > 1:   # 1 second
            score += 1
        
        # Issue severity
        critical_issues = ["No WHERE clause", "Sequential table scans", "Large sequential scan"]
        for issue in issues:
            if any(critical in issue for critical in critical_issues):
                score += 2
        
        # Determine priority
        if score >= 8:
            return "critical"
        elif score >= 6:
            return "high"
        elif score >= 3:
            return "medium"
        else:
            return "low"
    
    def _optimize_select_star(self, query: str) -> str:
        """Optimize SELECT * queries"""
        
        # This would need to analyze the table schema and usage patterns
        # For now, provide a template
        return query.replace('SELECT *', 'SELECT [specify needed columns]')
    
    def _optimize_in_subquery(self, query: str) -> str:
        """Convert IN subquery to JOIN"""
        
        # Simple pattern replacement (would need more sophisticated parsing)
        pattern = r'WHERE\s+(\w+)\s+IN\s+\(SELECT\s+(\w+)\s+FROM\s+(\w+)(?:\s+WHERE\s+([^)]+))?\)'
        
        def replace_func(match):
            column, select_col, from_table, where_clause = match.groups()
            where_part = f" AND {where_clause}" if where_clause else ""
            return f"JOIN {from_table} ON {column} = {from_table}.{select_col}{where_part}"
        
        return re.sub(pattern, replace_func, query, flags=re.IGNORECASE)
    
    def _optimize_or_conditions(self, query: str) -> str:
        """Optimize OR conditions to UNION where appropriate"""
        
        # This would need sophisticated parsing to properly convert OR to UNION
        # For now, provide a template
        return query + " [Consider converting OR conditions to UNION]"
    
    def _analyze_join_optimization(self, query: str) -> Optional[QueryOptimization]:
        """Analyze JOIN optimization opportunities"""
        
        # Count joins
        join_count = query.lower().count(' join ')
        
        if join_count > 3:
            return QueryOptimization(
                original_query=query,
                optimized_query="[Analyze join order and add indexes]",
                optimization_type="complex_join_optimization",
                description=f"Complex query with {join_count} joins - optimize join order and indexes",
                estimated_improvement="30-70% faster",
                impact="high",
                complexity="hard"
            )
        
        return None
    
    def _load_optimization_rules(self) -> Dict[str, List[str]]:
        """Load query optimization rules"""
        
        return {
            'select_optimization': [
                "Avoid SELECT * - specify only needed columns",
                "Use LIMIT when possible to reduce result set",
                "Consider using EXISTS instead of COUNT(*) > 0"
            ],
            'where_optimization': [
                "Avoid functions in WHERE clause predicates",
                "Put most selective conditions first",
                "Use appropriate data types in comparisons"
            ],
            'join_optimization': [
                "Ensure JOIN conditions are indexed",
                "Consider join order for optimal performance",
                "Use INNER JOIN instead of WHERE when possible"
            ],
            'index_optimization': [
                "Create indexes for frequently filtered columns",
                "Consider composite indexes for multi-column WHERE clauses",
                "Use covering indexes to avoid table lookups"
            ]
        }
    
    def get_slow_query_summary(self) -> Dict[str, Any]:
        """Get summary of slow query analysis"""
        
        total_queries = len(self.slow_queries)
        if total_queries == 0:
            return {
                'total_slow_queries': 0,
                'avg_execution_time': 0,
                'total_time_wasted': 0,
                'most_frequent_issues': []
            }
        
        total_time_wasted = sum(
            sq.avg_execution_time * sq.execution_count 
            for sq in self.slow_queries.values()
        )
        
        avg_execution_time = sum(sq.avg_execution_time for sq in self.slow_queries.values()) / total_queries
        
        # Most common query types
        query_types = defaultdict(int)
        for sq in self.slow_queries.values():
            query_types[sq.query_type] += 1
        
        return {
            'total_slow_queries': total_queries,
            'avg_execution_time': avg_execution_time,
            'total_time_wasted': total_time_wasted,
            'query_types': dict(query_types),
            'slowest_query': max(self.slow_queries.values(), key=lambda x: x.max_execution_time),
            'most_frequent_query': max(self.slow_queries.values(), key=lambda x: x.execution_count)
        }


# Global slow query analyzer instance
slow_query_analyzer = SlowQueryAnalyzer()


# Utility functions
def capture_slow_query(query: str, execution_time: float) -> str:
    """Convenience function to capture slow queries"""
    return slow_query_analyzer.capture_slow_query(query, execution_time)


def analyze_all_slow_queries() -> List[Dict[str, Any]]:
    """Analyze all captured slow queries"""
    return slow_query_analyzer.analyze_slow_queries()


def optimize_specific_query(query: str) -> List[QueryOptimization]:
    """Get optimizations for a specific query"""
    return slow_query_analyzer.optimize_query(query)
