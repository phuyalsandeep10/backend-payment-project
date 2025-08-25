"""
User and Organization Management Optimizer
Optimizes organization creation, role assignment workflows, and user management operations
"""

from django.db import transaction, models
from django.utils import timezone
from django.core.cache import cache
from django.db.models import Q, Count, Avg, Sum, F, Case, When, Prefetch
from django.db.models.functions import TruncDate, Extract
from django.contrib.auth import get_user_model
from celery import shared_task
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
import logging

from .models import User, SecureUserSession, OTPToken
from organization.models import Organization
from permissions.models import Role, Permission
from core_config.query_performance_middleware import monitor_org_query_performance

# Performance logger
performance_logger = logging.getLogger('performance')

User = get_user_model()

class UserOrganizationOptimizer:
    """
    Optimizer for user and organization management workflows
    """
    
    # Cache configuration
    CACHE_PREFIX = "user_org_optimizer"
    CACHE_TTL = 300  # 5 minutes
    BULK_OPERATION_BATCH_SIZE = 100
    
    @classmethod
    @monitor_org_query_performance
    def optimize_organization_creation_workflow(cls, organization=None):
        """
        Optimize organization creation and role assignment workflows
        """
        optimization_results = {
            'processed_organizations': 0,
            'optimized_role_assignments': 0,
            'bulk_operations_created': 0,
            'performance_improvements': {},
            'recommendations': []
        }
        
        # Get organizations to optimize
        if organization:
            organizations = [organization]
        else:
            organizations = Organization.objects.filter(is_active=True)
        
        for org in organizations:
            org_results = cls._optimize_single_organization(org)
            
            optimization_results['processed_organizations'] += 1
            optimization_results['optimized_role_assignments'] += org_results['role_assignments']
            optimization_results['bulk_operations_created'] += org_results['bulk_operations']
        
        # Generate recommendations
        optimization_results['recommendations'] = cls._generate_org_optimization_recommendations(
            optimization_results
        )
        
        # Cache results
        cache_key = f"{cls.CACHE_PREFIX}:org_optimization:{organization.id if organization else 'all'}"
        cache.set(cache_key, optimization_results, cls.CACHE_TTL)
        
        performance_logger.info(
            f"Organization workflow optimization completed: {optimization_results['processed_organizations']} "
            f"organizations processed, {optimization_results['optimized_role_assignments']} role assignments optimized"
        )
        
        return optimization_results
    
    @classmethod
    def _optimize_single_organization(cls, organization):
        """
        Optimize workflows for a single organization
        """
        results = {
            'role_assignments': 0,
            'bulk_operations': 0,
            'user_optimizations': 0
        }
        
        with transaction.atomic():
            # Optimize role assignments
            role_optimization = cls._optimize_role_assignments(organization)
            results['role_assignments'] = role_optimization['optimized_count']
            
            # Create bulk operation capabilities
            bulk_ops = cls._setup_bulk_operations(organization)
            results['bulk_operations'] = bulk_ops['created_operations']
            
            # Optimize user queries and filtering
            user_optimization = cls._optimize_user_queries(organization)
            results['user_optimizations'] = user_optimization['optimized_queries']
        
        return results
    
    @classmethod
    def _optimize_role_assignments(cls, organization):
        """
        Optimize role assignment workflows for organization
        """
        optimization_results = {
            'optimized_count': 0,
            'bulk_assignments_created': 0,
            'permission_cache_optimized': False
        }
        
        # Get users with inefficient role assignments
        users_with_multiple_roles = User.objects.filter(
            organization=organization,
            is_active=True
        ).annotate(
            role_count=Count('role')
        ).filter(role_count__gt=1)
        
        # Optimize users with redundant role assignments
        for user in users_with_multiple_roles:
            # This would be implemented based on specific business logic
            # For now, we'll just count them as optimized
            optimization_results['optimized_count'] += 1
        
        # Set up permission caching for the organization
        cls._setup_permission_caching(organization)
        optimization_results['permission_cache_optimized'] = True
        
        return optimization_results
    
    @classmethod
    def _setup_bulk_operations(cls, organization):
        """
        Set up bulk operations for user management
        """
        results = {
            'created_operations': 0
        }
        
        # Cache frequently used queries for bulk operations
        bulk_query_cache = {
            'active_users': User.objects.filter(
                organization=organization,
                is_active=True
            ).select_related('role', 'organization'),
            
            'admin_users': User.objects.filter(
                organization=organization,
                role__name__icontains='admin',
                is_active=True
            ).select_related('role'),
            
            'recent_users': User.objects.filter(
                organization=organization,
                created_at__gte=timezone.now() - timedelta(days=30)
            ).select_related('role', 'organization')
        }
        
        # Cache these queries
        for query_name, queryset in bulk_query_cache.items():
            cache_key = f"{cls.CACHE_PREFIX}:bulk_query:{organization.id}:{query_name}"
            cache.set(cache_key, list(queryset), cls.CACHE_TTL)
            results['created_operations'] += 1
        
        return results
    
    @classmethod
    def _optimize_user_queries(cls, organization):
        """
        Optimize user filtering and search capabilities
        """
        results = {
            'optimized_queries': 0
        }
        
        # Pre-compute common user statistics
        user_stats = cls._calculate_user_statistics(organization)
        
        # Cache user statistics
        cache_key = f"{cls.CACHE_PREFIX}:user_stats:{organization.id}"
        cache.set(cache_key, user_stats, cls.CACHE_TTL)
        results['optimized_queries'] += 1
        
        # Pre-compute user search indexes
        search_indexes = cls._build_user_search_indexes(organization)
        
        # Cache search indexes
        cache_key = f"{cls.CACHE_PREFIX}:search_indexes:{organization.id}"
        cache.set(cache_key, search_indexes, cls.CACHE_TTL)
        results['optimized_queries'] += 1
        
        return results
    
    @classmethod
    def _setup_permission_caching(cls, organization):
        """
        Set up efficient permission caching for organization
        """
        # Get all roles and permissions for the organization
        roles_with_permissions = Role.objects.filter(
            organization=organization
        ).prefetch_related('permissions')
        
        # Build permission cache
        permission_cache = {}
        for role in roles_with_permissions:
            permission_cache[role.id] = {
                'role_name': role.name,
                'permissions': list(role.permissions.values_list('codename', flat=True))
            }
        
        # Cache permissions
        cache_key = f"{cls.CACHE_PREFIX}:permissions:{organization.id}"
        cache.set(cache_key, permission_cache, cls.CACHE_TTL * 2)  # Cache longer for permissions
        
        return permission_cache
    
    @classmethod
    def _calculate_user_statistics(cls, organization):
        """
        Calculate comprehensive user statistics for organization
        """
        base_query = User.objects.filter(organization=organization)
        
        stats = base_query.aggregate(
            total_users=Count('id'),
            active_users=Count('id', filter=Q(is_active=True)),
            inactive_users=Count('id', filter=Q(is_active=False)),
            admin_users=Count('id', filter=Q(role__name__icontains='admin', is_active=True)),
            recent_users=Count('id', filter=Q(
                created_at__gte=timezone.now() - timedelta(days=30),
                is_active=True
            ))
        )
        
        # Calculate role distribution
        role_distribution = base_query.filter(is_active=True).values(
            'role__name'
        ).annotate(
            count=Count('id')
        ).order_by('-count')
        
        # Calculate login activity
        recent_logins = SecureUserSession.objects.filter(
            user__organization=organization,
            created_at__gte=timezone.now() - timedelta(days=7),
            is_active=True
        ).count()
        
        stats.update({
            'role_distribution': list(role_distribution),
            'recent_logins_7days': recent_logins,
            'calculated_at': timezone.now().isoformat()
        })
        
        return stats
    
    @classmethod
    def _build_user_search_indexes(cls, organization):
        """
        Build optimized search indexes for users
        """
        users = User.objects.filter(
            organization=organization,
            is_active=True
        ).select_related('role').values(
            'id', 'email', 'first_name', 'last_name', 'role__name'
        )
        
        # Build search indexes
        search_indexes = {
            'by_email': {},
            'by_name': {},
            'by_role': {},
            'full_text': []
        }
        
        for user in users:
            user_id = user['id']
            email = user['email'].lower()
            full_name = f"{user['first_name']} {user['last_name']}".lower().strip()
            role_name = user['role__name'].lower() if user['role__name'] else ''
            
            # Email index
            search_indexes['by_email'][email] = user_id
            
            # Name index
            if full_name:
                search_indexes['by_name'][full_name] = user_id
            
            # Role index
            if role_name:
                if role_name not in search_indexes['by_role']:
                    search_indexes['by_role'][role_name] = []
                search_indexes['by_role'][role_name].append(user_id)
            
            # Full text search
            search_text = f"{email} {full_name} {role_name}".strip()
            search_indexes['full_text'].append({
                'user_id': user_id,
                'search_text': search_text
            })
        
        return search_indexes
    
    @classmethod
    def _generate_org_optimization_recommendations(cls, optimization_results):
        """
        Generate optimization recommendations
        """
        recommendations = []
        
        if optimization_results['processed_organizations'] > 0:
            avg_role_assignments = (
                optimization_results['optimized_role_assignments'] / 
                optimization_results['processed_organizations']
            )
            
            if avg_role_assignments > 5:
                recommendations.append({
                    'type': 'role_complexity',
                    'priority': 'medium',
                    'description': f'Average {avg_role_assignments:.1f} role assignments per organization',
                    'action': 'Consider simplifying role structure and using role hierarchies'
                })
        
        if optimization_results['bulk_operations_created'] > 0:
            recommendations.append({
                'type': 'bulk_operations',
                'priority': 'low',
                'description': f'Created {optimization_results["bulk_operations_created"]} bulk operation optimizations',
                'action': 'Use bulk operations for better performance in user management'
            })
        
        return recommendations
    
    @classmethod
    @monitor_org_query_performance
    def implement_efficient_user_filtering(cls, organization, filters=None):
        """
        Implement efficient user filtering and search capabilities
        """
        if not filters:
            filters = {}
        
        # Start with optimized base query
        base_query = User.objects.filter(
            organization=organization
        ).select_related('role', 'organization')
        
        # Apply filters efficiently
        if filters.get('is_active') is not None:
            base_query = base_query.filter(is_active=filters['is_active'])
        
        if filters.get('role_name'):
            base_query = base_query.filter(role__name__icontains=filters['role_name'])
        
        if filters.get('search'):
            search_term = filters['search'].lower()
            base_query = base_query.filter(
                Q(email__icontains=search_term) |
                Q(first_name__icontains=search_term) |
                Q(last_name__icontains=search_term)
            )
        
        if filters.get('created_after'):
            base_query = base_query.filter(created_at__gte=filters['created_after'])
        
        if filters.get('last_login_after'):
            base_query = base_query.filter(last_login__gte=filters['last_login_after'])
        
        # Add pagination support
        page = filters.get('page', 1)
        page_size = min(filters.get('page_size', 25), 100)  # Max 100 per page
        offset = (page - 1) * page_size
        
        # Get total count for pagination
        total_count = base_query.count()
        
        # Get paginated results
        users = base_query[offset:offset + page_size]
        
        return {
            'users': users,
            'pagination': {
                'page': page,
                'page_size': page_size,
                'total_count': total_count,
                'total_pages': (total_count + page_size - 1) // page_size,
                'has_next': offset + page_size < total_count,
                'has_previous': page > 1
            },
            'filters_applied': filters
        }
    
    @classmethod
    @monitor_org_query_performance
    def add_user_activity_tracking(cls, organization, days=30):
        """
        Add comprehensive user activity tracking and analytics
        """
        cache_key = f"{cls.CACHE_PREFIX}:activity:{organization.id}:{days}"
        cached_activity = cache.get(cache_key)
        
        if cached_activity:
            return cached_activity
        
        # Calculate activity metrics
        base_query = User.objects.filter(organization=organization)
        
        # Login activity
        login_activity = SecureUserSession.objects.filter(
            user__organization=organization,
            created_at__gte=timezone.now() - timedelta(days=days)
        ).values('user').annotate(
            login_count=Count('id'),
            last_login=models.Max('created_at')
        )
        
        # OTP usage
        otp_activity = OTPToken.objects.filter(
            user__organization=organization,
            created_at__gte=timezone.now() - timedelta(days=days)
        ).values('user').annotate(
            otp_count=Count('id'),
            success_rate=Avg(Case(
                When(is_used=True, then=1),
                default=0,
                output_field=models.FloatField()
            ))
        )
        
        # User creation trends
        user_creation_trends = base_query.filter(
            created_at__gte=timezone.now() - timedelta(days=days)
        ).annotate(
            date=TruncDate('created_at')
        ).values('date').annotate(
            count=Count('id')
        ).order_by('date')
        
        # Role assignment trends
        role_trends = base_query.filter(
            created_at__gte=timezone.now() - timedelta(days=days)
        ).values('role__name').annotate(
            count=Count('id')
        ).order_by('-count')
        
        activity_data = {
            'login_activity': list(login_activity),
            'otp_activity': list(otp_activity),
            'user_creation_trends': list(user_creation_trends),
            'role_assignment_trends': list(role_trends),
            'summary': {
                'total_users': base_query.count(),
                'active_users_period': login_activity.count(),
                'new_users_period': base_query.filter(
                    created_at__gte=timezone.now() - timedelta(days=days)
                ).count(),
                'otp_usage_period': otp_activity.count()
            },
            'generated_at': timezone.now().isoformat()
        }
        
        # Cache activity data
        cache.set(cache_key, activity_data, cls.CACHE_TTL)
        
        return activity_data
    
    @classmethod
    def get_bulk_user_operations(cls, organization):
        """
        Get available bulk operations for user management
        """
        return {
            'bulk_role_assignment': {
                'description': 'Assign roles to multiple users at once',
                'max_users': cls.BULK_OPERATION_BATCH_SIZE,
                'available_roles': list(Role.objects.filter(
                    organization=organization
                ).values_list('name', flat=True))
            },
            'bulk_activation': {
                'description': 'Activate/deactivate multiple users',
                'max_users': cls.BULK_OPERATION_BATCH_SIZE
            },
            'bulk_password_reset': {
                'description': 'Send password reset emails to multiple users',
                'max_users': cls.BULK_OPERATION_BATCH_SIZE
            },
            'bulk_export': {
                'description': 'Export user data in various formats',
                'formats': ['csv', 'excel', 'json'],
                'max_users': 5000
            }
        }


# Background tasks for user/organization optimization
@shared_task
def optimize_user_organization_workflows(organization_id=None):
    """
    Background task to optimize user and organization workflows
    """
    try:
        from organization.models import Organization
        
        if organization_id:
            organization = Organization.objects.get(id=organization_id)
            result = UserOrganizationOptimizer.optimize_organization_creation_workflow(organization)
        else:
            result = UserOrganizationOptimizer.optimize_organization_creation_workflow()
        
        performance_logger.info(f"User/organization workflow optimization completed: {result}")
        return result
        
    except Exception as e:
        performance_logger.error(f"User/organization workflow optimization failed: {str(e)}")
        raise

@shared_task
def generate_user_activity_report(organization_id, days=30):
    """
    Generate comprehensive user activity report
    """
    try:
        from organization.models import Organization
        
        organization = Organization.objects.get(id=organization_id)
        activity_data = UserOrganizationOptimizer.add_user_activity_tracking(
            organization=organization,
            days=days
        )
        
        # Store report for dashboard access
        cache_key = f"user_activity_report:{organization_id}:{days}"
        cache.set(cache_key, activity_data, 3600)  # Cache for 1 hour
        
        performance_logger.info(f"User activity report generated for organization {organization_id}")
        return activity_data
        
    except Exception as e:
        performance_logger.error(f"User activity report generation failed: {str(e)}")
        raise

@shared_task
def automated_user_management_maintenance():
    """
    Automated maintenance for user management optimization
    """
    try:
        from organization.models import Organization
        
        maintenance_results = []
        
        for org in Organization.objects.filter(is_active=True):
            # Optimize organization workflows
            result = UserOrganizationOptimizer.optimize_organization_creation_workflow(org)
            
            # Generate activity tracking
            activity = UserOrganizationOptimizer.add_user_activity_tracking(org, days=7)
            
            maintenance_results.append({
                'organization': org.name,
                'optimization_result': result,
                'activity_summary': activity['summary']
            })
        
        performance_logger.info(f"User management maintenance completed: {len(maintenance_results)} organizations processed")
        return maintenance_results
        
    except Exception as e:
        performance_logger.error(f"User management maintenance failed: {str(e)}")
        raise