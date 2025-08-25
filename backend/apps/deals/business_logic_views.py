"""
Enhanced Business Logic Views
Integrates deal workflow optimization and user/organization management optimization
"""

from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from django.db import transaction
from datetime import datetime, timedelta
import logging

from .models import Deal
from .enhanced_workflow_optimizer import EnhancedDealWorkflowOptimizer
from authentication.user_org_optimizer import UserOrganizationOptimizer
from apps.authentication.models import User
from apps.organization.models import Organization
from permissions.permissions import IsOrgAdminOrSuperAdmin
from core_config.query_performance_middleware import monitor_org_query_performance

# Performance logger
performance_logger = logging.getLogger('performance')

class BusinessLogicOptimizationViewSet(viewsets.ViewSet):
    """
    ViewSet for comprehensive business logic optimization
    """
    permission_classes = [IsAuthenticated, IsOrgAdminOrSuperAdmin]
    
    @action(detail=False, methods=['post'], url_path='optimize-deal-workflows')
    @monitor_org_query_performance
    def optimize_deal_workflows(self, request):
        """
        Optimize deal state machine transitions with proper validation
        """
        try:
            user = request.user
            organization = user.organization if hasattr(user, 'organization') else None
            
            if not user.is_superuser and not organization:
                return Response(
                    {'error': 'User must belong to an organization'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Get optimization parameters
            batch_size = min(int(request.data.get('batch_size', 100)), 500)
            
            # Execute deal workflow optimization
            result = EnhancedDealWorkflowOptimizer.optimize_deal_state_transitions(
                organization=organization,
                batch_size=batch_size
            )
            
            return Response({
                'success': True,
                'optimization_results': result,
                'organization': organization.name if organization else 'All Organizations',
                'optimized_at': timezone.now().isoformat()
            })
            
        except Exception as e:
            performance_logger.error(f"Deal workflow optimization failed: {str(e)}")
            return Response(
                {'error': f'Optimization failed: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['get'], url_path='deal-workflow-metrics')
    @monitor_org_query_performance
    def get_deal_workflow_metrics(self, request):
        """
        Get comprehensive deal workflow performance metrics
        """
        try:
            user = request.user
            organization = user.organization if hasattr(user, 'organization') else None
            
            days = int(request.query_params.get('days', 30))
            days = min(days, 365)  # Max 1 year
            
            # Get workflow metrics
            metrics = EnhancedDealWorkflowOptimizer.get_workflow_performance_metrics(
                organization=organization,
                days=days
            )
            
            return Response({
                'metrics': metrics,
                'organization': organization.name if organization else 'All Organizations',
                'period_days': days
            })
            
        except Exception as e:
            performance_logger.error(f"Deal workflow metrics retrieval failed: {str(e)}")
            return Response(
                {'error': f'Metrics retrieval failed: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['post'], url_path='optimize-user-management')
    @monitor_org_query_performance
    def optimize_user_management(self, request):
        """
        Optimize organization creation and role assignment workflows
        """
        try:
            user = request.user
            organization = user.organization if hasattr(user, 'organization') else None
            
            if not user.is_superuser and not organization:
                return Response(
                    {'error': 'User must belong to an organization'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Execute user/organization optimization
            result = UserOrganizationOptimizer.optimize_organization_creation_workflow(
                organization=organization
            )
            
            return Response({
                'success': True,
                'optimization_results': result,
                'organization': organization.name if organization else 'All Organizations',
                'optimized_at': timezone.now().isoformat()
            })
            
        except Exception as e:
            performance_logger.error(f"User management optimization failed: {str(e)}")
            return Response(
                {'error': f'Optimization failed: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['get'], url_path='user-activity-analytics')
    @monitor_org_query_performance
    def get_user_activity_analytics(self, request):
        """
        Get comprehensive user activity tracking and analytics
        """
        try:
            user = request.user
            organization = user.organization if hasattr(user, 'organization') else None
            
            if not organization:
                return Response(
                    {'error': 'User must belong to an organization'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            days = int(request.query_params.get('days', 30))
            days = min(days, 365)  # Max 1 year
            
            # Get user activity analytics
            activity_data = UserOrganizationOptimizer.add_user_activity_tracking(
                organization=organization,
                days=days
            )
            
            return Response({
                'activity_data': activity_data,
                'organization': organization.name,
                'period_days': days
            })
            
        except Exception as e:
            performance_logger.error(f"User activity analytics retrieval failed: {str(e)}")
            return Response(
                {'error': f'Analytics retrieval failed: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['post'], url_path='bulk-user-operations')
    @monitor_org_query_performance
    def execute_bulk_user_operations(self, request):
        """
        Execute bulk operations for user management
        """
        try:
            user = request.user
            organization = user.organization if hasattr(user, 'organization') else None
            
            if not organization:
                return Response(
                    {'error': 'User must belong to an organization'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            operation_type = request.data.get('operation_type')
            user_ids = request.data.get('user_ids', [])
            operation_data = request.data.get('operation_data', {})
            
            if not operation_type or not user_ids:
                return Response(
                    {'error': 'operation_type and user_ids are required'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate user IDs belong to organization
            target_users = User.objects.filter(
                id__in=user_ids,
                organization=organization
            )
            
            if target_users.count() != len(user_ids):
                return Response(
                    {'error': 'Some users do not belong to your organization'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Execute bulk operation
            result = cls._execute_bulk_operation(
                operation_type, target_users, operation_data, user
            )
            
            return Response({
                'success': True,
                'operation_type': operation_type,
                'processed_users': len(user_ids),
                'result': result,
                'executed_at': timezone.now().isoformat()
            })
            
        except Exception as e:
            performance_logger.error(f"Bulk user operation failed: {str(e)}")
            return Response(
                {'error': f'Bulk operation failed: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['get'], url_path='efficient-user-search')
    @monitor_org_query_performance
    def efficient_user_search(self, request):
        """
        Implement efficient user filtering and search capabilities
        """
        try:
            user = request.user
            organization = user.organization if hasattr(user, 'organization') else None
            
            if not organization:
                return Response(
                    {'error': 'User must belong to an organization'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Parse search filters
            filters = {
                'is_active': request.query_params.get('is_active'),
                'role_name': request.query_params.get('role_name'),
                'search': request.query_params.get('search'),
                'page': int(request.query_params.get('page', 1)),
                'page_size': int(request.query_params.get('page_size', 25))
            }
            
            # Parse date filters
            if request.query_params.get('created_after'):
                try:
                    filters['created_after'] = datetime.strptime(
                        request.query_params['created_after'], '%Y-%m-%d'
                    )
                except ValueError:
                    pass
            
            if request.query_params.get('last_login_after'):
                try:
                    filters['last_login_after'] = datetime.strptime(
                        request.query_params['last_login_after'], '%Y-%m-%d'
                    )
                except ValueError:
                    pass
            
            # Convert string boolean to actual boolean
            if filters['is_active'] is not None:
                filters['is_active'] = filters['is_active'].lower() == 'true'
            
            # Execute efficient user filtering
            result = UserOrganizationOptimizer.implement_efficient_user_filtering(
                organization=organization,
                filters=filters
            )
            
            # Serialize users
            from apps.authentication.serializers import UserSerializer
            serializer = UserSerializer(result['users'], many=True)
            
            return Response({
                'users': serializer.data,
                'pagination': result['pagination'],
                'filters_applied': result['filters_applied'],
                'organization': organization.name
            })
            
        except Exception as e:
            performance_logger.error(f"Efficient user search failed: {str(e)}")
            return Response(
                {'error': f'User search failed: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['get'], url_path='business-logic-dashboard')
    @monitor_org_query_performance
    def get_business_logic_dashboard(self, request):
        """
        Get comprehensive business logic optimization dashboard
        """
        try:
            user = request.user
            organization = user.organization if hasattr(user, 'organization') else None
            
            days = int(request.query_params.get('days', 30))
            days = min(days, 365)  # Max 1 year
            
            # Get deal workflow metrics
            deal_metrics = EnhancedDealWorkflowOptimizer.get_workflow_performance_metrics(
                organization=organization,
                days=days
            )
            
            # Get user activity analytics (only if organization is specified)
            user_analytics = None
            if organization:
                user_analytics = UserOrganizationOptimizer.add_user_activity_tracking(
                    organization=organization,
                    days=days
                )
            
            # Get bulk operation capabilities
            bulk_operations = None
            if organization:
                bulk_operations = UserOrganizationOptimizer.get_bulk_user_operations(organization)
            
            dashboard_data = {
                'deal_workflow_metrics': deal_metrics,
                'user_activity_analytics': user_analytics,
                'bulk_operations_available': bulk_operations,
                'organization': organization.name if organization else 'All Organizations',
                'period_days': days,
                'generated_at': timezone.now().isoformat()
            }
            
            return Response(dashboard_data)
            
        except Exception as e:
            performance_logger.error(f"Business logic dashboard retrieval failed: {str(e)}")
            return Response(
                {'error': f'Dashboard retrieval failed: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['post'], url_path='generate-optimization-report')
    @monitor_org_query_performance
    def generate_optimization_report(self, request):
        """
        Generate comprehensive business logic optimization report
        """
        try:
            user = request.user
            organization = user.organization if hasattr(user, 'organization') else None
            
            report_type = request.data.get('report_type', 'comprehensive')
            days = int(request.data.get('days', 30))
            include_recommendations = request.data.get('include_recommendations', True)
            
            report_data = {
                'report_type': report_type,
                'organization': organization.name if organization else 'All Organizations',
                'analysis_period_days': days,
                'generated_at': timezone.now().isoformat(),
                'generated_by': user.email
            }
            
            # Include deal workflow data
            if report_type in ['comprehensive', 'deal_workflows']:
                report_data['deal_workflow_metrics'] = EnhancedDealWorkflowOptimizer.get_workflow_performance_metrics(
                    organization=organization, days=days
                )
            
            # Include user management data
            if report_type in ['comprehensive', 'user_management'] and organization:
                report_data['user_activity_analytics'] = UserOrganizationOptimizer.add_user_activity_tracking(
                    organization=organization, days=days
                )
            
            # Generate recommendations
            if include_recommendations:
                report_data['recommendations'] = cls._generate_comprehensive_recommendations(
                    report_data, organization
                )
            
            return Response(report_data)
            
        except Exception as e:
            performance_logger.error(f"Optimization report generation failed: {str(e)}")
            return Response(
                {'error': f'Report generation failed: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @classmethod
    def _execute_bulk_operation(cls, operation_type, target_users, operation_data, executing_user):
        """
        Execute bulk operation on users
        """
        results = {
            'successful': 0,
            'failed': 0,
            'errors': []
        }
        
        with transaction.atomic():
            for user in target_users:
                try:
                    if operation_type == 'bulk_role_assignment':
                        role_name = operation_data.get('role_name')
                        if role_name:
                            from apps.permissions.models import Role
                            role = Role.objects.get(
                                name=role_name,
                                organization=user.organization
                            )
                            user.role = role
                            user.save(update_fields=['role'])
                            results['successful'] += 1
                    
                    elif operation_type == 'bulk_activation':
                        is_active = operation_data.get('is_active', True)
                        user.is_active = is_active
                        user.save(update_fields=['is_active'])
                        results['successful'] += 1
                    
                    elif operation_type == 'bulk_password_reset':
                        # This would trigger password reset email
                        # Implementation depends on your password reset system
                        results['successful'] += 1
                    
                    else:
                        results['errors'].append({
                            'user_id': user.id,
                            'error': f'Unknown operation type: {operation_type}'
                        })
                        results['failed'] += 1
                
                except Exception as e:
                    results['errors'].append({
                        'user_id': user.id,
                        'error': str(e)
                    })
                    results['failed'] += 1
        
        return results
    
    @classmethod
    def _generate_comprehensive_recommendations(cls, report_data, organization):
        """
        Generate comprehensive optimization recommendations
        """
        recommendations = []
        
        # Deal workflow recommendations
        if 'deal_workflow_metrics' in report_data:
            deal_metrics = report_data['deal_workflow_metrics']
            
            # Check verification efficiency
            if deal_metrics['verification_metrics']['verification_rate'] < 80:
                recommendations.append({
                    'category': 'deal_workflow',
                    'priority': 'high',
                    'issue': f"Low verification rate ({deal_metrics['verification_metrics']['verification_rate']:.1f}%)",
                    'recommendation': 'Implement automated verification rules and provide verification team training'
                })
            
            # Check workflow efficiency
            if deal_metrics['workflow_efficiency']['efficiency_score'] < 70:
                recommendations.append({
                    'category': 'deal_workflow',
                    'priority': 'medium',
                    'issue': f"Low workflow efficiency ({deal_metrics['workflow_efficiency']['efficiency_score']:.1f}%)",
                    'recommendation': 'Optimize deal state transitions and reduce workflow bottlenecks'
                })
        
        # User management recommendations
        if 'user_activity_analytics' in report_data:
            user_analytics = report_data['user_activity_analytics']
            
            # Check user engagement
            total_users = user_analytics['summary']['total_users']
            active_users = user_analytics['summary']['active_users_period']
            
            if total_users > 0 and (active_users / total_users) < 0.7:
                recommendations.append({
                    'category': 'user_management',
                    'priority': 'medium',
                    'issue': f"Low user engagement ({active_users}/{total_users} users active)",
                    'recommendation': 'Implement user engagement strategies and review inactive user accounts'
                })
        
        return recommendations