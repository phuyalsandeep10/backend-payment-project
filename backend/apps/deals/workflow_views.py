"""
Enhanced Deal Workflow Views with Automation
"""

from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from django.db import transaction
from .models import Deal
from .workflow_automation import DealWorkflowEngine, DealPerformanceAnalyzer
from permissions.permissions import IsOrgAdminOrSuperAdmin
from core_config.query_performance_middleware import monitor_org_query_performance
import logging

# Performance logger
performance_logger = logging.getLogger('performance')

class DealWorkflowViewSet(viewsets.ViewSet):
    """
    ViewSet for deal workflow automation and management
    """
    permission_classes = [IsAuthenticated, IsOrgAdminOrSuperAdmin]
    
    @action(detail=True, methods=['post'], url_path='transition-status')
    @monitor_org_query_performance
    def transition_deal_status(self, request, pk=None):
        """
        Execute automated deal status transition with validation
        """
        try:
            deal = Deal.objects.get(pk=pk)
            user = request.user
            
            # Security check: ensure user can modify this deal
            if not user.is_superuser and user.organization != deal.organization:
                return Response(
                    {'error': 'You can only modify deals in your organization'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            new_verification_status = request.data.get('verification_status')
            new_payment_status = request.data.get('payment_status')
            remarks = request.data.get('remarks')
            notify_stakeholders = request.data.get('notify_stakeholders', True)
            
            # Execute transition using workflow engine
            result = DealWorkflowEngine.execute_status_transition(
                deal=deal,
                new_verification_status=new_verification_status,
                new_payment_status=new_payment_status,
                user=user,
                remarks=remarks,
                notify_stakeholders=notify_stakeholders
            )
            
            return Response(result)
            
        except Deal.DoesNotExist:
            return Response(
                {'error': 'Deal not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except ValueError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            performance_logger.error(f"Deal status transition failed: {str(e)}")
            return Response(
                {'error': 'Status transition failed'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['get'], url_path='validate-transition')
    def validate_status_transition(self, request, pk=None):
        """
        Validate a potential status transition without executing it
        """
        try:
            deal = Deal.objects.get(pk=pk)
            user = request.user
            
            # Security check
            if not user.is_superuser and user.organization != deal.organization:
                return Response(
                    {'error': 'You can only validate transitions for deals in your organization'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            new_verification_status = request.query_params.get('verification_status')
            new_payment_status = request.query_params.get('payment_status')
            
            validation_result = DealWorkflowEngine.validate_status_transition(
                deal=deal,
                new_verification_status=new_verification_status,
                new_payment_status=new_payment_status,
                user=user
            )
            
            return Response(validation_result)
            
        except Deal.DoesNotExist:
            return Response(
                {'error': 'Deal not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            performance_logger.error(f"Transition validation failed: {str(e)}")
            return Response(
                {'error': 'Validation failed'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['get'], url_path='pending-actions')
    @monitor_org_query_performance
    def get_pending_workflow_actions(self, request):
        """
        Get deals that require workflow actions
        """
        user = request.user
        organization = user.organization if hasattr(user, 'organization') else None
        
        if not user.is_superuser and not organization:
            return Response(
                {'error': 'User must belong to an organization'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        pending_actions = DealWorkflowEngine.get_pending_workflow_actions(
            organization=organization,
            user=user
        )
        
        return Response(pending_actions)
    
    @action(detail=False, methods=['post'], url_path='bulk-status-update')
    @monitor_org_query_performance
    def bulk_status_update(self, request):
        """
        Bulk update status for multiple deals with workflow automation
        """
        deal_ids = request.data.get('deal_ids', [])
        new_verification_status = request.data.get('verification_status')
        new_payment_status = request.data.get('payment_status')
        remarks = request.data.get('remarks')
        notify_stakeholders = request.data.get('notify_stakeholders', True)
        
        if not deal_ids:
            return Response(
                {'error': 'deal_ids are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user = request.user
        organization = user.organization if hasattr(user, 'organization') else None
        
        successful_updates = []
        failed_updates = []
        
        for deal_id in deal_ids:
            try:
                deal = Deal.objects.get(pk=deal_id)
                
                # Security check
                if not user.is_superuser and deal.organization != organization:
                    failed_updates.append({
                        'deal_id': deal_id,
                        'error': 'Cannot update deals outside your organization'
                    })
                    continue
                
                # Execute transition
                result = DealWorkflowEngine.execute_status_transition(
                    deal=deal,
                    new_verification_status=new_verification_status,
                    new_payment_status=new_payment_status,
                    user=user,
                    remarks=remarks,
                    notify_stakeholders=notify_stakeholders
                )
                
                successful_updates.append({
                    'deal_id': deal_id,
                    'deal_name': deal.deal_name,
                    'result': result
                })
                
            except Deal.DoesNotExist:
                failed_updates.append({
                    'deal_id': deal_id,
                    'error': 'Deal not found'
                })
            except Exception as e:
                failed_updates.append({
                    'deal_id': deal_id,
                    'error': str(e)
                })
        
        return Response({
            'successful_updates': successful_updates,
            'failed_updates': failed_updates,
            'summary': {
                'total_requested': len(deal_ids),
                'successful': len(successful_updates),
                'failed': len(failed_updates)
            }
        })
    
    @action(detail=True, methods=['post'], url_path='auto-update-payment-status')
    def auto_update_payment_status(self, request, pk=None):
        """
        Automatically update payment status based on payment records
        """
        try:
            deal = Deal.objects.get(pk=pk)
            user = request.user
            
            # Security check
            if not user.is_superuser and user.organization != deal.organization:
                return Response(
                    {'error': 'You can only update deals in your organization'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Get suggested payment status
            suggestion = DealWorkflowEngine.auto_update_payment_status(deal)
            
            if suggestion['requires_update']:
                # Execute the update if requested
                if request.data.get('execute_update', False):
                    result = DealWorkflowEngine.execute_status_transition(
                        deal=deal,
                        new_payment_status=suggestion['suggested_status'],
                        user=user,
                        remarks=f"Auto-updated payment status based on payment records. Total paid: {suggestion['total_paid']}"
                    )
                    
                    return Response({
                        'updated': True,
                        'suggestion': suggestion,
                        'result': result
                    })
                else:
                    return Response({
                        'updated': False,
                        'suggestion': suggestion,
                        'message': 'Set execute_update=true to apply the suggested change'
                    })
            else:
                return Response({
                    'updated': False,
                    'message': 'Payment status is already correct',
                    'current_status': deal.payment_status
                })
                
        except Deal.DoesNotExist:
            return Response(
                {'error': 'Deal not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            performance_logger.error(f"Auto payment status update failed: {str(e)}")
            return Response(
                {'error': 'Auto update failed'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class DealPerformanceViewSet(viewsets.ViewSet):
    """
    ViewSet for deal performance analytics and reporting
    """
    permission_classes = [IsAuthenticated, IsOrgAdminOrSuperAdmin]
    
    @action(detail=False, methods=['get'], url_path='verification-performance')
    @monitor_org_query_performance
    def get_verification_performance(self, request):
        """
        Get verification workflow performance analytics
        """
        user = request.user
        organization = user.organization if hasattr(user, 'organization') else None
        
        days = int(request.query_params.get('days', 30))
        
        performance_data = DealPerformanceAnalyzer.analyze_verification_performance(
            organization=organization,
            days=days
        )
        
        return Response(performance_data)
    
    @action(detail=False, methods=['get'], url_path='payment-performance')
    @monitor_org_query_performance
    def get_payment_performance(self, request):
        """
        Get payment workflow performance analytics
        """
        user = request.user
        organization = user.organization if hasattr(user, 'organization') else None
        
        days = int(request.query_params.get('days', 30))
        
        performance_data = DealPerformanceAnalyzer.analyze_payment_workflow_performance(
            organization=organization,
            days=days
        )
        
        return Response(performance_data)
    
    @action(detail=False, methods=['get'], url_path='workflow-bottlenecks')
    @monitor_org_query_performance
    def get_workflow_bottlenecks(self, request):
        """
        Identify workflow bottlenecks and optimization opportunities
        """
        user = request.user
        organization = user.organization if hasattr(user, 'organization') else None
        
        bottlenecks = DealPerformanceAnalyzer.get_workflow_bottlenecks(
            organization=organization
        )
        
        return Response(bottlenecks)
    
    @action(detail=False, methods=['get'], url_path='workflow-dashboard')
    @monitor_org_query_performance
    def get_workflow_dashboard(self, request):
        """
        Get comprehensive workflow dashboard data
        """
        user = request.user
        organization = user.organization if hasattr(user, 'organization') else None
        
        days = int(request.query_params.get('days', 30))
        
        # Get all performance data
        verification_performance = DealPerformanceAnalyzer.analyze_verification_performance(
            organization=organization, days=days
        )
        
        payment_performance = DealPerformanceAnalyzer.analyze_payment_workflow_performance(
            organization=organization, days=days
        )
        
        bottlenecks = DealPerformanceAnalyzer.get_workflow_bottlenecks(
            organization=organization
        )
        
        pending_actions = DealWorkflowEngine.get_pending_workflow_actions(
            organization=organization, user=user
        )
        
        return Response({
            'verification_performance': verification_performance,
            'payment_performance': payment_performance,
            'bottlenecks': bottlenecks,
            'pending_actions': pending_actions,
            'dashboard_generated_at': timezone.now().isoformat()
        })
    
    @action(detail=False, methods=['post'], url_path='generate-performance-report')
    @monitor_org_query_performance
    def generate_performance_report(self, request):
        """
        Generate comprehensive performance report
        """
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
        
        if report_type in ['comprehensive', 'verification']:
            report_data['verification_performance'] = DealPerformanceAnalyzer.analyze_verification_performance(
                organization=organization, days=days
            )
        
        if report_type in ['comprehensive', 'payment']:
            report_data['payment_performance'] = DealPerformanceAnalyzer.analyze_payment_workflow_performance(
                organization=organization, days=days
            )
        
        if report_type in ['comprehensive', 'bottlenecks']:
            report_data['bottlenecks'] = DealPerformanceAnalyzer.get_workflow_bottlenecks(
                organization=organization
            )
        
        if include_recommendations:
            report_data['recommendations'] = self._generate_recommendations(report_data)
        
        return Response(report_data)
    
    def _generate_recommendations(self, report_data):
        """
        Generate recommendations based on performance data
        """
        recommendations = []
        
        # Verification performance recommendations
        if 'verification_performance' in report_data:
            vp = report_data['verification_performance']
            
            if vp['verification_rate'] < 80:
                recommendations.append({
                    'category': 'verification',
                    'priority': 'high',
                    'issue': f"Low verification rate ({vp['verification_rate']:.1f}%)",
                    'recommendation': 'Review verification criteria and provide additional training to verification team'
                })
            
            if vp['avg_verification_time_hours'] > 48:
                recommendations.append({
                    'category': 'verification',
                    'priority': 'medium',
                    'issue': f"Slow verification process ({vp['avg_verification_time_hours']:.1f} hours average)",
                    'recommendation': 'Implement automated verification rules for standard deals'
                })
        
        # Payment performance recommendations
        if 'payment_performance' in report_data:
            pp = report_data['payment_performance']
            
            if pp['payment_completion_rate'] < 70:
                recommendations.append({
                    'category': 'payment',
                    'priority': 'high',
                    'issue': f"Low payment completion rate ({pp['payment_completion_rate']:.1f}%)",
                    'recommendation': 'Implement automated payment reminders and follow-up processes'
                })
        
        # Bottleneck recommendations
        if 'bottlenecks' in report_data:
            bottlenecks = report_data['bottlenecks']
            
            for bottleneck in bottlenecks['bottlenecks']:
                recommendations.append({
                    'category': 'bottleneck',
                    'priority': bottleneck['severity'],
                    'issue': bottleneck['description'],
                    'recommendation': bottleneck['recommendation']
                })
        
        return recommendations