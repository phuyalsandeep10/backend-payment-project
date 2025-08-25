"""
Background Task Views
Provides API endpoints for managing background tasks and automated business processes
"""

from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from django.core.cache import cache
from datetime import timedelta
import logging

from .background_task_processor import BackgroundTaskProcessor
from .automated_business_processes import AutomatedBusinessProcessManager
from apps.permissions.permissions import IsOrgAdminOrSuperAdmin

# Performance logger
performance_logger = logging.getLogger('performance')

class BackgroundTaskViewSet(viewsets.ViewSet):
    """
    ViewSet for managing background tasks
    """
    permission_classes = [IsAuthenticated, IsOrgAdminOrSuperAdmin]
    
    @action(detail=False, methods=['post'], url_path='queue-deal-processing')
    def queue_deal_processing(self, request):
        """
        Queue deal processing workflow task
        """
        try:
            deal_id = request.data.get('deal_id')
            workflow_action = request.data.get('workflow_action')
            priority = request.data.get('priority', BackgroundTaskProcessor.PRIORITY_MEDIUM)
            
            if not deal_id or not workflow_action:
                return Response(
                    {'error': 'deal_id and workflow_action are required'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate workflow action
            valid_actions = ['verify_deal', 'calculate_commission', 'update_payment_status', 'generate_invoice']
            if workflow_action not in valid_actions:
                return Response(
                    {'error': f'Invalid workflow_action. Must be one of: {valid_actions}'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Queue the task
            from .background_task_processor import process_deal_workflow
            
            task_result = BackgroundTaskProcessor.queue_task_with_monitoring(
                process_deal_workflow,
                deal_id,
                workflow_action,
                request.user.id,
                priority=priority
            )
            
            return Response({
                'success': True,
                'task_info': task_result,
                'message': f'Deal processing task queued successfully'
            })
            
        except Exception as e:
            performance_logger.error(f"Failed to queue deal processing task: {str(e)}")
            return Response(
                {'error': f'Failed to queue task: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['post'], url_path='queue-file-processing')
    def queue_file_processing(self, request):
        """
        Queue file processing task
        """
        try:
            file_type = request.data.get('file_type')  # 'profile_picture' or 'deal_attachment'
            file_path = request.data.get('file_path')
            original_filename = request.data.get('original_filename')
            priority = request.data.get('priority', BackgroundTaskProcessor.PRIORITY_MEDIUM)
            
            if not all([file_type, file_path, original_filename]):
                return Response(
                    {'error': 'file_type, file_path, and original_filename are required'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Queue appropriate task based on file type
            if file_type == 'profile_picture':
                from .background_task_processor import process_profile_picture
                
                task_result = BackgroundTaskProcessor.queue_task_with_monitoring(
                    process_profile_picture,
                    request.user.id,
                    file_path,
                    original_filename,
                    priority=priority
                )
                
            elif file_type == 'deal_attachment':
                deal_id = request.data.get('deal_id')
                mime_type = request.data.get('mime_type', 'application/octet-stream')
                
                if not deal_id:
                    return Response(
                        {'error': 'deal_id is required for deal attachments'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                from .background_task_processor import process_deal_attachment
                
                task_result = BackgroundTaskProcessor.queue_task_with_monitoring(
                    process_deal_attachment,
                    deal_id,
                    file_path,
                    original_filename,
                    mime_type,
                    priority=priority
                )
                
            else:
                return Response(
                    {'error': 'Invalid file_type. Must be profile_picture or deal_attachment'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            return Response({
                'success': True,
                'task_info': task_result,
                'message': f'File processing task queued successfully'
            })
            
        except Exception as e:
            performance_logger.error(f"Failed to queue file processing task: {str(e)}")
            return Response(
                {'error': f'Failed to queue task: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['post'], url_path='send-notification')
    def send_notification(self, request):
        """
        Queue email notification task
        """
        try:
            notification_type = request.data.get('notification_type')
            recipient_type = request.data.get('recipient_type')  # 'user' or 'deal'
            priority = request.data.get('priority', BackgroundTaskProcessor.PRIORITY_MEDIUM)
            
            if not notification_type or not recipient_type:
                return Response(
                    {'error': 'notification_type and recipient_type are required'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            if recipient_type == 'user':
                # Password-related notifications
                user_id = request.data.get('user_id', request.user.id)
                additional_data = request.data.get('additional_data')
                
                from .background_task_processor import send_password_request_notification
                
                task_result = BackgroundTaskProcessor.queue_task_with_monitoring(
                    send_password_request_notification,
                    user_id,
                    notification_type,
                    additional_data,
                    priority=priority
                )
                
            elif recipient_type == 'deal':
                # Deal-related notifications
                deal_id = request.data.get('deal_id')
                additional_data = request.data.get('additional_data')
                
                if not deal_id:
                    return Response(
                        {'error': 'deal_id is required for deal notifications'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                from .background_task_processor import send_deal_notification
                
                task_result = BackgroundTaskProcessor.queue_task_with_monitoring(
                    send_deal_notification,
                    deal_id,
                    notification_type,
                    request.user.id,
                    additional_data,
                    priority=priority
                )
                
            else:
                return Response(
                    {'error': 'Invalid recipient_type. Must be user or deal'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            return Response({
                'success': True,
                'task_info': task_result,
                'message': f'Notification task queued successfully'
            })
            
        except Exception as e:
            performance_logger.error(f"Failed to queue notification task: {str(e)}")
            return Response(
                {'error': f'Failed to queue task: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['get'], url_path='status')
    def get_task_status(self, request, pk=None):
        """
        Get status of a specific background task
        """
        try:
            task_id = pk
            
            if not task_id:
                return Response(
                    {'error': 'Task ID is required'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            task_status = BackgroundTaskProcessor.get_task_status(task_id)
            
            return Response({
                'task_status': task_status
            })
            
        except Exception as e:
            performance_logger.error(f"Failed to get task status: {str(e)}")
            return Response(
                {'error': f'Failed to get task status: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['get'], url_path='monitor')
    def monitor_tasks(self, request):
        """
        Monitor background tasks
        """
        try:
            from .background_task_processor import monitor_background_tasks
            
            # Queue monitoring task
            task_result = BackgroundTaskProcessor.queue_task_with_monitoring(
                monitor_background_tasks,
                priority=BackgroundTaskProcessor.PRIORITY_LOW
            )
            
            return Response({
                'success': True,
                'monitoring_task': task_result,
                'message': 'Task monitoring initiated'
            })
            
        except Exception as e:
            performance_logger.error(f"Failed to initiate task monitoring: {str(e)}")
            return Response(
                {'error': f'Failed to initiate monitoring: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AutomatedProcessViewSet(viewsets.ViewSet):
    """
    ViewSet for managing automated business processes
    """
    permission_classes = [IsAuthenticated, IsOrgAdminOrSuperAdmin]
    
    @action(detail=False, methods=['post'], url_path='trigger-verification-reminders')
    def trigger_verification_reminders(self, request):
        """
        Manually trigger deal verification reminders
        """
        try:
            from .automated_business_processes import send_deal_verification_reminders
            
            # Queue the task
            task_result = BackgroundTaskProcessor.queue_task_with_monitoring(
                send_deal_verification_reminders,
                priority=BackgroundTaskProcessor.PRIORITY_HIGH
            )
            
            return Response({
                'success': True,
                'task_info': task_result,
                'message': 'Deal verification reminders task queued'
            })
            
        except Exception as e:
            performance_logger.error(f"Failed to trigger verification reminders: {str(e)}")
            return Response(
                {'error': f'Failed to trigger reminders: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['post'], url_path='trigger-commission-calculation')
    def trigger_commission_calculation(self, request):
        """
        Manually trigger commission calculation
        """
        try:
            user = request.user
            organization_id = None
            
            # If not superuser, limit to user's organization
            if not user.is_superuser and hasattr(user, 'organization'):
                organization_id = user.organization.id
            
            from .automated_business_processes import automated_commission_calculation
            
            # Queue the task
            task_result = BackgroundTaskProcessor.queue_task_with_monitoring(
                automated_commission_calculation,
                organization_id,
                priority=BackgroundTaskProcessor.PRIORITY_MEDIUM
            )
            
            return Response({
                'success': True,
                'task_info': task_result,
                'organization_id': organization_id,
                'message': 'Commission calculation task queued'
            })
            
        except Exception as e:
            performance_logger.error(f"Failed to trigger commission calculation: {str(e)}")
            return Response(
                {'error': f'Failed to trigger calculation: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['post'], url_path='generate-audit-report')
    def generate_audit_report(self, request):
        """
        Generate audit report
        """
        try:
            user = request.user
            organization_id = None
            
            # If not superuser, limit to user's organization
            if not user.is_superuser and hasattr(user, 'organization'):
                organization_id = user.organization.id
            
            report_type = request.data.get('report_type', 'comprehensive')
            days = int(request.data.get('days', 30))
            days = min(days, 365)  # Max 1 year
            
            from .automated_business_processes import generate_audit_report
            
            # Queue the task
            task_result = BackgroundTaskProcessor.queue_task_with_monitoring(
                generate_audit_report,
                organization_id,
                report_type,
                days,
                priority=BackgroundTaskProcessor.PRIORITY_LOW
            )
            
            return Response({
                'success': True,
                'task_info': task_result,
                'report_parameters': {
                    'organization_id': organization_id,
                    'report_type': report_type,
                    'days': days
                },
                'message': 'Audit report generation task queued'
            })
            
        except Exception as e:
            performance_logger.error(f"Failed to generate audit report: {str(e)}")
            return Response(
                {'error': f'Failed to generate report: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['post'], url_path='trigger-cleanup')
    def trigger_cleanup(self, request):
        """
        Manually trigger cleanup of expired sessions and tokens
        """
        try:
            from .automated_business_processes import cleanup_expired_sessions_and_tokens
            
            # Queue the task
            task_result = BackgroundTaskProcessor.queue_task_with_monitoring(
                cleanup_expired_sessions_and_tokens,
                priority=BackgroundTaskProcessor.PRIORITY_MEDIUM
            )
            
            return Response({
                'success': True,
                'task_info': task_result,
                'message': 'Cleanup task queued'
            })
            
        except Exception as e:
            performance_logger.error(f"Failed to trigger cleanup: {str(e)}")
            return Response(
                {'error': f'Failed to trigger cleanup: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['get'], url_path='process-status')
    def get_process_status(self, request):
        """
        Get status of automated business processes
        """
        try:
            process_name = request.query_params.get('process_name')
            
            if process_name:
                # Get specific process status
                process_status = AutomatedBusinessProcessManager.get_process_status(process_name)
                return Response({
                    'process_status': process_status
                })
            else:
                # Get all process statuses
                processes = [
                    'deal_verification_reminders',
                    'automated_commission_calculation',
                    'audit_report_comprehensive',
                    'cleanup_expired_sessions_tokens',
                    'system_health_check'
                ]
                
                all_statuses = {}
                for process in processes:
                    all_statuses[process] = AutomatedBusinessProcessManager.get_process_status(process)
                
                return Response({
                    'all_process_statuses': all_statuses,
                    'summary': {
                        'total_processes': len(processes),
                        'running_processes': len([s for s in all_statuses.values() if s['status'] == 'running']),
                        'failed_processes': len([s for s in all_statuses.values() if s['status'] == 'failed'])
                    }
                })
            
        except Exception as e:
            performance_logger.error(f"Failed to get process status: {str(e)}")
            return Response(
                {'error': f'Failed to get process status: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['get'], url_path='system-health')
    def get_system_health(self, request):
        """
        Get system health report
        """
        try:
            # Get cached health report
            health_report = cache.get('system_health_report')
            
            if not health_report:
                # Trigger health check if no cached report
                from .automated_business_processes import system_health_check
                
                task_result = BackgroundTaskProcessor.queue_task_with_monitoring(
                    system_health_check,
                    priority=BackgroundTaskProcessor.PRIORITY_HIGH
                )
                
                return Response({
                    'health_report': None,
                    'health_check_queued': True,
                    'task_info': task_result,
                    'message': 'Health check task queued. Check back in a few moments.'
                })
            
            return Response({
                'health_report': health_report,
                'cached': True
            })
            
        except Exception as e:
            performance_logger.error(f"Failed to get system health: {str(e)}")
            return Response(
                {'error': f'Failed to get system health: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['get'], url_path='audit-report')
    def get_audit_report(self, request):
        """
        Get generated audit report
        """
        try:
            user = request.user
            organization_id = None
            
            # If not superuser, limit to user's organization
            if not user.is_superuser and hasattr(user, 'organization'):
                organization_id = user.organization.id
            
            report_type = request.query_params.get('report_type', 'comprehensive')
            days = int(request.query_params.get('days', 30))
            
            # Get cached report
            report_key = f"audit_report:{report_type}:{organization_id or 'all'}:{days}"
            audit_report = cache.get(report_key)
            
            if not audit_report:
                return Response({
                    'audit_report': None,
                    'message': 'No cached audit report found. Generate a new report first.',
                    'report_parameters': {
                        'report_type': report_type,
                        'organization_id': organization_id,
                        'days': days
                    }
                }, status=status.HTTP_404_NOT_FOUND)
            
            return Response({
                'audit_report': audit_report,
                'cached': True
            })
            
        except Exception as e:
            performance_logger.error(f"Failed to get audit report: {str(e)}")
            return Response(
                {'error': f'Failed to get audit report: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )