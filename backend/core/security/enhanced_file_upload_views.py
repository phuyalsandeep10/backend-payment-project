"""
Enhanced File Upload Views with Background Processing
Integrates file uploads with background task processing for improved user experience
"""

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser
from django.conf import settings
from django.core.files.storage import default_storage
from django.utils import timezone
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
import tempfile
import os
import uuid
import logging
from typing import Dict, Any

from core.performance.background_tasks.background_task_processor import BackgroundTaskProcessor, process_profile_picture, process_deal_attachment
from .file_security import validate_file_security_enhanced

logger = logging.getLogger(__name__)

class EnhancedFileUploadView(APIView):
    """
    Enhanced file upload view with background processing
    Supports profile pictures and deal attachments
    """
    
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]
    
    @swagger_auto_schema(
        operation_description="Upload files with background processing",
        manual_parameters=[
            openapi.Parameter(
                'file_type',
                openapi.IN_FORM,
                description="Type of file: 'profile_picture' or 'deal_attachment'",
                type=openapi.TYPE_STRING,
                required=True
            ),
            openapi.Parameter(
                'entity_id',
                openapi.IN_FORM,
                description="ID of the entity (user_id for profile_picture, deal_id for deal_attachment)",
                type=openapi.TYPE_INTEGER,
                required=True
            ),
            openapi.Parameter(
                'file',
                openapi.IN_FORM,
                description="File to upload",
                type=openapi.TYPE_FILE,
                required=True
            )
        ],
        responses={
            200: openapi.Response(
                description="File upload initiated successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'task_id': openapi.Schema(type=openapi.TYPE_STRING),
                        'upload_id': openapi.Schema(type=openapi.TYPE_STRING),
                        'file_info': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'filename': openapi.Schema(type=openapi.TYPE_STRING),
                                'size': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'content_type': openapi.Schema(type=openapi.TYPE_STRING)
                            }
                        )
                    }
                )
            ),
            400: openapi.Response(description="Bad request - invalid file or parameters"),
            401: openapi.Response(description="Unauthorized"),
            413: openapi.Response(description="File too large"),
            415: openapi.Response(description="Unsupported file type")
        }
    )
    def post(self, request):
        """Upload file with background processing"""
        try:
            # Validate required parameters
            file_type = request.data.get('file_type')
            entity_id = request.data.get('entity_id')
            uploaded_file = request.FILES.get('file')
            
            if not all([file_type, entity_id, uploaded_file]):
                return Response({
                    'success': False,
                    'error': 'Missing required parameters: file_type, entity_id, file'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Validate file type parameter
            if file_type not in ['profile_picture', 'deal_attachment']:
                return Response({
                    'success': False,
                    'error': 'Invalid file_type. Must be "profile_picture" or "deal_attachment"'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Validate entity ID
            try:
                entity_id = int(entity_id)
            except (ValueError, TypeError):
                return Response({
                    'success': False,
                    'error': 'Invalid entity_id. Must be a valid integer'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Validate file size
            max_size = settings.FILE_UPLOAD_MAX_MEMORY_SIZE if hasattr(settings, 'FILE_UPLOAD_MAX_MEMORY_SIZE') else 5 * 1024 * 1024  # 5MB default
            if uploaded_file.size > max_size:
                return Response({
                    'success': False,
                    'error': f'File too large. Maximum size is {max_size / (1024 * 1024):.1f}MB'
                }, status=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)
            
            # Validate file security
            try:
                uploaded_file.seek(0)  # Reset file pointer
                security_result = validate_file_security_enhanced(uploaded_file)
                
                if not security_result['is_safe']:
                    return Response({
                        'success': False,
                        'error': f'File security validation failed: {security_result["reason"]}'
                    }, status=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE)
                    
            except Exception as e:
                logger.error(f"File security validation error: {str(e)}")
                return Response({
                    'success': False,
                    'error': 'File validation failed'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Generate unique upload ID
            upload_id = str(uuid.uuid4())
            
            # Save file to temporary location
            temp_dir = tempfile.gettempdir()
            temp_filename = f"prs_temp_{upload_id}_{uploaded_file.name}"
            temp_file_path = os.path.join(temp_dir, temp_filename)
            
            try:
                uploaded_file.seek(0)  # Reset file pointer
                with open(temp_file_path, 'wb') as temp_file:
                    for chunk in uploaded_file.chunks():
                        temp_file.write(chunk)
                
                logger.info(f"File saved to temporary location: {temp_file_path}")
                
            except Exception as e:
                logger.error(f"Failed to save temporary file: {str(e)}")
                return Response({
                    'success': False,
                    'error': 'Failed to save file for processing'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            # Queue background task based on file type
            try:
                if file_type == 'profile_picture':
                    # Validate user exists and user has permission
                    from apps.authentication.models import User
                    
                    if entity_id != request.user.id and not request.user.is_staff:
                        # Only allow users to upload their own profile pictures (unless admin)
                        os.remove(temp_file_path)
                        return Response({
                            'success': False,
                            'error': 'Permission denied: can only upload your own profile picture'
                        }, status=status.HTTP_403_FORBIDDEN)
                    
                    try:
                        user = User.objects.get(id=entity_id)
                    except User.DoesNotExist:
                        os.remove(temp_file_path)
                        return Response({
                            'success': False,
                            'error': 'User not found'
                        }, status=status.HTTP_404_NOT_FOUND)
                    
                    # Queue profile picture processing
                    task_result = BackgroundTaskProcessor.queue_task_with_monitoring(
                        process_profile_picture,
                        entity_id,
                        temp_file_path,
                        uploaded_file.name,
                        priority=BackgroundTaskProcessor.PRIORITY_HIGH
                    )
                    
                elif file_type == 'deal_attachment':
                    # Validate deal exists and user has permission
                    from deals.models import Deal
                    
                    try:
                        deal = Deal.objects.get(id=entity_id)
                        
                        # Check if user has permission to upload to this deal
                        if (deal.organization != request.user.organization and 
                            not request.user.is_staff):
                            os.remove(temp_file_path)
                            return Response({
                                'success': False,
                                'error': 'Permission denied: cannot upload to this deal'
                            }, status=status.HTTP_403_FORBIDDEN)
                            
                    except Deal.DoesNotExist:
                        os.remove(temp_file_path)
                        return Response({
                            'success': False,
                            'error': 'Deal not found'
                        }, status=status.HTTP_404_NOT_FOUND)
                    
                    # Queue deal attachment processing
                    task_result = BackgroundTaskProcessor.queue_task_with_monitoring(
                        process_deal_attachment,
                        entity_id,
                        temp_file_path,
                        uploaded_file.name,
                        uploaded_file.content_type,
                        priority=BackgroundTaskProcessor.PRIORITY_MEDIUM
                    )
                
                # Return success response with task information
                return Response({
                    'success': True,
                    'message': f'{file_type.replace("_", " ").title()} upload initiated successfully',
                    'task_id': task_result['task_id'],
                    'upload_id': upload_id,
                    'file_info': {
                        'filename': uploaded_file.name,
                        'size': uploaded_file.size,
                        'content_type': uploaded_file.content_type
                    },
                    'processing_info': {
                        'priority': task_result['priority'],
                        'queued_at': task_result['queued_at'],
                        'estimated_completion': 'Within 5 minutes'
                    }
                }, status=status.HTTP_200_OK)
                
            except Exception as e:
                # Clean up temp file on error
                if os.path.exists(temp_file_path):
                    os.remove(temp_file_path)
                
                logger.error(f"Failed to queue background task: {str(e)}")
                return Response({
                    'success': False,
                    'error': 'Failed to initiate file processing'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
        except Exception as e:
            logger.error(f"File upload error: {str(e)}")
            return Response({
                'success': False,
                'error': 'File upload failed'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class FileProcessingStatusView(APIView):
    """
    Check the status of file processing tasks
    """
    
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        operation_description="Check file processing task status",
        manual_parameters=[
            openapi.Parameter(
                'task_id',
                openapi.IN_QUERY,
                description="Task ID returned from file upload",
                type=openapi.TYPE_STRING,
                required=True
            )
        ],
        responses={
            200: openapi.Response(
                description="Task status retrieved successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                        'task_status': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'task_id': openapi.Schema(type=openapi.TYPE_STRING),
                                'status': openapi.Schema(type=openapi.TYPE_STRING),
                                'result': openapi.Schema(type=openapi.TYPE_OBJECT),
                                'date_done': openapi.Schema(type=openapi.TYPE_STRING),
                                'successful': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                                'failed': openapi.Schema(type=openapi.TYPE_BOOLEAN)
                            }
                        )
                    }
                )
            ),
            400: openapi.Response(description="Missing task_id parameter"),
            401: openapi.Response(description="Unauthorized")
        }
    )
    def get(self, request):
        """Get file processing task status"""
        try:
            task_id = request.query_params.get('task_id')
            
            if not task_id:
                return Response({
                    'success': False,
                    'error': 'Missing task_id parameter'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Get task status
            task_status = BackgroundTaskProcessor.get_task_status(task_id)
            
            return Response({
                'success': True,
                'task_status': task_status
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error getting task status: {str(e)}")
            return Response({
                'success': False,
                'error': 'Failed to get task status'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class BackgroundTaskMonitoringView(APIView):
    """
    Monitor background tasks for administrators
    """
    
    permission_classes = [IsAuthenticated]
    
    def get_permissions(self):
        """Only allow administrators to access monitoring"""
        permissions = super().get_permissions()
        
        # Add admin permission check
        if self.request.user.is_authenticated:
            if not (self.request.user.is_staff or 
                   (hasattr(self.request.user, 'role') and 
                    self.request.user.role and 
                    'admin' in self.request.user.role.name.lower())):
                from rest_framework.exceptions import PermissionDenied
                raise PermissionDenied("Admin access required")
        
        return permissions
    
    @swagger_auto_schema(
        operation_description="Get background task monitoring information",
        responses={
            200: openapi.Response(
                description="Task monitoring information retrieved successfully"
            ),
            401: openapi.Response(description="Unauthorized"),
            403: openapi.Response(description="Admin access required")
        }
    )
    def get(self, request):
        """Get background task monitoring information"""
        try:
            from .background_task_processor import monitor_background_tasks
            
            # Get current task monitoring report
            monitoring_result = monitor_background_tasks.delay()
            monitoring_report = monitoring_result.get(timeout=10)
            
            # Get automated business process statuses
            from .automated_business_processes import AutomatedBusinessProcessManager
            
            process_statuses = {}
            processes = [
                'deal_verification_reminders',
                'automated_commission_calculation', 
                'generate_audit_report',
                'cleanup_expired_sessions_tokens',
                'system_health_check'
            ]
            
            for process in processes:
                process_statuses[process] = AutomatedBusinessProcessManager.get_process_status(process)
            
            return Response({
                'success': True,
                'monitoring_report': monitoring_report,
                'automated_processes': process_statuses,
                'system_info': {
                    'timestamp': timezone.now().isoformat(),
                    'total_processes_monitored': len(processes)
                }
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error getting monitoring information: {str(e)}")
            return Response({
                'success': False,
                'error': 'Failed to get monitoring information'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)