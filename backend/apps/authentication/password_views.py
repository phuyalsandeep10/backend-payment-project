"""
Password management API views
"""

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.utils import timezone
from django.db.models import Count, Q
from .models import User, PasswordExpiration, PasswordHistory
from .password_policy import PasswordPolicy
from apps.permissions.permissions import IsOrgAdminOrSuperAdmin
from core.performance.background_tasks.background_task_processor import BackgroundTaskProcessor, send_password_request_notification
import logging

# Security logger
security_logger = logging.getLogger('security')

from .response_validators import validate_response_type, ensure_drf_response

@api_view(['GET'])
@permission_classes([IsAuthenticated, IsOrgAdminOrSuperAdmin])
@validate_response_type
def password_policy_dashboard(request):
    """
    Get password policy dashboard data for organization
    """
    user = request.user
    organization_id = None
    
    if user.is_superuser:
        org_id = request.query_params.get('organization_id')
        if org_id:
            organization_id = org_id
    else:
        organization_id = user.organization.id if user.organization else None
    
    if not organization_id:
        return Response(
            {'error': 'Organization ID required'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        # Get organization users
        users = User.objects.filter(
            organization_id=organization_id,
            is_active=True
        ).select_related('organization')
        
        # Password expiration statistics
        expiration_stats = {
            'total_users': users.count(),
            'expired_passwords': 0,
            'expiring_soon': 0,
            'must_change_password': users.filter(must_change_password=True).count(),
            'never_changed_password': 0
        }
        
        user_details = []
        
        for user_obj in users:
            expiration_info = PasswordPolicy.check_password_expiration(user_obj)
            
            if expiration_info['expired']:
                expiration_stats['expired_passwords'] += 1
            elif expiration_info['expires_soon']:
                expiration_stats['expiring_soon'] += 1
            
            # Check if user never changed password (still using initial password)
            password_history_count = PasswordHistory.objects.filter(user=user_obj).count()
            if password_history_count == 0:
                expiration_stats['never_changed_password'] += 1
            
            user_details.append({
                'id': user_obj.id,
                'email': user_obj.email,
                'name': user_obj.get_full_name() or user_obj.username,
                'must_change_password': user_obj.must_change_password,
                'password_expired': expiration_info['expired'],
                'expires_soon': expiration_info['expires_soon'],
                'days_until_expiration': expiration_info['days_until_expiration'],
                'last_password_change': expiration_info['last_password_change'],
                'password_history_count': password_history_count
            })
        
        # Get password policy
        policy = PasswordPolicy.get_policy_for_organization(organization_id)
        
        return Response({
            'organization_id': organization_id,
            'policy': policy,
            'statistics': expiration_stats,
            'users': user_details,
            'generated_at': timezone.now().isoformat()
        })
        
    except Exception as e:
        security_logger.error(f"Password policy dashboard error: {str(e)}")
        return Response(
            {'error': 'Failed to generate dashboard data'}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@validate_response_type
def validate_password_strength(request):
    """
    Validate password strength against organization policy
    """
    password = request.data.get('password')
    if not password:
        return Response(
            {'error': 'Password is required'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    user = request.user
    organization_id = user.organization.id if user.organization else None
    
    # Validate password
    validation_result = PasswordPolicy.validate_password(
        password, 
        user=user, 
        organization_id=organization_id
    )
    
    # Get strength score
    strength_score = PasswordPolicy.get_password_strength_score(
        password,
        user=user,
        organization_id=organization_id
    )
    
    return Response({
        'is_valid': validation_result['is_valid'],
        'errors': validation_result['errors'],
        'strength_score': strength_score,
        'policy': validation_result['policy']
    })

@api_view(['GET'])
@permission_classes([IsAuthenticated, IsOrgAdminOrSuperAdmin])
@validate_response_type
def password_analytics(request):
    """
    Get password analytics for organization
    """
    user = request.user
    organization_id = None
    
    if user.is_superuser:
        org_id = request.query_params.get('organization_id')
        if org_id:
            organization_id = org_id
    else:
        organization_id = user.organization.id if user.organization else None
    
    if not organization_id:
        return Response(
            {'error': 'Organization ID required'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        # Get users in organization
        users = User.objects.filter(
            organization_id=organization_id,
            is_active=True
        )
        
        # Password strength distribution
        strength_distribution = {
            'weak': 0,      # 0-40
            'fair': 0,      # 41-60
            'good': 0,      # 61-80
            'strong': 0     # 81-100
        }
        
        # Password age distribution
        age_distribution = {
            'new': 0,       # < 30 days
            'recent': 0,    # 30-60 days
            'old': 0,       # 60-90 days
            'expired': 0    # > 90 days
        }
        
        policy_violations = {
            'length': 0,
            'complexity': 0,
            'common_passwords': 0,
            'repeated_chars': 0
        }
        
        for user_obj in users:
            # Note: We can't check actual password strength without the plain password
            # This would typically be done during password setting/changing
            
            # Check password age
            expiration_info = PasswordPolicy.check_password_expiration(user_obj)
            days_since_change = (timezone.now() - expiration_info['last_password_change']).days
            
            if days_since_change < 30:
                age_distribution['new'] += 1
            elif days_since_change < 60:
                age_distribution['recent'] += 1
            elif days_since_change < 90:
                age_distribution['old'] += 1
            else:
                age_distribution['expired'] += 1
        
        # Password history statistics
        history_stats = PasswordHistory.objects.filter(
            user__organization_id=organization_id
        ).aggregate(
            total_changes=Count('id'),
            unique_users=Count('user', distinct=True)
        )
        
        return Response({
            'organization_id': organization_id,
            'total_users': users.count(),
            'strength_distribution': strength_distribution,
            'age_distribution': age_distribution,
            'policy_violations': policy_violations,
            'history_stats': history_stats,
            'generated_at': timezone.now().isoformat()
        })
        
    except Exception as e:
        security_logger.error(f"Password analytics error: {str(e)}")
        return Response(
            {'error': 'Failed to generate analytics data'}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([IsAuthenticated, IsOrgAdminOrSuperAdmin])
@validate_response_type
def force_password_reset_organization(request):
    """
    Force password reset for all users in organization
    """
    user = request.user
    organization_id = None
    
    if user.is_superuser:
        org_id = request.data.get('organization_id')
        if org_id:
            organization_id = org_id
    else:
        organization_id = user.organization.id if user.organization else None
    
    if not organization_id:
        return Response(
            {'error': 'Organization ID required'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        # Get all active users in organization
        users = User.objects.filter(
            organization_id=organization_id,
            is_active=True
        )
        
        # Force password change for all users
        updated_count = users.update(must_change_password=True)
        
        # Log the action
        security_logger.info(
            f"Organization-wide password reset forced by {user.email} "
            f"for organization {organization_id}. Affected users: {updated_count}"
        )
        
        return Response({
            'message': f'Password reset forced for {updated_count} users',
            'affected_users': updated_count,
            'organization_id': organization_id
        })
        
    except Exception as e:
        security_logger.error(f"Force password reset error: {str(e)}")
        return Response(
            {'error': 'Failed to force password reset'}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated, IsOrgAdminOrSuperAdmin])
@validate_response_type
def send_password_notification_bulk(request):
    """
    Send password notifications to multiple users via background tasks
    """
    user = request.user
    organization_id = None
    
    if user.is_superuser:
        org_id = request.data.get('organization_id')
        if org_id:
            organization_id = org_id
    else:
        organization_id = user.organization.id if user.organization else None
    
    if not organization_id:
        return Response(
            {'error': 'Organization ID required'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    notification_type = request.data.get('notification_type', 'password_expiry_warning')
    user_ids = request.data.get('user_ids', [])
    
    # Validate notification type
    valid_types = ['password_reset', 'password_created', 'password_expiry_warning']
    if notification_type not in valid_types:
        return Response(
            {'error': f'Invalid notification_type. Must be one of: {valid_types}'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        # Get users to notify
        users_query = User.objects.filter(
            organization_id=organization_id,
            is_active=True
        )
        
        if user_ids:
            users_query = users_query.filter(id__in=user_ids)
        
        users = list(users_query.values('id', 'email', 'first_name'))
        
        if not users:
            return Response(
                {'error': 'No users found to notify'}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Queue background notification tasks
        task_results = []
        successful_queued = 0
        failed_queued = 0
        
        for user_data in users:
            try:
                # Prepare additional data for certain notification types
                additional_data = None
                if notification_type == 'password_expiry_warning':
                    # Check actual days until expiration
                    user_obj = User.objects.get(id=user_data['id'])
                    expiration_info = PasswordPolicy.check_password_expiration(user_obj)
                    additional_data = {
                        'days_until_expiry': expiration_info.get('days_until_expiration', 7)
                    }
                
                # Queue background email task
                task_result = BackgroundTaskProcessor.queue_task_with_monitoring(
                    send_password_request_notification,
                    user_data['id'],
                    notification_type,
                    additional_data,
                    priority=BackgroundTaskProcessor.PRIORITY_MEDIUM
                )
                
                task_results.append({
                    'user_id': user_data['id'],
                    'user_email': user_data['email'],
                    'task_id': task_result['task_id'],
                    'status': 'queued'
                })
                
                successful_queued += 1
                
            except Exception as e:
                task_results.append({
                    'user_id': user_data['id'],
                    'user_email': user_data['email'],
                    'status': 'failed',
                    'error': str(e)
                })
                failed_queued += 1
                security_logger.error(f"Failed to queue password notification for user {user_data['id']}: {str(e)}")
        
        # Log the action
        security_logger.info(
            f"Bulk password notifications queued by {user.email} "
            f"for organization {organization_id}. Type: {notification_type}. "
            f"Successful: {successful_queued}, Failed: {failed_queued}"
        )
        
        return Response({
            'message': f'Password notifications queued for {successful_queued} users',
            'notification_type': notification_type,
            'organization_id': organization_id,
            'summary': {
                'total_users': len(users),
                'successful_queued': successful_queued,
                'failed_queued': failed_queued
            },
            'task_results': task_results
        })
        
    except Exception as e:
        security_logger.error(f"Bulk password notification error: {str(e)}")
        return Response(
            {'error': 'Failed to queue password notifications'}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated, IsOrgAdminOrSuperAdmin])
@validate_response_type
def send_password_notification_single(request, user_id):
    """
    Send password notification to a single user via background task
    """
    user = request.user
    notification_type = request.data.get('notification_type', 'password_expiry_warning')
    
    # Validate notification type
    valid_types = ['password_reset', 'password_created', 'password_expiry_warning']
    if notification_type not in valid_types:
        return Response(
            {'error': f'Invalid notification_type. Must be one of: {valid_types}'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        # Get target user
        target_user = User.objects.get(id=user_id, is_active=True)
        
        # Check permissions - can only notify users in same organization (unless superuser)
        if not user.is_superuser:
            if not user.organization or target_user.organization != user.organization:
                return Response(
                    {'error': 'Permission denied: cannot notify users outside your organization'}, 
                    status=status.HTTP_403_FORBIDDEN
                )
        
        # Prepare additional data for certain notification types
        additional_data = None
        if notification_type == 'password_expiry_warning':
            expiration_info = PasswordPolicy.check_password_expiration(target_user)
            additional_data = {
                'days_until_expiry': expiration_info.get('days_until_expiration', 7)
            }
        
        # Queue background email task
        task_result = BackgroundTaskProcessor.queue_task_with_monitoring(
            send_password_request_notification,
            target_user.id,
            notification_type,
            additional_data,
            priority=BackgroundTaskProcessor.PRIORITY_HIGH
        )
        
        # Log the action
        security_logger.info(
            f"Password notification queued by {user.email} "
            f"for user {target_user.email}. Type: {notification_type}"
        )
        
        return Response({
            'message': f'Password notification queued for {target_user.email}',
            'notification_type': notification_type,
            'target_user': {
                'id': target_user.id,
                'email': target_user.email,
                'name': target_user.get_full_name() or target_user.username
            },
            'task_info': {
                'task_id': task_result['task_id'],
                'priority': task_result['priority'],
                'queued_at': task_result['queued_at']
            }
        })
        
    except User.DoesNotExist:
        return Response(
            {'error': 'User not found'}, 
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        security_logger.error(f"Single password notification error: {str(e)}")
        return Response(
            {'error': 'Failed to queue password notification'}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )