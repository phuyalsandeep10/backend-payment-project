"""
User Management Views

This module contains the UserViewSet and related user management functionality.
Extracted from views.py for better organization and reduced complexity.
"""

import logging
from decimal import Decimal

from django.db import transaction
from django.core.management import call_command
from django.core.mail import send_mail
from django.conf import settings

from rest_framework import status, viewsets, serializers
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from .models import User, PasswordExpiration
from .serializers import UserSerializer, UserDetailSerializer, UserUpdateSerializer
from .serializers.user_serializers import UserCreateSerializer
from .filters import UserFilter
from .auth_utils import get_client_ip

from core.performance.database_optimizer import QueryOptimizer, OptimizedQueryMixin
from core_config.error_handling import security_event_logger
from apps.organization.models import Organization
from apps.permissions.models import Role
from apps.permissions.permissions import IsOrgAdminOrSuperAdmin, CanManageUserPasswords
from .response_validators import validate_response_type

# Security logger
security_logger = logging.getLogger('security')


class UserViewSet(OptimizedQueryMixin, viewsets.ModelViewSet):
    """
    API endpoint that allows users to be viewed or edited.
    Filtering by organization is handled automatically.
    Super Admins can filter by any organization using a query parameter.
    """
    queryset = User.objects.all().order_by('-date_joined')
    filterset_class = UserFilter
    permission_classes = [IsOrgAdminOrSuperAdmin]
    throttle_classes = [UserRateThrottle]

    def get_queryset(self):
        if getattr(self, 'swagger_fake_view', False) or not self.request.user.is_authenticated:
            return User.objects.none()
        
        user = self.request.user
        
        # Use QueryOptimizer for enhanced optimization
        base_queryset = User.objects.all()
        
        # Apply organization filtering first for better performance
        if user.is_superuser:
            org_id = self.request.query_params.get('organization')
            if org_id:
                base_queryset = base_queryset.filter(organization_id=org_id)
            # For superusers, if no organization is specified, show all users
        elif hasattr(user, 'organization') and user.organization:
            base_queryset = base_queryset.filter(
                organization_id=user.organization.id,
                is_active=True
            )
        else:
            return User.objects.none()
        
        # Apply QueryOptimizer for comprehensive optimization
        # Only include expensive related queries when specifically requested
        include_related = 'detailed' in self.request.query_params
        optimized_queryset = QueryOptimizer.optimize_user_queryset(
            base_queryset, 
            user.organization if hasattr(user, 'organization') else None,
            include_related=include_related
        )
        
        # Add additional prefetch based on query parameters
        include_params = self.request.query_params.get('include', '').split(',')
        
        if 'commissions' in include_params:
            optimized_queryset = optimized_queryset.prefetch_related('commissions')
        
        if 'sessions' in include_params:
            optimized_queryset = optimized_queryset.prefetch_related('secure_sessions')
        
        final_queryset = optimized_queryset.order_by('-date_joined')
        
        return final_queryset

    def get_serializer_class(self):
        if self.action == 'create':
            return UserCreateSerializer
        return UserSerializer

    def perform_create(self, serializer):
        user = self.request.user
        
        # The new UserCreateSerializer handles role assignment internally
        # We only need to ensure organization is properly set
        if user.is_superuser:
            # For superusers, organization comes from request data and is handled by serializer
            serializer.save()
        else:
            # For org admins, use their organization
            serializer.save(organization=user.organization)
    
    @swagger_auto_schema(
        method='post',
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'new_password': openapi.Schema(type=openapi.TYPE_STRING, description='New password for the user'),
                'must_change_password': openapi.Schema(type=openapi.TYPE_BOOLEAN, description='Whether user must change password on next login', default=False),
            },
            required=['new_password']
        ),
        responses={
            200: openapi.Response('Password assigned successfully'),
            400: openapi.Response('Bad request - invalid password or missing data'),
            403: openapi.Response('Forbidden - insufficient permissions'),
            500: openapi.Response('Internal server error')
        },
        tags=['User Management']
    )
    @action(detail=True, methods=['post'], permission_classes=[CanManageUserPasswords])
    @validate_response_type
    def assign_password(self, request, pk=None):
        """
        Allow Organization Admin to assign a new password to a user in their organization.
        Only Organization Admins and Superusers can use this endpoint.
        """
        target_user = self.get_object()
        requesting_user = request.user
        
        # Validate that the requesting user can assign passwords to this target user
        if not requesting_user.is_superuser:
            # Organization Admin can only assign passwords within their organization
            if not requesting_user.organization or requesting_user.organization != target_user.organization:
                return Response(
                    {'error': 'You can only assign passwords to users in your organization.'}, 
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Check if requesting user is Organization Admin
            if not requesting_user.role or requesting_user.role.name != 'Organization Admin':
                return Response(
                    {'error': 'Only Organization Admins can assign passwords.'}, 
                    status=status.HTTP_403_FORBIDDEN
                )
        
        # Get new password from request
        new_password = request.data.get('new_password')
        if not new_password:
            return Response(
                {'error': 'new_password is required.'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Enhanced password validation using policy
        from .password_policy import PasswordPolicy, PasswordHistoryManager
        
        # Validate password against organization policy
        validation_result = PasswordPolicy.validate_password(
            new_password, 
            user=target_user, 
            organization_id=target_user.organization.id if target_user.organization else None
        )
        
        if not validation_result['is_valid']:
            return Response(
                {
                    'error': 'Password does not meet policy requirements',
                    'details': validation_result['errors'],
                    'policy': validation_result['policy']
                }, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check password history to prevent reuse
        if PasswordHistoryManager.check_password_reuse(target_user, new_password):
            return Response(
                {'error': 'Password was recently used. Please choose a different password.'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            with transaction.atomic():
                # Store old password hash for history
                old_password_hash = target_user.password
                
                # Set the new password
                target_user.set_password(new_password)
                target_user.must_change_password = request.data.get('must_change_password', False)
                target_user.save(update_fields=['password', 'must_change_password'])
                
                # Add old password to history
                if old_password_hash:
                    PasswordHistoryManager.add_password_to_history(target_user, old_password_hash)
                
                # Update password expiration tracking
                password_expiration, created = PasswordExpiration.objects.get_or_create(
                    user=target_user
                )
                password_expiration.update_password_changed()
            
            # Log the password assignment
            security_logger.info(
                f"Password assigned to user {target_user.email} by {requesting_user.email}"
            )
            
            # Send notification email to the target user
            self._send_password_assigned_email(target_user, requesting_user, new_password)
            
            # Get password strength score
            strength_score = PasswordPolicy.get_password_strength_score(
                new_password, 
                user=target_user,
                organization_id=target_user.organization.id if target_user.organization else None
            )
            
            return Response({
                'message': f'Password successfully assigned to {target_user.first_name} {target_user.last_name}',
                'user_notified': True,
                'password_strength_score': strength_score,
                'must_change_password': target_user.must_change_password
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            security_logger.error(
                f"Failed to assign password to {target_user.email} by {requesting_user.email}: {str(e)}"
            )
            return Response(
                {'error': 'Failed to assign password. Please try again.'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['post'], url_path='generate-password')
    @validate_response_type
    def generate_secure_password(self, request):
        """
        Generate a secure password that meets organization policy
        """
        user = request.user
        organization_id = None
        
        if user.is_superuser:
            # Super admin can specify organization
            org_id = request.data.get('organization_id')
            if org_id:
                organization_id = org_id
        else:
            # Use requesting user's organization
            organization_id = user.organization.id if user.organization else None
        
        length = request.data.get('length', 12)
        try:
            length = int(length)
            if length < 8 or length > 50:
                length = 12
        except (ValueError, TypeError):
            length = 12
        
        from .password_policy import PasswordPolicy
        
        try:
            secure_password = PasswordPolicy.generate_secure_password(
                organization_id=organization_id,
                length=length
            )
            
            strength_score = PasswordPolicy.get_password_strength_score(
                secure_password,
                organization_id=organization_id
            )
            
            return Response({
                'password': secure_password,
                'strength_score': strength_score,
                'length': len(secure_password)
            })
            
        except Exception as e:
            security_logger.error(f"Failed to generate secure password: {str(e)}")
            return Response(
                {'error': 'Failed to generate secure password'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['get'], url_path='password-policy')
    @validate_response_type
    def get_password_policy(self, request):
        """
        Get password policy for the organization
        """
        user = request.user
        organization_id = None
        
        if user.is_superuser:
            # Super admin can specify organization
            org_id = request.query_params.get('organization_id')
            if org_id:
                organization_id = org_id
        else:
            # Use requesting user's organization
            organization_id = user.organization.id if user.organization else None
        
        from .password_policy import PasswordPolicy
        
        policy = PasswordPolicy.get_policy_for_organization(organization_id)
        
        return Response({
            'policy': policy,
            'organization_id': organization_id
        })
    
    @action(detail=True, methods=['get'], url_path='password-status')
    @validate_response_type
    def get_password_status(self, request, pk=None):
        """
        Get password expiration status for a user
        """
        target_user = self.get_object()
        requesting_user = request.user
        
        # Security check: ensure user can view this information
        if not requesting_user.is_superuser:
            if not requesting_user.organization or requesting_user.organization != target_user.organization:
                return Response(
                    {'error': 'You can only view password status for users in your organization.'}, 
                    status=status.HTTP_403_FORBIDDEN
                )
            
            if not requesting_user.role or requesting_user.role.name != 'Organization Admin':
                return Response(
                    {'error': 'Only Organization Admins can view password status.'}, 
                    status=status.HTTP_403_FORBIDDEN
                )
        
        from .password_policy import PasswordPolicy
        
        expiration_info = PasswordPolicy.check_password_expiration(target_user)
        
        return Response({
            'user_id': target_user.id,
            'user_email': target_user.email,
            'password_status': expiration_info,
            'must_change_password': target_user.must_change_password
        })
    
    @action(detail=False, methods=['post'], url_path='bulk-password-reset')
    @validate_response_type
    def bulk_password_reset(self, request):
        """
        Reset passwords for multiple users (Organization Admin only)
        """
        user_ids = request.data.get('user_ids', [])
        if not user_ids:
            return Response(
                {'error': 'No user IDs provided'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        requesting_user = request.user
        organization = requesting_user.organization
        
        if not organization and not requesting_user.is_superuser:
            return Response(
                {'error': 'User must belong to an organization'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Security check
        if not requesting_user.is_superuser:
            if not requesting_user.role or requesting_user.role.name != 'Organization Admin':
                return Response(
                    {'error': 'Only Organization Admins can perform bulk password reset'}, 
                    status=status.HTTP_403_FORBIDDEN
                )
        
        from .password_policy import PasswordPolicy, PasswordHistoryManager
        
        successful_resets = []
        failed_resets = []
        
        with transaction.atomic():
            for user_id in user_ids:
                try:
                    target_user = User.objects.get(id=user_id)
                    
                    # Security check: ensure user can reset password for this target user
                    if not requesting_user.is_superuser:
                        if target_user.organization != organization:
                            failed_resets.append({
                                'user_id': user_id,
                                'error': 'Cannot reset password for users outside your organization'
                            })
                            continue
                    
                    # Generate secure password
                    new_password = PasswordPolicy.generate_secure_password(
                        organization_id=target_user.organization.id if target_user.organization else None
                    )
                    
                    # Store old password hash for history
                    old_password_hash = target_user.password
                    
                    # Set the new password
                    target_user.set_password(new_password)
                    target_user.must_change_password = True
                    target_user.save(update_fields=['password', 'must_change_password'])
                    
                    # Add old password to history
                    if old_password_hash:
                        PasswordHistoryManager.add_password_to_history(target_user, old_password_hash)
                    
                    # Update password expiration tracking
                    password_expiration, created = PasswordExpiration.objects.get_or_create(
                        user=target_user
                    )
                    password_expiration.update_password_changed()
                    
                    # Send notification email
                    self._send_password_assigned_email(target_user, requesting_user, new_password)
                    
                    successful_resets.append({
                        'user_id': user_id,
                        'user_email': target_user.email,
                        'password_sent': True
                    })
                    
                except User.DoesNotExist:
                    failed_resets.append({
                        'user_id': user_id,
                        'error': f'User with id {user_id} not found'
                    })
                except Exception as e:
                    failed_resets.append({
                        'user_id': user_id,
                        'error': str(e)
                    })
        
        return Response({
            'successful_resets': successful_resets,
            'failed_resets': failed_resets,
            'summary': {
                'total': len(user_ids),
                'successful': len(successful_resets),
                'failed': len(failed_resets)
            }
        })
    
    def _send_password_assigned_email(self, target_user, assigning_admin, new_password):
        """Send email notification to user about their new password"""
        subject = "Your Password Has Been Updated"
        message = f"""
Dear {target_user.first_name},

Your password has been updated by your Organization Admin ({assigning_admin.first_name} {assigning_admin.last_name}).

Your new temporary password is: {new_password}

For security reasons, please log in and change this password immediately.

Best regards,
PRS System
        """
        
        try:
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [target_user.email],
                fail_silently=False,
            )
        except Exception as e:
            security_logger.error(
                f"Failed to send password assignment email to {target_user.email}: {str(e)}"
            )
