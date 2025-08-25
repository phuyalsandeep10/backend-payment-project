from django.shortcuts import render
from rest_framework import viewsets, generics, permissions
from rest_framework.response import Response
from .models import Permission, Role, Organization
from .serializers import PermissionSerializer, RoleSerializer
from .permissions import IsOrgAdminOrSuperAdmin, CanManageRoles
from apps.authentication.models import User
from django.db.models import Q, Count
from rest_framework import serializers
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework import status
from django.db import IntegrityError, transaction
from django.core.cache import cache
from django.utils import timezone
import logging

# Performance logger
performance_logger = logging.getLogger('performance')

# Create your views here.

class PermissionListView(generics.ListAPIView):
    """
    List all available permissions.  
    Accessible to superusers **or** any user whose role has the `can_manage_roles` permission (i.e., Org-Admins).
    """
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer

    # Any authenticated user can read the list (harmless metadata)
    permission_classes = [permissions.IsAuthenticated]

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        
        # Group permissions by content_type for the UI
        grouped_data = {}
        for item in serializer.data:
            content_type = item['content_type']
            if content_type not in grouped_data:
                grouped_data[content_type] = []
            grouped_data[content_type].append(item)
            
        return Response(grouped_data)

class RoleViewSet(viewsets.ModelViewSet):
    """
    Enhanced ViewSet for managing Roles with bulk operations and caching.
    Requires 'can_manage_roles' permission.
    """
    serializer_class = RoleSerializer
    permission_classes = [permissions.IsAuthenticated, CanManageRoles]
    pagination_class = None
    
    def update(self, request, *args, **kwargs):
        """Debug role update requests"""
        print(f"🔧 DEBUG - Role update request:")
        print(f"  Method: {request.method}")
        print(f"  User: {request.user}")
        print(f"  Role ID: {kwargs.get('pk')}")
        print(f"  Request data: {request.data}")
        print(f"  Content type: {request.content_type}")
        
        # Call parent update method
        return super().update(request, *args, **kwargs)
    
    def partial_update(self, request, *args, **kwargs):
        """Debug role partial update requests"""
        print(f"🔧 DEBUG - Role partial update request:")
        print(f"  Method: {request.method}")
        print(f"  User: {request.user}")
        print(f"  Role ID: {kwargs.get('pk')}")
        print(f"  Request data: {request.data}")
        print(f"  Content type: {request.content_type}")
        
        # Call parent partial_update method
        return super().partial_update(request, *args, **kwargs)

    def get_queryset(self):
        """
        Users can only see roles within their own organization.
        Uses caching for better performance.
        """
        # Handle swagger schema generation
        if getattr(self, 'swagger_fake_view', False):
            return Role.objects.none()
            
        user = self.request.user
        if not user.is_authenticated or not user.organization:
            return Role.objects.none()
        
        # Use caching for role queries
        cache_key = f"org_roles_{user.organization.id}"
        cached_roles = cache.get(cache_key)
        
        if cached_roles is None:
            queryset = Role.objects.filter(
                organization=user.organization
            ).prefetch_related('permissions').annotate(
                user_count=Count('users')
            )
            
            # Cache for 15 minutes
            cache.set(cache_key, list(queryset), 900)
            performance_logger.info(f"Cached roles for organization {user.organization.name}")
            return queryset
        else:
            performance_logger.info(f"Using cached roles for organization {user.organization.name}")
            # Convert cached data back to queryset
            role_ids = [role.id for role in cached_roles]
            return Role.objects.filter(id__in=role_ids).prefetch_related('permissions')
    
    def list(self, request, *args, **kwargs):
        """Enhanced list with role usage analytics"""
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        
        # Return roles directly for frontend compatibility
        # Analytics can be accessed via separate endpoint if needed
        return Response(serializer.data)
    
    def _get_role_analytics(self, organization):
        """Get role usage analytics for the organization"""
        cache_key = f"role_analytics_{organization.id}"
        analytics = cache.get(cache_key)
        
        if analytics is None:
            total_users = User.objects.filter(organization=organization, is_active=True).count()
            
            role_stats = Role.objects.filter(organization=organization).annotate(
                user_count=Count('users', filter=Q(users__is_active=True))
            ).values('name', 'user_count')
            
            analytics = {
                'total_users': total_users,
                'role_distribution': list(role_stats),
                'most_used_role': max(role_stats, key=lambda x: x['user_count'])['name'] if role_stats else None,
                'unused_roles': [r['name'] for r in role_stats if r['user_count'] == 0],
                'last_updated': timezone.now().isoformat()
            }
            
            # Cache for 30 minutes
            cache.set(cache_key, analytics, 1800)
            
        return analytics

    def perform_create(self, serializer):
        user = self.request.user
        if user.is_superuser:
            # Super admins can create roles for any organization or system-wide
            # The organization ID can be passed in the request data
            org_id = self.request.data.get('organization')
            organization = None
            if org_id:
                try:
                    organization = Organization.objects.get(id=org_id)
                except Organization.DoesNotExist:
                    raise serializers.ValidationError({'organization': 'Organization not found.'})
            
            # Handle potential duplicate role creation
            try:
                serializer.save(organization=organization)
            except IntegrityError:
                # If role already exists, fetch and return the existing one
                role_name = serializer.validated_data.get('name')
                existing_role = Role.objects.get(name=role_name, organization=organization)
                # Update the serializer instance to return the existing role
                serializer.instance = existing_role
                
        else:
            # Org Admins can only create roles for their own organization.
            # Fail if they try to specify a different one.
            if 'organization' in self.request.data and self.request.data['organization'] is not None:
                raise serializers.ValidationError({
                    'organization': 'You do not have permission to create roles for other organizations.'
                })
            
            # Handle potential duplicate role creation
            try:
                serializer.save(organization=user.organization)
            except IntegrityError:
                # If role already exists, fetch and return the existing one
                role_name = serializer.validated_data.get('name')
                existing_role = Role.objects.get(name=role_name, organization=user.organization)
                # Update the serializer instance to return the existing role
                serializer.instance = existing_role
    
    @action(detail=False, methods=['post'], url_path='bulk-assign')
    def bulk_assign_roles(self, request):
        """
        Bulk assign roles to multiple users.
        Expected payload: {
            "assignments": [
                {"user_id": 1, "role_id": 2},
                {"user_id": 3, "role_id": 4}
            ]
        }
        """
        assignments = request.data.get('assignments', [])
        if not assignments:
            return Response(
                {'error': 'No assignments provided'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user = request.user
        organization = user.organization
        
        if not organization and not user.is_superuser:
            return Response(
                {'error': 'User must belong to an organization'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        successful_assignments = []
        failed_assignments = []
        
        with transaction.atomic():
            for assignment in assignments:
                try:
                    user_id = assignment.get('user_id')
                    role_id = assignment.get('role_id')
                    
                    if not user_id or not role_id:
                        failed_assignments.append({
                            'assignment': assignment,
                            'error': 'Missing user_id or role_id'
                        })
                        continue
                    
                    # Get the target user
                    target_user = User.objects.get(id=user_id)
                    
                    # Security check: ensure user can assign roles to this target user
                    if not user.is_superuser:
                        if target_user.organization != organization:
                            failed_assignments.append({
                                'assignment': assignment,
                                'error': 'Cannot assign roles to users outside your organization'
                            })
                            continue
                    
                    # Get the role
                    role = Role.objects.get(id=role_id)
                    
                    # Security check: ensure role belongs to the same organization
                    if not user.is_superuser:
                        if role.organization != organization:
                            failed_assignments.append({
                                'assignment': assignment,
                                'error': 'Cannot assign roles from other organizations'
                            })
                            continue
                    
                    # Assign the role
                    target_user.role = role
                    target_user.save(update_fields=['role'])
                    
                    successful_assignments.append({
                        'user_id': user_id,
                        'user_email': target_user.email,
                        'role_id': role_id,
                        'role_name': role.name
                    })
                    
                except User.DoesNotExist:
                    failed_assignments.append({
                        'assignment': assignment,
                        'error': f'User with id {user_id} not found'
                    })
                except Role.DoesNotExist:
                    failed_assignments.append({
                        'assignment': assignment,
                        'error': f'Role with id {role_id} not found'
                    })
                except Exception as e:
                    failed_assignments.append({
                        'assignment': assignment,
                        'error': str(e)
                    })
        
        # Invalidate role caches after bulk assignment
        if successful_assignments:
            self._invalidate_role_caches(organization)
        
        return Response({
            'successful_assignments': successful_assignments,
            'failed_assignments': failed_assignments,
            'summary': {
                'total': len(assignments),
                'successful': len(successful_assignments),
                'failed': len(failed_assignments)
            }
        })
    
    @action(detail=False, methods=['get'], url_path='usage-report')
    def role_usage_report(self, request):
        """
        Get detailed role usage report for the organization
        """
        user = request.user
        organization = user.organization
        
        if not organization and not user.is_superuser:
            return Response(
                {'error': 'User must belong to an organization'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get comprehensive role usage data
        roles_with_users = Role.objects.filter(
            organization=organization
        ).prefetch_related('users').annotate(
            active_user_count=Count('users', filter=Q(users__is_active=True)),
            total_user_count=Count('users')
        )
        
        report_data = []
        for role in roles_with_users:
            users_data = []
            for user in role.users.filter(is_active=True):
                users_data.append({
                    'id': user.id,
                    'email': user.email,
                    'name': user.get_full_name() or user.username,
                    'last_login': user.last_login,
                    'date_joined': user.date_joined
                })
            
            report_data.append({
                'role_id': role.id,
                'role_name': role.name,
                'active_user_count': role.active_user_count,
                'total_user_count': role.total_user_count,
                'users': users_data,
                'permissions_count': role.permissions.count()
            })
        
        return Response({
            'organization': organization.name,
            'report_date': timezone.now().isoformat(),
            'roles': report_data,
            'summary': {
                'total_roles': len(report_data),
                'total_active_users': sum(r['active_user_count'] for r in report_data),
                'roles_with_no_users': len([r for r in report_data if r['active_user_count'] == 0])
            }
        })
    
    def _invalidate_role_caches(self, organization):
        """Invalidate role-related caches for the organization"""
        cache_keys = [
            f"org_roles_{organization.id}",
            f"role_analytics_{organization.id}",
            f"role_permissions_{organization.id}"
        ]
        
        for key in cache_keys:
            cache.delete(key)
        
        performance_logger.info(f"Invalidated role caches for organization {organization.name}")

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_salesperson_role_id(request):
    """
    Returns the ID of the 'Salesperson' role within the user's organization.
    For Super Admins, allows specifying an organization via query parameter.
    """
    user = request.user
    
    # For Super Admins, allow specifying organization or use first available
    if user.is_superuser:
        org_id = request.query_params.get('organization')
        if org_id:
            try:
                organization = Organization.objects.get(id=org_id)
            except Organization.DoesNotExist:
                return Response({"error": "Organization not found"}, status=status.HTTP_404_NOT_FOUND)
        else:
            # Use the first available organization
            organization = Organization.objects.first()
            if not organization:
                return Response({"error": "No organizations found"}, status=status.HTTP_404_NOT_FOUND)
    else:
        # Regular users must belong to an organization
        if not user.organization:
            return Response({"error": "User does not belong to an organization"}, status=status.HTTP_400_BAD_REQUEST)
        organization = user.organization
    
    try:
        role = Role.objects.get(name="Salesperson", organization=organization)
        return Response({"id": role.id})
    except Role.DoesNotExist:
        return Response({"error": f"Salesperson role not found in organization '{organization.name}'"}, status=status.HTTP_404_NOT_FOUND)
