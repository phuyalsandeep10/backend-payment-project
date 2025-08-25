"""
User Relationship Service - Task 2.3.2

Service to reduce User model coupling by abstracting relationships through composition patterns.
This helps reduce the 35+ relationships on the User model.
"""

from typing import Dict, List, Optional, Any, Tuple
from django.db import transaction
from django.db.models import Q, Count, Prefetch
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

from .base_service import BaseService, ServiceResult
import logging

User = get_user_model()
logger = logging.getLogger(__name__)


class UserRelationshipService(BaseService):
    """
    Service for managing user relationships and reducing direct model coupling
    Task 2.3.2: Composition patterns for user operations
    """
    
    def get_user_deals(self, user_id: int = None, filters: Dict[str, Any] = None) -> ServiceResult:
        """
        Get deals associated with a user through composition pattern
        Reduces direct user.deals relationship usage
        """
        try:
            target_user = self._get_target_user(user_id)
            if not target_user:
                return self.create_error_result("User not found or access denied")
            
            # Import here to avoid circular imports
            from deals.models import Deal
            
            # Base query - deals created by user or assigned to user's organization
            deals_query = Deal.objects.filter(
                Q(created_by=target_user) | 
                Q(organization=target_user.organization)
            ).select_related('client', 'created_by', 'organization')
            
            # Apply filters
            if filters:
                if filters.get('status'):
                    deals_query = deals_query.filter(verification_status=filters['status'])
                if filters.get('date_from'):
                    deals_query = deals_query.filter(deal_date__gte=filters['date_from'])
                if filters.get('date_to'):  
                    deals_query = deals_query.filter(deal_date__lte=filters['date_to'])
            
            deals = deals_query.order_by('-created_at')
            
            # Serialize deal data
            deals_data = []
            for deal in deals:
                deals_data.append({
                    'id': deal.id,
                    'deal_name': deal.deal_name,
                    'deal_value': float(deal.deal_value),
                    'status': deal.verification_status,
                    'payment_status': deal.payment_status,
                    'client_name': deal.client.client_name if deal.client else None,
                    'created_at': deal.created_at.isoformat(),
                    'is_creator': deal.created_by_id == target_user.id
                })
            
            return self.create_result(
                success=True,
                data={
                    'user_id': target_user.id,
                    'deals': deals_data,
                    'total_deals': len(deals_data),
                    'created_deals': sum(1 for d in deals_data if d['is_creator']),
                    'organization_deals': sum(1 for d in deals_data if not d['is_creator'])
                }
            )
            
        except Exception as e:
            logger.error(f"Error getting user deals: {str(e)}")
            return self.create_error_result(f"Failed to get user deals: {str(e)}")
    
    def get_user_team_info(self, user_id: int = None) -> ServiceResult:
        """
        Get user team information through service composition
        Reduces direct user.team relationship usage
        """
        try:
            target_user = self._get_target_user(user_id)
            if not target_user:
                return self.create_error_result("User not found or access denied")
            
            # Import here to avoid circular imports
            from team.models import Team
            
            team_info = {
                'user_id': target_user.id,
                'has_team': bool(target_user.team_id),
                'team_data': None,
                'team_members': [],
                'team_role': None
            }
            
            if target_user.team_id:
                team = Team.objects.select_related('organization').prefetch_related(
                    Prefetch('assigned_users', queryset=User.objects.select_related('role'))
                ).get(id=target_user.team_id)
                
                team_info['team_data'] = {
                    'id': team.id,
                    'name': team.name,
                    'description': team.description,
                    'organization': team.organization.name if team.organization else None
                }
                
                # Get team members (composition instead of direct relationship)
                team_members = []
                for member in team.assigned_users.all():
                    team_members.append({
                        'id': member.id,
                        'name': member.get_full_name() or member.email,
                        'email': member.email,
                        'role': member.role.name if member.role else None,
                        'is_current_user': member.id == target_user.id
                    })
                
                team_info['team_members'] = team_members
                team_info['team_role'] = 'member'  # Could be enhanced with specific team roles
            
            return self.create_result(success=True, data=team_info)
            
        except Exception as e:
            logger.error(f"Error getting user team info: {str(e)}")
            return self.create_error_result(f"Failed to get team info: {str(e)}")
    
    def get_user_permissions_summary(self, user_id: int = None) -> ServiceResult:
        """
        Get user permissions through composition instead of direct relationships
        Task 2.3.2: Reduce permission relationship coupling
        """
        try:
            target_user = self._get_target_user(user_id)
            if not target_user:
                return self.create_error_result("User not found or access denied")
            
            permissions_info = {
                'user_id': target_user.id,
                'role_info': None,
                'organization_role': None,
                'permissions': [],
                'permission_count': 0
            }
            
            # Get role information through composition
            if target_user.role:
                permissions_info['role_info'] = {
                    'id': target_user.role.id,
                    'name': target_user.role.name,
                    'description': getattr(target_user.role, 'description', '')
                }
                
                # Get permissions through role (instead of direct user permissions)
                if hasattr(target_user.role, 'permissions'):
                    role_permissions = target_user.role.permissions.all()
                    for perm in role_permissions:
                        permissions_info['permissions'].append({
                            'id': perm.id,
                            'name': perm.name,
                            'codename': perm.codename,
                            'content_type': perm.content_type.name if perm.content_type else None
                        })
            
            permissions_info['permission_count'] = len(permissions_info['permissions'])
            
            # Organization role info (composition pattern)
            if target_user.organization:
                permissions_info['organization_role'] = {
                    'organization_name': target_user.organization.name,
                    'is_admin': target_user.role.name.lower() in ['admin', 'super admin', 'org admin'] if target_user.role else False,
                    'organization_id': target_user.organization.id
                }
            
            return self.create_result(success=True, data=permissions_info)
            
        except Exception as e:
            logger.error(f"Error getting user permissions: {str(e)}")
            return self.create_error_result(f"Failed to get permissions: {str(e)}")
    
    def get_user_activity_summary(self, user_id: int = None, days: int = 30) -> ServiceResult:
        """
        Get user activity summary through composition patterns
        Reduces need for multiple direct relationships
        """
        try:
            target_user = self._get_target_user(user_id)
            if not target_user:
                return self.create_error_result("User not found or access denied")
            
            from datetime import timedelta
            from django.utils import timezone
            from deals.models import Deal, Payment
            
            # Calculate date range
            end_date = timezone.now()
            start_date = end_date - timedelta(days=days)
            
            # Activity summary through composition
            activity = {
                'user_id': target_user.id,
                'period_days': days,
                'deals_created': 0,
                'payments_processed': 0,
                'last_login': target_user.last_login.isoformat() if target_user.last_login else None,
                'login_count': getattr(target_user, 'login_count', 0),
                'is_active': target_user.is_active,
                'recent_activity': []
            }
            
            # Get deals created in period (composition instead of user.created_deals)
            recent_deals = Deal.objects.filter(
                created_by=target_user,
                created_at__gte=start_date
            ).order_by('-created_at')
            
            activity['deals_created'] = recent_deals.count()
            
            # Get payments in deals user is involved with
            user_deal_ids = Deal.objects.filter(
                Q(created_by=target_user) | Q(organization=target_user.organization)
            ).values_list('id', flat=True)
            
            recent_payments = Payment.objects.filter(
                deal_id__in=user_deal_ids,
                created_at__gte=start_date
            ).count()
            
            activity['payments_processed'] = recent_payments
            
            # Recent activity log (composition pattern)
            recent_activities = []
            for deal in recent_deals[:5]:  # Last 5 deals
                recent_activities.append({
                    'type': 'deal_created',
                    'description': f"Created deal: {deal.deal_name}",
                    'timestamp': deal.created_at.isoformat(),
                    'deal_id': deal.id
                })
            
            activity['recent_activity'] = recent_activities
            
            return self.create_result(success=True, data=activity)
            
        except Exception as e:
            logger.error(f"Error getting user activity: {str(e)}")
            return self.create_error_result(f"Failed to get activity: {str(e)}")
    
    def update_user_relationships(self, user_id: int, relationship_updates: Dict[str, Any]) -> ServiceResult:
        """
        Update user relationships through service composition
        Task 2.3.2: Centralized relationship management
        """
        try:
            target_user = self._get_target_user(user_id)
            if not target_user:
                return self.create_error_result("User not found or access denied")
            
            updated_fields = []
            
            with transaction.atomic():
                # Update team assignment
                if 'team_id' in relationship_updates:
                    team_id = relationship_updates['team_id']
                    if team_id:
                        # Validate team belongs to same organization
                        from team.models import Team
                        try:
                            team = Team.objects.get(
                                id=team_id, 
                                organization=target_user.organization
                            )
                            target_user.team = team
                            updated_fields.append('team')
                        except Team.DoesNotExist:
                            return self.create_error_result("Team not found or access denied")
                    else:
                        target_user.team = None
                        updated_fields.append('team')
                
                # Update role assignment
                if 'role_id' in relationship_updates:
                    role_id = relationship_updates['role_id']
                    if role_id:
                        from permissions.models import Role
                        try:
                            role = Role.objects.get(id=role_id)
                            target_user.role = role
                            updated_fields.append('role')
                        except Role.DoesNotExist:
                            return self.create_error_result("Role not found")
                    else:
                        target_user.role = None
                        updated_fields.append('role')
                
                # Save changes
                if updated_fields:
                    target_user.save(update_fields=updated_fields + ['updated_at'] if hasattr(target_user, 'updated_at') else updated_fields)
                
                logger.info(f"Updated user relationships for {target_user.email}: {updated_fields}")
                
                return self.create_result(
                    success=True,
                    data={
                        'user_id': target_user.id,
                        'updated_fields': updated_fields,
                        'current_team_id': target_user.team_id,
                        'current_role_id': target_user.role_id
                    }
                )
                
        except Exception as e:
            logger.error(f"Error updating user relationships: {str(e)}")
            return self.create_error_result(f"Failed to update relationships: {str(e)}")
    
    def _get_target_user(self, user_id: int = None) -> Optional[User]:
        """Get target user with organization validation"""
        if user_id is None:
            return self.user
        
        if user_id == self.user.id:
            return self.user
        
        # Only allow access to users in same organization
        try:
            return User.objects.select_related('role', 'organization', 'team').get(
                id=user_id,
                organization=self.organization
            )
        except User.DoesNotExist:
            return None

