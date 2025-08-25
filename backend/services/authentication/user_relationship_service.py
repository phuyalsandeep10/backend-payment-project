"""
User Relationship Service - Task 2.3.2

Reduces User model coupling by managing relationships through service interfaces
instead of direct model access. Implements composition pattern for relationships.
"""

from services.base_service import BaseService
from typing import Dict, Optional, Any, List, Union
from django.contrib.auth import get_user_model
from django.db import models
from django.core.paginator import Paginator
import logging

User = get_user_model()
logger = logging.getLogger(__name__)


class UserRelationshipService(BaseService):
    """
    Service for managing user relationships without tight coupling.
    Provides controlled access to user-related data through service interfaces.
    """

    def __init__(self, user=None, organization=None, **kwargs):
        super().__init__(user=user, organization=organization)

    def get_service_name(self) -> str:
        """Return the name of this service for logging and identification"""
        return "user_relationship_service"

    def get_user_related_counts(self, user_id: int) -> Dict[str, Any]:
        """
        Get counts of all user-related entities without tight coupling.
        
        Args:
            user_id: User ID
            
        Returns:
            dict: Counts of related entities
        """
        try:
            user = User.objects.get(id=user_id)
            counts = {
                'user_id': user_id,
                'relationships': {}
            }
            
            # Define relationship mappings to handle gracefully
            relationship_mappings = {
                # Security relationships
                'sessions': ('usersession_set', 'active_sessions'),
                'security_events': ('security_events', 'security_events'),
                'otp_tokens': ('otp_tokens', 'otp_tokens'),
                'password_history': ('password_history', 'password_changes'),
                
                # Business relationships
                'clients_created': ('clients_created', 'created_clients'),
                'clients_updated': ('clients_updated', 'updated_clients'),
                'deals': ('deals', 'assigned_deals'),
                'commissions': ('commissions', 'commission_records'),
                'created_commissions': ('created_commissions', 'created_commissions'),
                'payments': ('payments', 'payment_records'),
                
                # Administrative relationships
                'created_organizations': ('created_organizations', 'organizations_created'),
                'audit_trails': ('audittrail_set', 'audit_entries'),
                'security_alerts': ('assigned_security_alerts', 'assigned_alerts'),
                'compliance_reports': ('compliancereport_set', 'compliance_reports')
            }
            
            # Get counts safely
            for attr_name, (related_name, display_name) in relationship_mappings.items():
                try:
                    if hasattr(user, related_name):
                        related_manager = getattr(user, related_name)
                        if hasattr(related_manager, 'count'):
                            counts['relationships'][display_name] = related_manager.count()
                        else:
                            counts['relationships'][display_name] = len(related_manager.all())
                except Exception as e:
                    logger.debug(f"Could not get count for {related_name}: {e}")
                    counts['relationships'][display_name] = 0
            
            # Calculate total relationships
            counts['total_relationships'] = sum(counts['relationships'].values())
            
            return counts
            
        except User.DoesNotExist:
            return {'error': 'User not found'}
        except Exception as e:
            logger.error(f"Error getting user related counts {user_id}: {e}")
            return {'error': 'Failed to get relationship counts'}

    def get_user_activity_timeline(self, user_id: int, limit: int = 50,
                                  activity_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Get user activity timeline across all relationships.
        
        Args:
            user_id: User ID
            limit: Maximum activities to return
            activity_types: Optional filter for activity types
            
        Returns:
            dict: Activity timeline
        """
        try:
            user = User.objects.get(id=user_id)
            activities = []
            
            # Collect activities from different sources
            activity_sources = [
                ('sessions', 'usersession_set', 'created_at', self._format_session_activity),
                ('security_events', 'security_events', 'created_at', self._format_security_activity),
                ('deals', 'deals', 'created_at', self._format_deal_activity),
                ('commissions', 'commissions', 'created_at', self._format_commission_activity),
            ]
            
            for activity_type, related_name, date_field, formatter in activity_sources:
                if activity_types and activity_type not in activity_types:
                    continue
                
                try:
                    if hasattr(user, related_name):
                        related_objects = getattr(user, related_name).order_by(f'-{date_field}')[:limit//len(activity_sources)]
                        
                        for obj in related_objects:
                            activity = formatter(obj, activity_type)
                            if activity:
                                activities.append(activity)
                                
                except Exception as e:
                    logger.debug(f"Could not get activities from {related_name}: {e}")
            
            # Sort by timestamp
            activities.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            
            return {
                'user_id': user_id,
                'activities': activities[:limit],
                'total_collected': len(activities),
                'limited_to': limit
            }
            
        except User.DoesNotExist:
            return {'error': 'User not found'}
        except Exception as e:
            logger.error(f"Error getting user activity timeline {user_id}: {e}")
            return {'error': 'Failed to get activity timeline'}

    def get_relationship_summary(self, user_id: int, relationship_type: str) -> Dict[str, Any]:
        """
        Get detailed summary of specific relationship type.
        
        Args:
            user_id: User ID
            relationship_type: Type of relationship to summarize
            
        Returns:
            dict: Relationship summary
        """
        try:
            user = User.objects.get(id=user_id)
            
            # Map relationship types to handlers
            relationship_handlers = {
                'sessions': self._get_sessions_summary,
                'security': self._get_security_summary,
                'business': self._get_business_summary,
                'administrative': self._get_administrative_summary
            }
            
            if relationship_type not in relationship_handlers:
                return {'error': f'Unknown relationship type: {relationship_type}'}
            
            return relationship_handlers[relationship_type](user)
            
        except User.DoesNotExist:
            return {'error': 'User not found'}
        except Exception as e:
            logger.error(f"Error getting relationship summary {relationship_type} for user {user_id}: {e}")
            return {'error': 'Failed to get relationship summary'}

    def cleanup_inactive_relationships(self, user_id: int, 
                                     relationship_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Clean up inactive or expired relationships for user.
        
        Args:
            user_id: User ID
            relationship_types: Optional filter for relationship types
            
        Returns:
            dict: Cleanup result
        """
        try:
            user = User.objects.get(id=user_id)
            cleanup_results = {}
            
            # Default relationship types to clean
            if not relationship_types:
                relationship_types = ['expired_sessions', 'old_security_events', 'completed_otp_tokens']
            
            # Clean up expired sessions
            if 'expired_sessions' in relationship_types:
                cleanup_results['expired_sessions'] = self._cleanup_expired_sessions(user)
            
            # Clean up old security events
            if 'old_security_events' in relationship_types:
                cleanup_results['old_security_events'] = self._cleanup_old_security_events(user)
            
            # Clean up completed OTP tokens
            if 'completed_otp_tokens' in relationship_types:
                cleanup_results['completed_otp_tokens'] = self._cleanup_completed_otp_tokens(user)
            
            return {
                'user_id': user_id,
                'cleanup_results': cleanup_results,
                'success': True
            }
            
        except User.DoesNotExist:
            return {'error': 'User not found'}
        except Exception as e:
            logger.error(f"Error cleaning up relationships for user {user_id}: {e}")
            return {'error': 'Cleanup failed'}

    def transfer_user_relationships(self, source_user_id: int, target_user_id: int,
                                   relationship_types: List[str]) -> Dict[str, Any]:
        """
        Transfer relationships from one user to another.
        Useful for user merging or reassignment scenarios.
        
        Args:
            source_user_id: Source user ID
            target_user_id: Target user ID
            relationship_types: Types of relationships to transfer
            
        Returns:
            dict: Transfer result
        """
        try:
            source_user = User.objects.get(id=source_user_id)
            target_user = User.objects.get(id=target_user_id)
            
            transfer_results = {}
            
            # Define transferable relationships
            transferable_mappings = {
                'deals': 'deals',
                'clients': 'clients_created', 
                'commissions': 'commissions',
                'audit_trails': 'audittrail_set'
            }
            
            for rel_type in relationship_types:
                if rel_type in transferable_mappings:
                    result = self._transfer_relationship(
                        source_user, target_user, 
                        transferable_mappings[rel_type], rel_type
                    )
                    transfer_results[rel_type] = result
            
            return {
                'source_user_id': source_user_id,
                'target_user_id': target_user_id,
                'transfer_results': transfer_results,
                'success': True
            }
            
        except User.DoesNotExist:
            return {'error': 'Source or target user not found'}
        except Exception as e:
            logger.error(f"Error transferring relationships: {e}")
            return {'error': 'Transfer failed'}

    def _format_session_activity(self, session, activity_type: str) -> Optional[Dict[str, Any]]:
        """Format session activity for timeline"""
        try:
            return {
                'type': activity_type,
                'action': 'login',
                'timestamp': getattr(session, 'created_at', None),
                'details': {
                    'ip_address': getattr(session, 'ip_address', 'unknown'),
                    'device': getattr(session, 'device_info', {})
                }
            }
        except Exception:
            return None

    def _format_security_activity(self, event, activity_type: str) -> Optional[Dict[str, Any]]:
        """Format security activity for timeline"""
        try:
            return {
                'type': activity_type,
                'action': getattr(event, 'event_type', 'unknown'),
                'timestamp': getattr(event, 'created_at', None),
                'details': {
                    'risk_level': getattr(event, 'risk_level', 'low'),
                    'description': getattr(event, 'description', '')
                }
            }
        except Exception:
            return None

    def _format_deal_activity(self, deal, activity_type: str) -> Optional[Dict[str, Any]]:
        """Format deal activity for timeline"""
        try:
            return {
                'type': activity_type,
                'action': 'deal_created',
                'timestamp': getattr(deal, 'created_at', None),
                'details': {
                    'deal_id': getattr(deal, 'id', None),
                    'amount': str(getattr(deal, 'amount', 0)),
                    'status': getattr(deal, 'status', 'unknown')
                }
            }
        except Exception:
            return None

    def _format_commission_activity(self, commission, activity_type: str) -> Optional[Dict[str, Any]]:
        """Format commission activity for timeline"""
        try:
            return {
                'type': activity_type,
                'action': 'commission_earned',
                'timestamp': getattr(commission, 'created_at', None),
                'details': {
                    'amount': str(getattr(commission, 'total', 0)),
                    'period': getattr(commission, 'period', 'unknown')
                }
            }
        except Exception:
            return None

    def _get_sessions_summary(self, user: User) -> Dict[str, Any]:
        """Get sessions relationship summary"""
        try:
            summary = {'type': 'sessions', 'data': {}}
            
            if hasattr(user, 'usersession_set'):
                sessions = user.usersession_set.all()
                summary['data'] = {
                    'total_sessions': sessions.count(),
                    'active_sessions': sessions.filter(is_active=True).count(),
                    'recent_sessions': list(sessions.order_by('-created_at')[:5].values(
                        'id', 'ip_address', 'created_at', 'is_active'
                    ))
                }
            
            return summary
        except Exception as e:
            logger.error(f"Error getting sessions summary: {e}")
            return {'type': 'sessions', 'error': 'Failed to get summary'}

    def _get_security_summary(self, user: User) -> Dict[str, Any]:
        """Get security relationship summary"""
        try:
            summary = {'type': 'security', 'data': {}}
            
            # Combine security-related counts
            security_counts = {}
            security_relations = ['security_events', 'otp_tokens', 'password_history']
            
            for relation in security_relations:
                if hasattr(user, relation):
                    try:
                        count = getattr(user, relation).count()
                        security_counts[relation] = count
                    except Exception:
                        security_counts[relation] = 0
            
            summary['data'] = security_counts
            return summary
            
        except Exception as e:
            logger.error(f"Error getting security summary: {e}")
            return {'type': 'security', 'error': 'Failed to get summary'}

    def _get_business_summary(self, user: User) -> Dict[str, Any]:
        """Get business relationship summary"""
        try:
            summary = {'type': 'business', 'data': {}}
            
            business_counts = {}
            business_relations = ['deals', 'commissions', 'clients_created', 'payments']
            
            for relation in business_relations:
                if hasattr(user, relation):
                    try:
                        count = getattr(user, relation).count()
                        business_counts[relation] = count
                    except Exception:
                        business_counts[relation] = 0
            
            summary['data'] = business_counts
            return summary
            
        except Exception as e:
            logger.error(f"Error getting business summary: {e}")
            return {'type': 'business', 'error': 'Failed to get summary'}

    def _get_administrative_summary(self, user: User) -> Dict[str, Any]:
        """Get administrative relationship summary"""
        try:
            summary = {'type': 'administrative', 'data': {}}
            
            admin_counts = {}
            admin_relations = ['created_organizations', 'audittrail_set', 'assigned_security_alerts']
            
            for relation in admin_relations:
                if hasattr(user, relation):
                    try:
                        count = getattr(user, relation).count()
                        admin_counts[relation] = count
                    except Exception:
                        admin_counts[relation] = 0
            
            summary['data'] = admin_counts
            return summary
            
        except Exception as e:
            logger.error(f"Error getting administrative summary: {e}")
            return {'type': 'administrative', 'error': 'Failed to get summary'}

    def _cleanup_expired_sessions(self, user: User) -> Dict[str, Any]:
        """Clean up expired user sessions"""
        try:
            if hasattr(user, 'usersession_set'):
                from django.utils import timezone
                expired_sessions = user.usersession_set.filter(
                    expires_at__lt=timezone.now(),
                    is_active=True
                )
                count = expired_sessions.count()
                expired_sessions.update(is_active=False)
                return {'cleaned': count}
            return {'cleaned': 0}
        except Exception as e:
            logger.error(f"Error cleaning expired sessions: {e}")
            return {'error': 'Cleanup failed'}

    def _cleanup_old_security_events(self, user: User) -> Dict[str, Any]:
        """Clean up old security events"""
        try:
            if hasattr(user, 'security_events'):
                from django.utils import timezone
                from datetime import timedelta
                
                # Keep events for 90 days
                cutoff_date = timezone.now() - timedelta(days=90)
                old_events = user.security_events.filter(created_at__lt=cutoff_date)
                count = old_events.count()
                old_events.delete()
                return {'cleaned': count}
            return {'cleaned': 0}
        except Exception as e:
            logger.error(f"Error cleaning old security events: {e}")
            return {'error': 'Cleanup failed'}

    def _cleanup_completed_otp_tokens(self, user: User) -> Dict[str, Any]:
        """Clean up completed OTP tokens"""
        try:
            if hasattr(user, 'otp_tokens'):
                completed_tokens = user.otp_tokens.filter(is_used=True)
                count = completed_tokens.count()
                completed_tokens.delete()
                return {'cleaned': count}
            return {'cleaned': 0}
        except Exception as e:
            logger.error(f"Error cleaning completed OTP tokens: {e}")
            return {'error': 'Cleanup failed'}

    def _transfer_relationship(self, source_user: User, target_user: User, 
                             relation_name: str, relation_type: str) -> Dict[str, Any]:
        """Transfer specific relationship from source to target user"""
        try:
            if hasattr(source_user, relation_name):
                related_objects = getattr(source_user, relation_name)
                
                # For foreign key relationships, update the foreign key
                if hasattr(related_objects, 'update'):
                    count = related_objects.count()
                    related_objects.update(user=target_user)  # Assumes 'user' field name
                    return {'transferred': count}
                
            return {'transferred': 0}
            
        except Exception as e:
            logger.error(f"Error transferring {relation_name}: {e}")
            return {'error': 'Transfer failed'}
