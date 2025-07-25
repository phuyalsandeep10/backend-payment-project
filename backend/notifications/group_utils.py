"""
Redis Group Management Utilities for Notifications System

This module provides utilities for managing Redis channel groups for different
notification targeting strategies: user-specific, role-based, organization-wide,
and system-wide broadcasts.
"""

from typing import List, Set, Optional
from django.contrib.auth import get_user_model
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync, sync_to_async


class NotificationGroupManager:
    """Manages Redis channel groups for notification targeting"""
    
    def __init__(self):
        self.channel_layer = None
    
    @property
    def _channel_layer(self):
        """Lazy initialization of channel layer"""
        if self.channel_layer is None:
            self.channel_layer = get_channel_layer()
        return self.channel_layer
    
    # Group Name Generators
    @staticmethod
    def get_user_group(user_id: int) -> str:
        """Get user-specific notification group name"""
        return f"notifications_user_{user_id}"
    
    @staticmethod
    def get_role_group(org_id: int, role_name: str) -> str:
        """Get role-based notification group name within organization"""
        return f"notifications_role_{org_id}_{role_name.lower().replace(' ', '_')}"
    
    @staticmethod
    def get_org_group(org_id: int) -> str:
        """Get organization-wide notification group name"""
        return f"notifications_org_{org_id}"
    
    @staticmethod
    def get_org_broadcast_group(org_id: int) -> str:
        """Get organization broadcast group name"""
        return f"notifications_org_{org_id}_broadcast"
    
    @staticmethod
    def get_system_broadcast_group() -> str:
        """Get system-wide broadcast group name"""
        return "notifications_system_broadcast"
    
    @staticmethod
    def get_system_admin_group() -> str:
        """Get system administrators group name"""
        return "notifications_system_admins"
    
    # Async-safe User Group Calculation
    @sync_to_async
    def _get_user_data(self, user):
        """Get user data synchronously for async context"""
        user_data = {
            'id': user.id,
            'is_superuser': getattr(user, 'is_superuser', False),
            'organization_id': None,
            'role_name': None
        }
        
        # Safely get organization
        try:
            if hasattr(user, 'organization') and user.organization:
                user_data['organization_id'] = user.organization.id
        except Exception:
            pass
        
        # Safely get role
        try:
            if hasattr(user, 'role') and user.role:
                user_data['role_name'] = user.role.name
        except Exception:
            pass
            
        return user_data
    
    def get_user_groups_sync(self, user) -> List[str]:
        """
        Calculate all Redis groups a user should join (synchronous version)
        """
        groups = []
        
        # Personal user group
        groups.append(self.get_user_group(user.id))
        
        # Organization-wide groups
        try:
            if hasattr(user, 'organization') and user.organization:
                org_id = user.organization.id
                groups.append(self.get_org_group(org_id))
                groups.append(self.get_org_broadcast_group(org_id))
                
                # Role-based groups within organization
                if hasattr(user, 'role') and user.role:
                    role_name = user.role.name
                    groups.append(self.get_role_group(org_id, role_name))
        except Exception:
            pass
        
        # System-wide groups
        groups.append(self.get_system_broadcast_group())
        
        # System admin group for superusers
        if getattr(user, 'is_superuser', False):
            groups.append(self.get_system_admin_group())
        
        return groups
    
    async def get_user_groups(self, user) -> List[str]:
        """
        Calculate all Redis groups a user should join (async version)
        """
        user_data = await self._get_user_data(user)
        groups = []
        
        # Personal user group
        groups.append(self.get_user_group(user_data['id']))
        
        # Organization-wide groups
        if user_data['organization_id']:
            org_id = user_data['organization_id']
            groups.append(self.get_org_group(org_id))
            groups.append(self.get_org_broadcast_group(org_id))
            
            # Role-based groups within organization
            if user_data['role_name']:
                groups.append(self.get_role_group(org_id, user_data['role_name']))
        
        # System-wide groups
        groups.append(self.get_system_broadcast_group())
        
        # System admin group for superusers
        if user_data['is_superuser']:
            groups.append(self.get_system_admin_group())
        
        return groups
    
    # Channel Management
    async def add_user_to_groups(self, user, channel_name: str):
        """Add user's channel to all appropriate Redis groups"""
        groups = await self.get_user_groups(user)
        
        for group_name in groups:
            await self._channel_layer.group_add(group_name, channel_name)
        
        return groups
    
    async def remove_user_from_groups(self, user, channel_name: str):
        """Remove user's channel from all Redis groups"""
        groups = await self.get_user_groups(user)
        
        for group_name in groups:
            await self._channel_layer.group_discard(group_name, channel_name)
        
        return groups
    
    # Group Broadcasting
    async def send_to_user(self, user_id: int, message: dict):
        """Send notification to specific user"""
        group_name = self.get_user_group(user_id)
        await self._channel_layer.group_send(group_name, {
            'type': 'send_notification',
            'notification': message
        })
    
    async def send_to_role(self, org_id: int, role_name: str, message: dict):
        """Send notification to all users with specific role in organization"""
        group_name = self.get_role_group(org_id, role_name)
        await self._channel_layer.group_send(group_name, {
            'type': 'send_notification',
            'notification': message
        })
    
    async def send_to_roles(self, org_id: int, role_names: List[str], message: dict):
        """Send notification to multiple roles in organization"""
        for role_name in role_names:
            await self.send_to_role(org_id, role_name, message)
    
    async def send_to_organization(self, org_id: int, message: dict):
        """Send notification to all users in organization"""
        group_name = self.get_org_group(org_id)
        await self._channel_layer.group_send(group_name, {
            'type': 'send_notification',
            'notification': message
        })
    
    async def send_org_broadcast(self, org_id: int, message: dict):
        """Send broadcast notification to organization"""
        group_name = self.get_org_broadcast_group(org_id)
        await self._channel_layer.group_send(group_name, {
            'type': 'send_notification',
            'notification': message
        })
    
    async def send_system_broadcast(self, message: dict):
        """Send system-wide broadcast notification"""
        group_name = self.get_system_broadcast_group()
        await self._channel_layer.group_send(group_name, {
            'type': 'send_notification',
            'notification': message
        })
    
    async def send_to_system_admins(self, message: dict):
        """Send notification to all system administrators"""
        group_name = self.get_system_admin_group()
        await self._channel_layer.group_send(group_name, {
            'type': 'send_notification',
            'notification': message
        })


# Synchronous wrapper for use in Django signals
class SyncNotificationGroupManager:
    """Synchronous wrapper for NotificationGroupManager"""
    
    def __init__(self):
        self.async_manager = NotificationGroupManager()
    
    def get_user_groups(self, user) -> List[str]:
        """Get user groups synchronously"""
        return self.async_manager.get_user_groups_sync(user)
    
    def send_to_user(self, user_id: int, message: dict):
        """Send notification to specific user (sync)"""
        async_to_sync(self.async_manager.send_to_user)(user_id, message)
    
    def send_to_role(self, org_id: int, role_name: str, message: dict):
        """Send notification to specific role (sync)"""
        async_to_sync(self.async_manager.send_to_role)(org_id, role_name, message)
    
    def send_to_roles(self, org_id: int, role_names: List[str], message: dict):
        """Send notification to multiple roles (sync)"""
        async_to_sync(self.async_manager.send_to_roles)(org_id, role_names, message)
    
    def send_to_organization(self, org_id: int, message: dict):
        """Send notification to organization (sync)"""
        async_to_sync(self.async_manager.send_to_organization)(org_id, message)
    
    def send_org_broadcast(self, org_id: int, message: dict):
        """Send organization broadcast (sync)"""
        async_to_sync(self.async_manager.send_org_broadcast)(org_id, message)
    
    def send_system_broadcast(self, message: dict):
        """Send system broadcast (sync)"""
        async_to_sync(self.async_manager.send_system_broadcast)(message)
    
    def send_to_system_admins(self, message: dict):
        """Send to system admins (sync)"""
        async_to_sync(self.async_manager.send_to_system_admins)(message)


# Global instances for easy import
group_manager = NotificationGroupManager()
sync_group_manager = SyncNotificationGroupManager()
