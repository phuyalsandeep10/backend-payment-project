from channels.generic.websocket import AsyncWebsocketConsumer
from urllib.parse import parse_qs
from django.contrib.auth import get_user_model
from django.db import close_old_connections
from django.apps import apps
import json
from channels.db import database_sync_to_async
from .group_utils import NotificationGroupManager

class NotificationConsumer(AsyncWebsocketConsumer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.group_manager = NotificationGroupManager()
        self.user_groups = []
    
    @property
    def User(self):
        return get_user_model()

    @database_sync_to_async
    def get_user_from_ws_token(self, token_key):
        """Get user from short-lived WebSocket token stored in cache"""
        from django.core.cache import cache
        from django.contrib.auth import get_user_model
        
        try:
            cache_key = f'ws_token:{token_key}'
            token_data = cache.get(cache_key)
            
            if not token_data or not isinstance(token_data, dict):
                return None
                
            user_id = token_data.get('user_id')
            if not user_id:
                return None
                
            User = get_user_model()
            return User.objects.get(id=user_id)
            
        except (User.DoesNotExist, Exception):
            return None

    async def connect(self):
        # Parse WebSocket token from query string
        query_string = self.scope["query_string"].decode()
        token_key = parse_qs(query_string).get("ws_token", [None])[0]
        self.user = None

        # Log connection attempt without exposing token
        import logging
        security_logger = logging.getLogger('security')
        client_ip = self.scope.get('client', ['unknown'])[0]
        security_logger.info(f"WebSocket connection attempt from {client_ip}")

        if token_key:
            close_old_connections()
            # Use short-lived WebSocket token instead of DRF token
            self.user = await self.get_user_from_ws_token(token_key)
        else:
            security_logger.warning("WebSocket connection attempt without token")
        # Log authentication result without exposing user details
        if self.user:
            security_logger.info(f"WebSocket authentication successful for user ID: {self.user.id}")
        else:
            security_logger.warning("WebSocket authentication failed")
        if self.user and self.user.is_active:
            # Add user to all appropriate Redis groups
            self.user_groups = await self.group_manager.add_user_to_groups(
                self.user, self.channel_name
            )
            
            await self.accept()
            
            # Get timestamp
            timestamp = await self._get_current_timestamp()
            
            # Send connection confirmation with group information
            await self.send(text_data=json.dumps({
                "message": "WebSocket connected!",
                "user_id": self.user.id,
                "groups": self.user_groups,
                "timestamp": timestamp
            }))

            # After connection, push unread notifications so the frontend
            # can render current state without an extra REST round-trip.
            batch = await self._get_unread_notifications()
            await self.send(text_data=json.dumps({
                "type": "notification_batch",
                "notifications": batch,
                "count": len(batch)
            }, default=str))
        else:
            security_logger.warning("WebSocket connection rejected: user not authenticated or inactive")
            await self.close()

    async def disconnect(self, close_code):
        # Remove user from all Redis groups they were part of
        if hasattr(self, "user") and self.user and hasattr(self, "user_groups"):
            await self.group_manager.remove_user_from_groups(
                self.user, self.channel_name
            )
            security_logger.info(f"WebSocket user {self.user.id} disconnected from {len(self.user_groups)} groups")

    @database_sync_to_async
    def _get_unread_notifications(self):
        """Return last 50 unread notifications as plain dicts (avoid DRF serialization in async context)"""
        from notifications.models import Notification
        unread = (
            Notification.objects
            .filter(recipient=self.user, is_read=False)
            .order_by('-created_at')
            .values(
                'id', 'title', 'message', 'notification_type', 'priority', 'category',
                'is_read', 'related_object_type', 'related_object_id', 'action_url', 'created_at'
            )[:50]
        )
        return list(unread)
    
    @database_sync_to_async
    def _get_current_timestamp(self):
        """Get current timestamp"""
        from django.utils import timezone
        return timezone.now().isoformat()

    async def receive(self, text_data):
        """Handle incoming WebSocket messages from client"""
        try:
            data = json.loads(text_data)
            message_type = data.get('type')
            
            # Handle client-side message types
            if message_type == 'ping':
                timestamp = await self._get_current_timestamp()
                await self.send(text_data=json.dumps({
                    "type": "pong",
                    "timestamp": timestamp
                }))
                return  # Important: return early to avoid other processing
                
            elif message_type == 'mark_as_read':
                notification_id = data.get('notification_id')
                if notification_id:
                    success = await self._mark_notification_as_read(notification_id)
                    await self.send(text_data=json.dumps({
                        "type": "mark_as_read_response",
                        "notification_id": notification_id,
                        "success": success
                    }))
            elif message_type == 'get_unread_count':
                count = await self._get_unread_count()
                await self.send(text_data=json.dumps({
                    "type": "unread_count",
                    "count": count
                }))
                
        except json.JSONDecodeError as e:
            security_logger.warning(f"WebSocket invalid JSON received from user {self.user.id if self.user else 'anonymous'}")
            await self.send(text_data=json.dumps({
                "type": "error",
                "message": "Invalid JSON format"
            }))
        except Exception as e:
            security_logger.error(f"WebSocket error handling message from user {self.user.id if self.user else 'anonymous'}: {str(e)}")
            await self.send(text_data=json.dumps({
                "type": "error", 
                "message": "Internal server error"
            }))

    @database_sync_to_async
    def _mark_notification_as_read(self, notification_id):
        """Mark notification as read"""
        try:
            from notifications.models import Notification
            notification = Notification.objects.get(
                id=notification_id, 
                recipient=self.user
            )
            notification.is_read = True
            notification.save()
            return True
        except Notification.DoesNotExist:
            return False
        except Exception as e:
            security_logger.error(f"Error marking notification as read for user {self.user.id}: {str(e)}")
            return False
    
    @database_sync_to_async
    def _get_unread_count(self):
        """Get unread notification count for user"""
        try:
            from notifications.models import Notification
            return Notification.objects.filter(
                recipient=self.user,
                is_read=False
            ).count()
        except Exception as e:
            security_logger.error(f"Error getting unread count for user {self.user.id}: {str(e)}")
            return 0

    async def send_notification(self, event):
        """Handle notification broadcast from Redis groups"""
        notification = event["notification"]
        
        # Get timestamp
        timestamp = await self._get_current_timestamp()
        
        # Add timestamp and channel info for debugging
        enhanced_notification = {
            **notification,
            "received_at": timestamp,
            "channel_name": self.channel_name[:8] + "..." if len(self.channel_name) > 8 else self.channel_name
        }
        
        await self.send(text_data=json.dumps({
            "type": "notification",
            "notification": enhanced_notification
        }, default=str)) 
