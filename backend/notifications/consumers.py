from channels.generic.websocket import AsyncWebsocketConsumer
from urllib.parse import parse_qs
from django.contrib.auth import get_user_model
from django.db import close_old_connections
from django.apps import apps
import json
from channels.db import database_sync_to_async

class NotificationConsumer(AsyncWebsocketConsumer):
    @property
    def User(self):
        return get_user_model()

    @database_sync_to_async
    def get_token(self, Token, token_key):
        try:
            return Token.objects.select_related("user").get(key=token_key)
        except Token.DoesNotExist:
            return None

    async def connect(self):
        # Lazy import Token model to avoid AppRegistryNotReady
        Token = apps.get_model('authtoken', 'Token')
        # Parse token from query string
        query_string = self.scope["query_string"].decode()
        token_key = parse_qs(query_string).get("token", [None])[0]
        self.user = None

        print(f"[NotificationConsumer] Token key: {token_key}")

        if token_key:
            close_old_connections()
            token = await self.get_token(Token, token_key)
            if token:
                self.user = token.user
            else:
                self.user = None
        print(f"[NotificationConsumer] User: {self.user}")
        if self.user and self.user.is_active:
            self.group_name = f"notifications_{self.user.id}"
            await self.channel_layer.group_add(self.group_name, self.channel_name)
            await self.accept()
            # Send a hello message
            await self.send(text_data=json.dumps({"message": "WebSocket connected!"}))

            # After connection, push unread notifications so the frontend
            # can render current state without an extra REST round-trip.
            batch = await self._get_unread_notifications()
            await self.send(text_data=json.dumps({
                "type": "notification_batch",
                "notifications": batch
            }, default=str))
        else:
            print("[NotificationConsumer] WebSocket connection rejected: user not authenticated or inactive.")
            await self.close()

    async def disconnect(self, close_code):
        if hasattr(self, "group_name"):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

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

    async def receive(self, text_data):
        pass

    async def send_notification(self, event):
        notification = event["notification"]
        await self.send(text_data=json.dumps({
            "type": "notification",
            "notification": notification
        })) 