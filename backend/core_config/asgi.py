"""
ASGI config for backend project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.2/howto/deployment/asgi/
"""

import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from apps.notifications.consumers import NotificationConsumer
from django.urls import path, re_path

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')

django_asgi_app = get_asgi_application()

websocket_urlpatterns = [
    path('ws/notifications/', NotificationConsumer.as_asgi()),
    path('ws/', NotificationConsumer.as_asgi()),  # Add this for backward compatibility
    re_path(r'^$', NotificationConsumer.as_asgi()),  # Handle root path
]

application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": AuthMiddlewareStack(
        URLRouter(websocket_urlpatterns)
    ),
})
