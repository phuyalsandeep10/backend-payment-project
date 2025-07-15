import os
import django
import sys

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from notifications.models import Notification
from authentication.models import User

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python send_test_notification.py <user_id>")
        sys.exit(1)
    user_id = int(sys.argv[1])
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        print(f"User with id {user_id} does not exist.")
        sys.exit(1)
    notification = Notification.objects.create(
        title="Test Notification",
        message="This is a test notification sent via script.",
        notification_type="info",
        priority="normal",
        category="test",
        recipient=user,
        organization=user.organization if hasattr(user, 'organization') else None,
    )
    print(f"Notification sent to user {user.email} (id={user.id})!") 