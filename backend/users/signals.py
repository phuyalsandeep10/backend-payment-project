from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver
from django.utils.timezone import now
from .models import LoginSession
from .utils import get_client_ip,get_location_from_ip
from django.contrib.sessions.models import Session

@receiver(user_logged_in)
def capture_login_info(sender, request, user, **kwargs):
    ip = get_client_ip(request)
    user_agent = request.META.get('HTTP_USER_AGENT', '')

    # If you don't want geo location, comment this out
    # location = get_location_from_ip(ip) if ip else None
    # location = None # for now none
    location = get_location_from_ip(ip)
    session_key = request.session.session_key
    LoginSession.objects.create(
        user=user,
        ip_address=ip,
        session_key=session_key,
        user_agent=user_agent,
        location=location,
        login_time=now()
    )