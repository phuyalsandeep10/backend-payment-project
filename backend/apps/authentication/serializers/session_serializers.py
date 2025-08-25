"""
Session Management Serializers - Task 2.3.3

Focused serializers for session operations using service layer.
"""

from rest_framework import serializers
from apps.authentication.models import UserSession
from apps.authentication.services import session_service
from user_agents import parse


class UserSessionSerializer(serializers.ModelSerializer):
    """
    Focused serializer for user sessions using service layer.
    Task 2.3.3: Service-based session management.
    """
    device = serializers.SerializerMethodField()
    is_current_session = serializers.SerializerMethodField()
    user_agent = serializers.CharField(read_only=True)
    security_status = serializers.SerializerMethodField()
    
    class Meta:
        model = UserSession
        fields = [
            'id', 'session_key', 'ip_address', 'device', 'user_agent',
            'created_at', 'last_activity', 'expires_at', 'is_active',
            'is_current_session', 'security_status'
        ]
        read_only_fields = ['session_key', 'created_at', 'last_activity']
    
    def get_device(self, obj):
        """Parse user agent to get device information"""
        try:
            if obj.user_agent:
                user_agent = parse(obj.user_agent)
                return {
                    'browser': f"{user_agent.browser.family} {user_agent.browser.version_string}",
                    'os': f"{user_agent.os.family} {user_agent.os.version_string}",
                    'device': user_agent.device.family
                }
        except Exception:
            pass
        
        return {
            'browser': 'Unknown',
            'os': 'Unknown', 
            'device': 'Unknown'
        }
    
    def get_is_current_session(self, obj):
        """Check if this is the current session using service layer"""
        try:
            request = self.context.get('request')
            if request and hasattr(request, 'session'):
                # Compare session keys if available
                current_session_key = getattr(request.session, 'session_key', None)
                if current_session_key:
                    return obj.session_key == current_session_key
            return False
        except Exception:
            return False
    
    def get_security_status(self, obj):
        """Get security status of session using service layer"""
        try:
            request = self.context.get('request')
            if request and obj.user:
                # Use session service to validate security
                validation = session_service.validate_session_security(
                    obj.session_key, obj.user, request
                )
                
                return {
                    'valid': validation['valid'],
                    'warnings': validation.get('warnings', []),
                    'risk_level': 'low' if validation['valid'] else 'high'
                }
        except Exception:
            pass
        
        return {
            'valid': True,
            'warnings': [],
            'risk_level': 'unknown'
        }
    
    def validate(self, attrs):
        """Validate session data using service layer"""
        # Additional validation can be added here using session service
        return attrs
