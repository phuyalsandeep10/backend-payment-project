"""
Response Serializers - Task 2.3.3

Focused response serializers for API consistency.
Separates response formatting from business logic.
"""

from rest_framework import serializers
from .user_serializers import UserDetailSerializer


class AuthSuccessResponseSerializer(serializers.Serializer):
    """
    Focused serializer for successful authentication responses.
    Task 2.3.3: Consistent response format.
    """
    token = serializers.CharField(read_only=True)
    user = UserDetailSerializer(read_only=True)
    expires_at = serializers.DateTimeField(read_only=True, required=False)
    session_info = serializers.DictField(read_only=True, required=False)
    
    def to_representation(self, instance):
        """Custom representation with service layer data"""
        data = super().to_representation(instance)
        
        # Add additional response data using services if available
        if 'user' in instance and instance['user']:
            try:
                from apps.authentication.services import profile_service
                user = instance['user']
                
                # Add activity summary to response
                activity_summary = profile_service.get_user_activity_summary(user.id, days=7)
                if activity_summary and not activity_summary.get('error'):
                    data['user_activity'] = {
                        'login_count': activity_summary.get('login_count', 0),
                        'last_login': activity_summary.get('last_login'),
                        'current_streak': activity_summary.get('current_streak', 0)
                    }
                    
            except Exception:
                # Graceful degradation - don't fail response if service unavailable
                pass
        
        return data


class MessageResponseSerializer(serializers.Serializer):
    """
    Focused serializer for simple message responses.
    Task 2.3.3: Consistent message format.
    """
    message = serializers.CharField()
    success = serializers.BooleanField(default=True)
    timestamp = serializers.DateTimeField(read_only=True, required=False)
    
    def to_representation(self, instance):
        """Add timestamp to message responses"""
        data = super().to_representation(instance)
        
        if 'timestamp' not in data:
            from django.utils import timezone
            data['timestamp'] = timezone.now()
        
        return data


class ErrorResponseSerializer(serializers.Serializer):
    """
    Focused serializer for error responses.
    Task 2.3.3: Consistent error format with service integration.
    """
    error = serializers.CharField()
    detail = serializers.CharField(required=False)
    code = serializers.CharField(required=False)
    timestamp = serializers.DateTimeField(read_only=True, required=False)
    errors = serializers.DictField(required=False)  # For field-specific errors
    
    def to_representation(self, instance):
        """Enhanced error representation"""
        data = super().to_representation(instance)
        
        # Add timestamp
        if 'timestamp' not in data:
            from django.utils import timezone
            data['timestamp'] = timezone.now()
        
        # Add error tracking ID for debugging
        if not data.get('code'):
            import uuid
            data['tracking_id'] = str(uuid.uuid4())[:8]
        
        return data


class ValidationErrorResponseSerializer(ErrorResponseSerializer):
    """
    Focused serializer for validation errors.
    Task 2.3.3: Specific validation error format.
    """
    field_errors = serializers.DictField(required=False)
    non_field_errors = serializers.ListField(required=False)
    
    def to_representation(self, instance):
        """Format validation errors consistently"""
        data = super().to_representation(instance)
        
        # Ensure error type is clear
        data['error_type'] = 'validation_error'
        
        return data


class PaginatedResponseSerializer(serializers.Serializer):
    """
    Focused serializer for paginated responses.
    Task 2.3.3: Consistent pagination format.
    """
    count = serializers.IntegerField()
    next = serializers.URLField(required=False, allow_null=True)
    previous = serializers.URLField(required=False, allow_null=True)
    results = serializers.ListField()
    
    # Additional pagination metadata
    page_size = serializers.IntegerField(required=False)
    current_page = serializers.IntegerField(required=False)
    total_pages = serializers.IntegerField(required=False)
    
    def to_representation(self, instance):
        """Enhanced pagination information"""
        data = super().to_representation(instance)
        
        # Calculate additional metadata if not provided
        if 'page_size' not in data and 'count' in data and 'results' in data:
            results_count = len(data['results'])
            if results_count > 0:
                data['page_size'] = results_count
        
        return data


class ServiceHealthResponseSerializer(serializers.Serializer):
    """
    Focused serializer for service health responses.
    Task 2.3.3: Service layer health monitoring.
    """
    service_name = serializers.CharField()
    status = serializers.ChoiceField(choices=['healthy', 'degraded', 'unhealthy'])
    response_time = serializers.FloatField(required=False)
    last_check = serializers.DateTimeField()
    details = serializers.DictField(required=False)
    
    def to_representation(self, instance):
        """Enhanced service health information"""
        data = super().to_representation(instance)
        
        # Add overall system health if multiple services
        if isinstance(instance, dict) and 'services' in instance:
            services = instance['services']
            if services:
                healthy_count = sum(1 for s in services if s.get('status') == 'healthy')
                total_count = len(services)
                
                data['system_health'] = {
                    'overall_status': 'healthy' if healthy_count == total_count else 'degraded',
                    'healthy_services': healthy_count,
                    'total_services': total_count,
                    'health_percentage': (healthy_count / total_count * 100) if total_count > 0 else 0
                }
        
        return data
