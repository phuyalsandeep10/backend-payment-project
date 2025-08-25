"""
Response Serializers - Task 2.4.2

Standardized response serializers for consistent API design.
These serializers ensure uniform response formats across all endpoints.
"""

from rest_framework import serializers
from django.utils import timezone
from typing import Dict, Any, Optional, List
import uuid


class StandardResponseSerializer(serializers.Serializer):
    """
    Base response serializer with common fields.
    Task 2.4.2: Foundation for all API responses.
    """
    
    success = serializers.BooleanField(default=True)
    timestamp = serializers.DateTimeField(default=timezone.now)
    request_id = serializers.CharField(read_only=True)
    
    def to_representation(self, instance):
        """Add standard response metadata"""
        data = super().to_representation(instance)
        
        # Add request ID if not present
        if 'request_id' not in data or not data['request_id']:
            data['request_id'] = str(uuid.uuid4())[:8]
        
        # Ensure timestamp is present
        if 'timestamp' not in data or not data['timestamp']:
            data['timestamp'] = timezone.now()
        
        return data


class SuccessResponseSerializer(StandardResponseSerializer):
    """
    Serializer for successful operation responses.
    Task 2.4.2: Consistent success response format.
    """
    
    message = serializers.CharField(default="Operation completed successfully")
    data = serializers.JSONField(required=False)
    
    def __init__(self, *args, **kwargs):
        # Extract data for the data field
        if 'data' in kwargs:
            self.data_content = kwargs.pop('data')
        super().__init__(*args, **kwargs)
    
    def to_representation(self, instance):
        """Enhanced success response"""
        data = super().to_representation(instance)
        
        # Include data content if provided during initialization
        if hasattr(self, 'data_content'):
            data['data'] = self.data_content
        
        # Ensure success is True
        data['success'] = True
        
        return data


class ErrorResponseSerializer(StandardResponseSerializer):
    """
    Serializer for error responses.
    Task 2.4.2: Consistent error response format.
    """
    
    success = serializers.BooleanField(default=False)
    error = serializers.CharField()
    error_code = serializers.CharField(required=False)
    error_type = serializers.CharField(required=False)
    details = serializers.JSONField(required=False)
    field_errors = serializers.DictField(required=False)
    
    def to_representation(self, instance):
        """Enhanced error response"""
        data = super().to_representation(instance)
        
        # Ensure success is False for errors
        data['success'] = False
        
        # Add error categorization if not present
        if 'error_type' not in data or not data['error_type']:
            data['error_type'] = self._categorize_error(data.get('error', ''))
        
        # Add support contact info for serious errors
        if data.get('error_type') in ['server_error', 'critical']:
            data['support'] = {
                'message': 'Please contact support if this error persists',
                'tracking_id': data.get('request_id')
            }
        
        return data
    
    def _categorize_error(self, error_message):
        """Categorize error type based on message"""
        error_lower = error_message.lower()
        
        if 'validation' in error_lower or 'invalid' in error_lower:
            return 'validation_error'
        elif 'permission' in error_lower or 'unauthorized' in error_lower:
            return 'permission_error'
        elif 'not found' in error_lower:
            return 'not_found_error'
        elif 'server' in error_lower or 'internal' in error_lower:
            return 'server_error'
        else:
            return 'general_error'


class ValidationErrorResponseSerializer(ErrorResponseSerializer):
    """
    Specialized serializer for validation errors.
    Task 2.4.2: Consistent validation error format.
    """
    
    error_type = serializers.CharField(default='validation_error')
    field_errors = serializers.DictField()
    non_field_errors = serializers.ListField(required=False)
    
    def to_representation(self, instance):
        """Enhanced validation error response"""
        data = super().to_representation(instance)
        
        # Ensure error type is set correctly
        data['error_type'] = 'validation_error'
        
        # Structure field errors for better frontend handling
        if 'field_errors' in data and data['field_errors']:
            formatted_errors = {}
            for field, errors in data['field_errors'].items():
                if isinstance(errors, list):
                    formatted_errors[field] = {
                        'messages': errors,
                        'count': len(errors)
                    }
                else:
                    formatted_errors[field] = {
                        'messages': [str(errors)],
                        'count': 1
                    }
            data['field_errors'] = formatted_errors
        
        return data


class PaginatedResponseSerializer(SuccessResponseSerializer):
    """
    Serializer for paginated responses.
    Task 2.4.2: Consistent pagination format.
    """
    
    count = serializers.IntegerField()
    next = serializers.URLField(required=False, allow_null=True)
    previous = serializers.URLField(required=False, allow_null=True)
    results = serializers.ListField()
    
    # Additional pagination metadata
    page_info = serializers.SerializerMethodField()
    
    def get_page_info(self, obj):
        """Calculate additional pagination information"""
        try:
            count = obj.get('count', 0)
            results_count = len(obj.get('results', []))
            
            # Try to calculate page information
            page_size = results_count if results_count > 0 else 10
            total_pages = (count + page_size - 1) // page_size if count > 0 else 1
            
            # Estimate current page based on URLs
            current_page = 1
            if obj.get('previous'):
                # This is a simplified estimation
                current_page = 2  # At least page 2 if there's a previous page
            
            return {
                'page_size': page_size,
                'total_pages': total_pages,
                'current_page': current_page,
                'has_next': bool(obj.get('next')),
                'has_previous': bool(obj.get('previous')),
                'showing_results': f"{min(count, results_count)} of {count}"
            }
            
        except Exception:
            return {
                'page_size': len(obj.get('results', [])),
                'total_pages': 1,
                'current_page': 1,
                'has_next': False,
                'has_previous': False
            }


class BulkOperationResponseSerializer(StandardResponseSerializer):
    """
    Serializer for bulk operation responses.
    Task 2.4.2: Consistent bulk operation format.
    """
    
    total_items = serializers.IntegerField()
    successful_items = serializers.IntegerField()
    failed_items = serializers.IntegerField()
    success_rate = serializers.SerializerMethodField()
    results = serializers.ListField()
    errors = serializers.ListField(required=False)
    
    def get_success_rate(self, obj):
        """Calculate success rate percentage"""
        try:
            total = obj.get('total_items', 0)
            successful = obj.get('successful_items', 0)
            
            if total == 0:
                return 0
            
            return round((successful / total) * 100, 2)
        except Exception:
            return 0
    
    def to_representation(self, instance):
        """Enhanced bulk operation response"""
        data = super().to_representation(instance)
        
        # Calculate derived fields if not provided
        if 'total_items' in data and 'successful_items' in data:
            if 'failed_items' not in data:
                data['failed_items'] = data['total_items'] - data['successful_items']
        
        # Set overall success based on failure rate
        if data.get('failed_items', 0) == 0:
            data['success'] = True
            data['message'] = f"All {data.get('total_items', 0)} items processed successfully"
        else:
            # Partial success
            data['success'] = data.get('failed_items', 0) < data.get('total_items', 1)
            data['message'] = (
                f"{data.get('successful_items', 0)} of {data.get('total_items', 0)} "
                f"items processed successfully"
            )
        
        return data


class HealthCheckResponseSerializer(StandardResponseSerializer):
    """
    Serializer for system health check responses.
    Task 2.4.2: Consistent health check format.
    """
    
    status = serializers.ChoiceField(choices=['healthy', 'degraded', 'unhealthy'])
    services = serializers.ListField(required=False)
    uptime = serializers.CharField(required=False)
    version = serializers.CharField(required=False)
    
    def to_representation(self, instance):
        """Enhanced health check response"""
        data = super().to_representation(instance)
        
        # Set overall success based on health status
        data['success'] = data.get('status') in ['healthy', 'degraded']
        
        # Add system information if not present
        if 'version' not in data:
            data['version'] = '1.0.0'  # Default version
        
        if 'uptime' not in data:
            # Calculate uptime (simplified)
            data['uptime'] = 'Unknown'
        
        return data


class SearchResponseSerializer(PaginatedResponseSerializer):
    """
    Serializer for search operation responses.
    Task 2.4.2: Consistent search result format.
    """
    
    query = serializers.CharField()
    search_time = serializers.FloatField(required=False)
    filters_applied = serializers.DictField(required=False)
    suggestions = serializers.ListField(required=False)
    
    def to_representation(self, instance):
        """Enhanced search response"""
        data = super().to_representation(instance)
        
        # Add search metadata
        count = data.get('count', 0)
        query = data.get('query', '')
        
        if count == 0:
            data['message'] = f"No results found for '{query}'"
            data['suggestions'] = data.get('suggestions', [])
        else:
            data['message'] = f"Found {count} results for '{query}'"
        
        # Add search performance info
        if 'search_time' in data and data['search_time']:
            data['performance'] = {
                'search_time_ms': data['search_time'],
                'results_per_second': round(count / max(data['search_time'] / 1000, 0.001), 2)
            }
        
        return data


class ExportResponseSerializer(SuccessResponseSerializer):
    """
    Serializer for data export responses.
    Task 2.4.2: Consistent export format.
    """
    
    file_url = serializers.URLField(required=False)
    file_name = serializers.CharField()
    file_size = serializers.IntegerField(required=False)
    format = serializers.CharField()
    expires_at = serializers.DateTimeField(required=False)
    record_count = serializers.IntegerField(required=False)
    
    def to_representation(self, instance):
        """Enhanced export response"""
        data = super().to_representation(instance)
        
        # Add download instructions
        if data.get('file_url'):
            data['download_info'] = {
                'url': data['file_url'],
                'filename': data.get('file_name'),
                'expires_at': data.get('expires_at'),
                'instructions': 'Click the URL to download the file'
            }
        
        # Format file size for display
        if data.get('file_size'):
            data['file_size_display'] = self._format_file_size(data['file_size'])
        
        return data
    
    def _format_file_size(self, size_bytes):
        """Format file size for human readability"""
        try:
            for unit in ['bytes', 'KB', 'MB', 'GB']:
                if size_bytes < 1024.0:
                    return f"{size_bytes:.1f} {unit}"
                size_bytes /= 1024.0
            return f"{size_bytes:.1f} TB"
        except Exception:
            return f"{size_bytes} bytes"
