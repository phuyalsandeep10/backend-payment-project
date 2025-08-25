"""
Example Service Implementation

Demonstrates how to create services using the base service layer.
This file can be removed after other services are implemented.

Task 2.1.1 - Service Layer Implementation
"""

from typing import Dict, Any, Optional
from .base_service import BaseService, ServiceResult
from .service_registry import register_service


@register_service('example_service')
class ExampleService(BaseService):
    """
    Example service showing how to implement business logic services
    """
    
    def get_service_name(self) -> str:
        return "ExampleService"
    
    def process_data(self, data: Dict[str, Any]) -> ServiceResult:
        """
        Example method showing service patterns
        
        Args:
            data: Input data to process
            
        Returns:
            ServiceResult with processed data or errors
        """
        try:
            # Log the service action
            self.log_service_action("process_data", {"input_keys": list(data.keys())})
            
            # Validate input
            validation_result = self.validate_input(data, required_fields=['name'])
            if not validation_result.success:
                return validation_result
            
            # Check user permissions (example)
            permission_result = self.validate_user_permission('example_permission')
            if not permission_result.success:
                return permission_result
            
            # Process the data (business logic)
            processed_data = {
                'original': data,
                'processed_at': self._get_current_timestamp(),
                'processed_by': self.user.email if self.user else 'Anonymous',
                'organization': self.organization.name if self.organization else None
            }
            
            # Create successful result
            result = self.create_result(data=processed_data)
            result.add_meta('processing_method', 'example_processing')
            
            return result
            
        except Exception as e:
            return self.handle_exception(e, "process_data")
    
    def _get_current_timestamp(self) -> str:
        """Private helper method"""
        from django.utils import timezone
        return timezone.now().isoformat()
    
    def batch_process(self, items: list) -> ServiceResult:
        """
        Example of batch processing with transaction management
        
        Args:
            items: List of items to process
            
        Returns:
            ServiceResult with batch processing results
        """
        def batch_operation():
            results = []
            errors = []
            
            for i, item in enumerate(items):
                try:
                    item_result = self.process_data(item)
                    if item_result.success:
                        results.append(item_result.data)
                    else:
                        errors.extend([f"Item {i}: {error}" for error in item_result.errors])
                except Exception as e:
                    errors.append(f"Item {i}: {str(e)}")
            
            if errors:
                result = self.create_error_result("Batch processing had errors")
                result.errors.extend(errors)
                result.data = {'completed': results, 'failed_count': len(errors)}
                return result
            
            return self.create_result(data={'processed': results, 'count': len(results)})
        
        return self.execute_with_transaction(batch_operation)


# Example of how to use the service registry programmatically
def register_additional_services():
    """Example of programmatic service registration"""
    from .service_registry import service_registry
    
    # Register as singleton
    service_registry.register_service('example_singleton', ExampleService, singleton=True)
    
    # Register with factory function
    def example_factory(user=None, organization=None, **kwargs):
        service = ExampleService(user=user, organization=organization)
        # Additional setup can be done here
        return service
    
    service_registry.register_factory('example_factory', example_factory)
