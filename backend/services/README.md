# Service Layer Documentation

## Overview

This service layer provides a structured approach to organizing business logic in the PRS system. It separates business logic from Django views and models, making the code more maintainable and testable.

**Task 2.1.1 - Service Layer Implementation**

## Architecture

```
services/
├── __init__.py              # Package initialization
├── apps.py                  # Django app configuration
├── base_service.py          # Base service class with common patterns
├── service_registry.py      # Dependency injection system
├── example_service.py       # Example service implementation
└── README.md               # This documentation
```

## Key Components

### 1. BaseService Class

All business logic services should inherit from `BaseService` which provides:

- **Transaction Management**: Automatic database transaction handling
- **User Context**: Built-in user and organization context
- **Error Handling**: Consistent exception handling and logging
- **Validation**: Common validation patterns for inputs and permissions
- **Logging**: Structured logging with service context

### 2. ServiceResult Class

Standard result object for service operations:

```python
result = ServiceResult(
    success=True,
    data={"processed": data},
    errors=[],
    warnings=[],
    meta={"processing_time": "0.5s"}
)
```

### 3. Service Registry

Dependency injection system for managing service instances:

- **Auto-registration**: Services register themselves with decorators
- **Singleton Support**: Services can be configured as singletons
- **Factory Functions**: Support for complex service creation
- **Context Injection**: Automatic user/organization context injection

## Creating a New Service

### Step 1: Create Service Class

```python
from .base_service import BaseService, ServiceResult
from .service_registry import register_service

@register_service('my_service')
class MyService(BaseService):
    
    def get_service_name(self) -> str:
        return "MyService"
    
    def process_something(self, data):
        try:
            # Log the action
            self.log_service_action("process_something", {"data_keys": list(data.keys())})
            
            # Validate input
            validation = self.validate_input(data, required_fields=['required_field'])
            if not validation.success:
                return validation
            
            # Check permissions
            permission = self.validate_user_permission('some_permission')
            if not permission.success:
                return permission
            
            # Business logic here
            result_data = self._do_business_logic(data)
            
            return self.create_result(data=result_data)
            
        except Exception as e:
            return self.handle_exception(e, "process_something")
    
    def _do_business_logic(self, data):
        # Private business logic methods
        return {"processed": data}
```

### Step 2: Register in Service Registry

Services can be registered in several ways:

```python
# 1. Using decorator (recommended)
@register_service('my_service')
class MyService(BaseService):
    pass

# 2. Manual registration
from .service_registry import service_registry
service_registry.register_service('my_service', MyService)

# 3. Singleton registration
service_registry.register_service('my_service', MyService, singleton=True)

# 4. Factory registration
def create_my_service(user=None, organization=None, **kwargs):
    service = MyService(user=user, organization=organization)
    # Custom initialization
    return service

service_registry.register_factory('my_service', create_my_service)
```

## Using Services

### In Django Views

```python
from services import get_service

def my_view(request):
    # Get service with user context
    service = get_service('my_service', user=request.user, organization=request.user.organization)
    
    # Use the service
    result = service.process_something(request.data)
    
    if result.success:
        return JsonResponse({'data': result.data})
    else:
        return JsonResponse({'errors': result.errors}, status=400)
```

### In Other Services

```python
class MyOtherService(BaseService):
    
    def __init__(self, user=None, organization=None):
        super().__init__(user, organization)
        # Get dependent service
        self.my_service = get_service('my_service', user=user, organization=organization)
    
    def complex_operation(self, data):
        # Use the dependent service
        result = self.my_service.process_something(data)
        if not result.success:
            return result
        
        # Continue with complex logic
        return self.create_result(data=result.data)
```

### In Management Commands

```python
from django.core.management.base import BaseCommand
from services import get_service

class Command(BaseCommand):
    
    def handle(self, *args, **options):
        service = get_service('my_service')  # No user context needed
        result = service.process_something(data)
        
        if result.success:
            self.stdout.write(f"Processed: {result.data}")
        else:
            self.stderr.write(f"Errors: {result.errors}")
```

## Best Practices

### 1. Service Responsibilities

- **Single Responsibility**: Each service should have a focused purpose
- **Business Logic Only**: Keep all business logic in services, not in views or models
- **Stateless**: Services should be stateless (except for user/org context)
- **Testable**: Design services to be easily testable in isolation

### 2. Error Handling

```python
def my_method(self, data):
    try:
        # Business logic
        return self.create_result(data=processed_data)
    except ValidationError as e:
        return self.create_error_result(str(e))
    except Exception as e:
        return self.handle_exception(e, "my_method")
```

### 3. Transaction Management

```python
def complex_operation(self, data):
    def transaction_operation():
        # All database operations here will be in one transaction
        result1 = self.step_one(data)
        if not result1.success:
            return result1
        
        result2 = self.step_two(result1.data)
        if not result2.success:
            return result2
        
        return self.create_result(data=result2.data)
    
    return self.execute_with_transaction(transaction_operation)
```

### 4. Logging

```python
def important_operation(self, data):
    self.log_service_action("important_operation_started", {"input_size": len(data)})
    
    try:
        result = self.do_work(data)
        self.log_service_action("important_operation_completed", {"result_size": len(result)})
        return self.create_result(data=result)
    except Exception as e:
        self.log_service_action("important_operation_failed", {"error": str(e)}, level="ERROR")
        return self.handle_exception(e, "important_operation")
```

## Testing Services

### Unit Test Example

```python
from django.test import TestCase
from services import get_service
from authentication.models import User

class MyServiceTest(TestCase):
    
    def setUp(self):
        self.user = User.objects.create_user(email='test@example.com')
        self.service = get_service('my_service', user=self.user)
    
    def test_process_something_success(self):
        data = {'required_field': 'value'}
        result = self.service.process_something(data)
        
        self.assertTrue(result.success)
        self.assertIn('processed', result.data)
    
    def test_process_something_validation_error(self):
        data = {}  # Missing required field
        result = self.service.process_something(data)
        
        self.assertFalse(result.success)
        self.assertIn('Required field missing', result.errors[0])
```

## Migration Strategy

To migrate existing business logic to services:

1. **Identify Business Logic**: Find business logic in views and models
2. **Create Service**: Create new service class for the domain
3. **Extract Logic**: Move business logic to service methods
4. **Update Views**: Change views to use services instead of direct model operations
5. **Test**: Ensure all functionality works with the new service layer

## Integration with Existing Code

Services can be gradually introduced:

- **Phase 1**: Create services for new features
- **Phase 2**: Extract complex business logic from existing views
- **Phase 3**: Move model business logic to services
- **Phase 4**: Refactor models to be data-only

This approach allows for incremental adoption without breaking existing functionality.
