"""
Service Registry for Dependency Injection

Provides centralized service registration and dependency injection.
Task 2.1.1 - Service Layer Implementation
"""

import logging
from typing import Dict, Type, Any, Optional, Callable
logger = logging.getLogger(__name__)

def get_user_model_safe():
    """Safely get user model to avoid AppRegistryNotReady errors"""
    from django.contrib.auth import get_user_model
    return get_user_model()


class ServiceRegistry:
    """
    Centralized service registry for dependency injection
    """
    
    _instance: Optional['ServiceRegistry'] = None
    _services: Dict[str, Type] = {}
    _singletons: Dict[str, Any] = {}
    _factories: Dict[str, Callable] = {}
    
    def __new__(cls) -> 'ServiceRegistry':
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not hasattr(self, '_initialized'):
            self._initialized = True
            logger.info("Service registry initialized")
    
    def register_service(self, name: str, service_class: Type, singleton: bool = False):
        """
        Register a service class
        
        Args:
            name: Service name for lookup
            service_class: The service class to register
            singleton: Whether to use singleton pattern
        """
        self._services[name] = service_class
        
        if singleton and name not in self._singletons:
            self._singletons[name] = None
        
        logger.debug(f"Registered service: {name} -> {service_class.__name__} (singleton={singleton})")
    
    def register_factory(self, name: str, factory_func: Callable):
        """
        Register a factory function for complex service creation
        
        Args:
            name: Service name for lookup
            factory_func: Factory function that returns service instance
        """
        self._factories[name] = factory_func
        logger.debug(f"Registered factory: {name} -> {factory_func.__name__}")
    
    def get_service(self, name: str, user=None, organization=None, **kwargs) -> Any:
        """
        Get a service instance by name
        
        Args:
            name: Service name to lookup
            user: User context for the service
            organization: Organization context
            **kwargs: Additional arguments for service creation
            
        Returns:
            Service instance
            
        Raises:
            ValueError: If service is not registered
        """
        # Check if it's a factory-created service
        if name in self._factories:
            return self._factories[name](user=user, organization=organization, **kwargs)
        
        # Check if it's a registered service
        if name not in self._services:
            raise ValueError(f"Service '{name}' is not registered")
        
        service_class = self._services[name]
        
        # Handle singleton services
        if name in self._singletons:
            if self._singletons[name] is None:
                self._singletons[name] = service_class(user=user, organization=organization, **kwargs)
                logger.debug(f"Created singleton service: {name}")
            return self._singletons[name]
        
        # Create new instance
        service_instance = service_class(user=user, organization=organization, **kwargs)
        logger.debug(f"Created service instance: {name}")
        return service_instance
    
    def is_registered(self, name: str) -> bool:
        """Check if a service is registered"""
        return name in self._services or name in self._factories
    
    def list_services(self) -> Dict[str, str]:
        """List all registered services"""
        services = {}
        
        for name, service_class in self._services.items():
            services[name] = f"{service_class.__module__}.{service_class.__name__}"
        
        for name, factory_func in self._factories.items():
            services[name] = f"factory:{factory_func.__name__}"
        
        return services
    
    def clear_singletons(self):
        """Clear all singleton instances (useful for testing)"""
        self._singletons.clear()
        logger.debug("Cleared all singleton services")
    
    def unregister_service(self, name: str):
        """Unregister a service"""
        if name in self._services:
            del self._services[name]
        if name in self._singletons:
            del self._singletons[name]
        if name in self._factories:
            del self._factories[name]
        logger.debug(f"Unregistered service: {name}")


# Global service registry instance
service_registry = ServiceRegistry()


def register_service(name: str, service_class: Type = None, singleton: bool = False):
    """
    Decorator for registering services
    
    Args:
        name: Service name for lookup
        service_class: Service class (if not using as decorator)
        singleton: Whether to use singleton pattern
    """
    def decorator(cls):
        service_registry.register_service(name, cls, singleton=singleton)
        return cls
    
    if service_class is not None:
        service_registry.register_service(name, service_class, singleton=singleton)
        return service_class
    
    return decorator


def get_service(name: str, user=None, organization=None, **kwargs) -> Any:
    """
    Convenience function to get a service instance
    
    Args:
        name: Service name to lookup
        user: User context for the service
        organization: Organization context
        **kwargs: Additional arguments for service creation
        
    Returns:
        Service instance
    """
    return service_registry.get_service(name, user=user, organization=organization, **kwargs)


# Auto-register services from specific modules
def auto_register_services():
    """
    Auto-register services from service modules
    This should be called during Django app initialization
    """
    try:
        # Register authentication services (Task 2.3.1 & 2.3.2)
        from .authentication.password_policy_service import PasswordPolicyService
        from .authentication.session_management_service import SessionManagementService
        from .authentication.security_event_service import SecurityEventService
        from .authentication.user_profile_service import UserProfileService
        from .authentication.user_role_service import UserRoleService
        from .authentication.user_organization_service import UserOrganizationService
        from .authentication.user_relationship_service import UserRelationshipService
        
        service_registry.register_service('password_policy_service', PasswordPolicyService, singleton=True)
        service_registry.register_service('session_management_service', SessionManagementService, singleton=True)
        service_registry.register_service('security_event_service', SecurityEventService, singleton=True)
        service_registry.register_service('user_profile_service', UserProfileService, singleton=True)
        service_registry.register_service('user_role_service', UserRoleService, singleton=True)
        service_registry.register_service('user_organization_service', UserOrganizationService, singleton=True)
        service_registry.register_service('user_relationship_service', UserRelationshipService, singleton=True)
        
        # Lazy import business logic services to avoid Django startup issues (Task 2.1.2, 2.1.3)
        try:
            from .deal_service import DealService
            service_registry.register_service('deal_service', DealService, singleton=False)
        except ImportError as e:
            logger.debug(f"Deal service not available during auto-registration: {e}")
        
        try:
            from .payment_service import PaymentService
            service_registry.register_service('payment_service', PaymentService, singleton=False)
        except ImportError as e:
            logger.debug(f"Payment service not available during auto-registration: {e}")
        
        logger.info("Auto-registered authentication services")
    except ImportError as e:
        # Services may not exist yet during initial implementation
        logger.debug(f"Service module not found during auto-registration: {e}")
