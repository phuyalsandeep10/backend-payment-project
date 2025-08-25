"""
Base Service Class for PRS System

Provides common patterns and utilities for all business logic services.
Task 2.1.1 - Service Layer Implementation
"""

import logging
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass
from abc import ABC, abstractmethod
from django.db import transaction
from django.core.exceptions import ValidationError
logger = logging.getLogger(__name__)

def get_user_model_safe():
    """Safely get user model to avoid AppRegistryNotReady errors"""
    from django.contrib.auth import get_user_model
    return get_user_model()


@dataclass
class ServiceResult:
    """
    Standard result object for service operations
    """
    success: bool = True
    data: Any = None
    errors: List[str] = None
    warnings: List[str] = None
    meta: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []
        if self.warnings is None:
            self.warnings = []
        if self.meta is None:
            self.meta = {}
    
    def add_error(self, error: str):
        """Add an error and mark result as failed"""
        self.errors.append(error)
        self.success = False
    
    def add_warning(self, warning: str):
        """Add a warning without failing the operation"""
        self.warnings.append(warning)
    
    def add_meta(self, key: str, value: Any):
        """Add metadata to the result"""
        self.meta[key] = value
    
    @property
    def has_errors(self) -> bool:
        """Check if the result has any errors"""
        return len(self.errors) > 0
    
    @property
    def has_warnings(self) -> bool:
        """Check if the result has any warnings"""
        return len(self.warnings) > 0


class BaseService(ABC):
    """
    Abstract base class for all business logic services
    
    Provides:
    - Common error handling patterns
    - Transaction management
    - Logging integration
    - User context management
    - Validation helpers
    """
    
    def __init__(self, user=None, organization=None):
        """
        Initialize service with user context
        
        Args:
            user: The user making the request
            organization: The organization context (if applicable)
        """
        self.user = user
        self.organization = organization or (user.organization if user and hasattr(user, 'organization') else None)
        self.logger = logging.getLogger(self.__class__.__module__)
    
    def create_result(self, success: bool = True, data: Any = None) -> ServiceResult:
        """Create a new ServiceResult object"""
        return ServiceResult(success=success, data=data)
    
    def create_error_result(self, error: str, data: Any = None) -> ServiceResult:
        """Create a failed ServiceResult with error message"""
        result = ServiceResult(success=False, data=data)
        result.add_error(error)
        return result
    
    @transaction.atomic
    def execute_with_transaction(self, operation_func, *args, **kwargs) -> ServiceResult:
        """
        Execute a service operation within a database transaction
        
        Args:
            operation_func: The function to execute
            *args, **kwargs: Arguments to pass to the function
            
        Returns:
            ServiceResult: The result of the operation
        """
        try:
            result = operation_func(*args, **kwargs)
            if isinstance(result, ServiceResult) and not result.success:
                # If operation failed, rollback transaction
                transaction.set_rollback(True)
            return result
        except Exception as e:
            self.logger.error(f"Transaction operation failed: {str(e)}")
            transaction.set_rollback(True)
            return self.create_error_result(f"Operation failed: {str(e)}")
    
    def validate_user_permission(self, permission: str) -> ServiceResult:
        """
        Validate that the current user has the required permission
        
        Args:
            permission: Permission string to check
            
        Returns:
            ServiceResult: Success if user has permission, error otherwise
        """
        if not self.user:
            return self.create_error_result("Authentication required")
        
        if not self.user.has_perm(permission):
            return self.create_error_result(f"Permission denied: {permission}")
        
        return self.create_result(success=True)
    
    def validate_organization_access(self, target_organization=None) -> ServiceResult:
        """
        Validate that the user has access to the target organization
        
        Args:
            target_organization: Organization to check access for
            
        Returns:
            ServiceResult: Success if user has access, error otherwise
        """
        if not self.user:
            return self.create_error_result("Authentication required")
        
        if not target_organization:
            target_organization = self.organization
        
        if not target_organization:
            return self.create_error_result("Organization context required")
        
        # Check if user belongs to the organization
        if hasattr(self.user, 'organization') and self.user.organization != target_organization:
            return self.create_error_result("Access denied to organization")
        
        return self.create_result(success=True)
    
    def validate_input(self, data: Dict[str, Any], required_fields: List[str] = None) -> ServiceResult:
        """
        Validate input data for required fields
        
        Args:
            data: Input data to validate
            required_fields: List of required field names
            
        Returns:
            ServiceResult: Success if validation passes, error otherwise
        """
        result = self.create_result()
        
        if required_fields:
            for field in required_fields:
                if field not in data or data[field] is None:
                    result.add_error(f"Required field missing: {field}")
        
        return result
    
    def log_service_action(self, action: str, data: Dict[str, Any] = None, level: str = 'INFO'):
        """
        Log a service action with context
        
        Args:
            action: Action description
            data: Additional data to log
            level: Log level (DEBUG, INFO, WARNING, ERROR)
        """
        log_data = {
            'service': self.__class__.__name__,
            'user': self.user.email if self.user else 'Anonymous',
            'organization': self.organization.name if self.organization else None,
            'action': action
        }
        
        if data:
            log_data.update(data)
        
        log_level = getattr(logging, level.upper(), logging.INFO)
        self.logger.log(log_level, f"Service Action: {action}", extra=log_data)
    
    def handle_exception(self, e: Exception, context: str = None) -> ServiceResult:
        """
        Handle exceptions with consistent logging and error response
        
        Args:
            e: The exception that occurred
            context: Additional context about where the exception occurred
            
        Returns:
            ServiceResult: Error result with appropriate message
        """
        error_msg = f"Service error in {self.__class__.__name__}"
        if context:
            error_msg += f" ({context})"
        error_msg += f": {str(e)}"
        
        self.logger.error(error_msg, exc_info=True, extra={
            'service': self.__class__.__name__,
            'user': self.user.email if self.user else 'Anonymous',
            'organization': self.organization.name if self.organization else None,
            'context': context
        })
        
        # Don't expose internal errors to users in production
        user_error = "An error occurred while processing your request"
        if hasattr(e, 'message'):
            user_error = e.message
        elif isinstance(e, ValidationError):
            user_error = str(e)
        
        return self.create_error_result(user_error)
    
    @abstractmethod
    def get_service_name(self) -> str:
        """Return the name of this service for logging and identification"""
        pass
    
    def __str__(self) -> str:
        return f"{self.get_service_name()}<user={self.user}, org={self.organization}>"
