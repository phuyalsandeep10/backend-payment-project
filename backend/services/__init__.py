"""
Service Layer for PRS System

This module provides a service layer architecture for business logic separation.
All business logic should be moved from views and models to appropriate service classes.

Task 2.1.1 - Service Layer Implementation
"""

from .base_service import BaseService, ServiceResult
from .service_registry import ServiceRegistry

__all__ = ['BaseService', 'ServiceResult', 'ServiceRegistry']
