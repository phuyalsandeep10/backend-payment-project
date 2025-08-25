"""
Core Monitoring Module

Task 2.2.2 - Core Config Decomposition

This module contains monitoring and alerting components moved from core_config:
- Error handling systems 
- Security event monitoring
- Performance monitoring
- Audit services
"""

# Version info
__version__ = '1.0.0'
__description__ = 'PRS Core Monitoring Module'

# Import error handling components
try:
    from .error_handling.error_handling import (
        StandardErrorResponse,
        SecureErrorHandler,
        custom_exception_handler
    )
    from .error_handling.global_exception_handler import global_exception_handler
    from .error_handling.emergency_response_system import EmergencyResponseSystem
    ERROR_HANDLING_AVAILABLE = True
except ImportError:
    ERROR_HANDLING_AVAILABLE = False

# Lazy import audit service to avoid AppRegistryNotReady
AUDIT_AVAILABLE = True

def get_audit_service():
    """Lazy import for AuditService to avoid Django startup issues"""
    try:
        from .audit_service import AuditService
        return AuditService
    except ImportError:
        return None

# Build __all__ based on available components
__all__ = []

if ERROR_HANDLING_AVAILABLE:
    __all__.extend([
        'StandardErrorResponse',
        'SecureErrorHandler',
        'custom_exception_handler',
        'global_exception_handler',
        'EmergencyResponseSystem'
    ])

if AUDIT_AVAILABLE:
    __all__.extend(['get_audit_service'])