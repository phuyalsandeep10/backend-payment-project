"""
Audit Service - Compatibility Layer

Audit service functionality has been moved to core.monitoring.audit_service
This file provides backward compatibility imports.
"""

# Lazy import audit service from new location to avoid startup issues
def get_audit_service():
    """Get AuditService from new location"""
    from core.monitoring.audit_service import AuditService
    return AuditService

# For backward compatibility - lazy loading
def __getattr__(name):
    if name == 'AuditService':
        return get_audit_service()
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")

# Make all imports available at module level for backward compatibility  
__all__ = ['AuditService', 'get_audit_service']

