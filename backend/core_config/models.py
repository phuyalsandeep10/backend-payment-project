"""
Core Config Models - Simplified

Models moved to appropriate modules:
- SecurityEvent, SecurityAlert, ComplianceReport -> core.security.models

This file now only contains essential core configuration models.
"""

# Import security models from new location for backward compatibility
from core.security.models import SecurityEvent, SecurityAlert, ComplianceReport

# Keep imports available at module level
__all__ = ['SecurityEvent', 'SecurityAlert', 'ComplianceReport']

# This file is now significantly reduced as models have been moved to appropriate modules