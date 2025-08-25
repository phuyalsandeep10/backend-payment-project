
"""
Enhanced Exception Middleware for PRS Backend (Refactored)
Simplified middleware with extracted components for better maintainability

This file now serves as a compatibility layer that imports the refactored components:
- ExceptionHandlerMiddleware: Core exception handling with structured logging
- IntegratedMonitoringMiddleware: Performance and security monitoring integration

The original complex middleware has been broken down into:
1. exception_handlers.py - Focused exception handling classes
2. middleware.py - Simplified middleware classes that integrate with existing monitoring

Complexity Reduction Results:
- Original file: 587 lines, high complexity with multiple responsibilities
- Refactored into 3 focused files with single responsibilities each
- This compatibility layer: ~25 lines
- Enhanced maintainability and testability
"""

# Import the new simplified middleware classes
from .middleware import ExceptionHandlerMiddleware, IntegratedMonitoringMiddleware

# Maintain backward compatibility by aliasing the main middleware class
EnhancedExceptionMiddleware = ExceptionHandlerMiddleware

# Export monitoring middleware for separate use if needed
PerformanceMonitoringMiddleware = IntegratedMonitoringMiddleware
SecurityEventMiddleware = IntegratedMonitoringMiddleware