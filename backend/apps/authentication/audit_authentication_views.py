#!/usr/bin/env python
"""
Audit script to verify all authentication views return proper DRF Response objects.
This script checks that all authentication endpoints have proper response validation decorators.
"""

import sys
import os
import inspect
import importlib
from typing import List, Dict, Any

# Add the backend directory to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
import django
django.setup()

from authentication import views as auth_views
from authentication import password_views
from authentication.response_validators import validate_response_type, ensure_drf_response, log_response_type

def get_view_functions(module) -> List[tuple]:
    """Get all view functions from a module."""
    view_functions = []
    
    for name, obj in inspect.getmembers(module):
        if inspect.isfunction(obj) and not name.startswith('_'):
            # Check if it's likely a view function
            if hasattr(obj, '__wrapped__') or 'request' in inspect.signature(obj).parameters:
                view_functions.append((name, obj))
    
    return view_functions

def get_view_classes(module) -> List[tuple]:
    """Get all view classes from a module."""
    view_classes = []
    
    for name, obj in inspect.getmembers(module):
        if inspect.isclass(obj) and not name.startswith('_'):
            # Check if it's likely a view class (inherits from APIView, ViewSet, etc.)
            mro = [cls.__name__ for cls in obj.__mro__]
            if any(base in mro for base in ['APIView', 'ViewSet', 'GenericAPIView', 'RetrieveUpdateAPIView']):
                view_classes.append((name, obj))
    
    return view_classes

def check_function_decorators(func) -> Dict[str, Any]:
    """Check if a function has response validation decorators."""
    result = {
        'has_validate_response_type': False,
        'has_ensure_drf_response': False,
        'has_log_response_type': False,
        'decorators': []
    }
    
    # Check if function has been wrapped by our decorators
    current_func = func
    while hasattr(current_func, '__wrapped__'):
        wrapper_name = getattr(current_func, '__name__', 'unknown')
        if hasattr(current_func, '__closure__') and current_func.__closure__:
            # Try to identify our decorators by checking closure variables
            for cell in current_func.__closure__:
                try:
                    if hasattr(cell.cell_contents, '__name__'):
                        if cell.cell_contents.__name__ == 'validate_response_type':
                            result['has_validate_response_type'] = True
                        elif cell.cell_contents.__name__ == 'ensure_drf_response':
                            result['has_ensure_drf_response'] = True
                        elif cell.cell_contents.__name__ == 'log_response_type':
                            result['has_log_response_type'] = True
                except (AttributeError, ValueError):
                    pass
        
        current_func = getattr(current_func, '__wrapped__', None)
        if current_func is None:
            break
    
    # Also check the function's attributes for decorator information
    if hasattr(func, '__name__'):
        func_source = inspect.getsource(func) if hasattr(func, '__code__') else ""
        if '@validate_response_type' in func_source:
            result['has_validate_response_type'] = True
        if '@ensure_drf_response' in func_source:
            result['has_ensure_drf_response'] = True
        if '@log_response_type' in func_source:
            result['has_log_response_type'] = True
    
    return result

def audit_authentication_views():
    """Audit all authentication views for proper response handling."""
    print("🔍 Auditing Authentication Views for Response Type Validation\n")
    
    # Critical authentication endpoints that must have ensure_drf_response
    critical_endpoints = [
        'login_view',
        'verify_otp_view',
        'super_admin_login_view',
        'super_admin_verify_view',
        'org_admin_login_view',
        'org_admin_verify_view',
        'register_view',
        'logout_view',
        'password_change_view',
        'password_change_with_token_view'
    ]
    
    # Get all view functions from authentication.views
    print("📋 Checking authentication.views module:")
    auth_view_functions = get_view_functions(auth_views)
    
    issues_found = []
    
    for name, func in auth_view_functions:
        decorator_info = check_function_decorators(func)
        
        is_critical = name in critical_endpoints
        has_any_validator = (
            decorator_info['has_validate_response_type'] or 
            decorator_info['has_ensure_drf_response']
        )
        
        status = "✅" if has_any_validator else "❌"
        critical_marker = " (CRITICAL)" if is_critical else ""
        
        print(f"  {status} {name}{critical_marker}")
        
        if decorator_info['has_ensure_drf_response']:
            print(f"    - Has ensure_drf_response decorator")
        if decorator_info['has_validate_response_type']:
            print(f"    - Has validate_response_type decorator")
        if decorator_info['has_log_response_type']:
            print(f"    - Has log_response_type decorator")
        
        if not has_any_validator:
            issues_found.append({
                'view': name,
                'module': 'authentication.views',
                'critical': is_critical,
                'issue': 'Missing response validation decorator'
            })
        elif is_critical and not decorator_info['has_ensure_drf_response']:
            issues_found.append({
                'view': name,
                'module': 'authentication.views',
                'critical': True,
                'issue': 'Critical endpoint should use ensure_drf_response decorator'
            })
    
    # Get all view classes from authentication.views
    print("\n📋 Checking authentication view classes:")
    auth_view_classes = get_view_classes(auth_views)
    
    for name, cls in auth_view_classes:
        print(f"  ℹ️  {name} (Class-based view - inherits DRF response handling)")
    
    # Check password_views module
    print("\n📋 Checking authentication.password_views module:")
    password_view_functions = get_view_functions(password_views)
    
    for name, func in password_view_functions:
        decorator_info = check_function_decorators(func)
        
        has_any_validator = (
            decorator_info['has_validate_response_type'] or 
            decorator_info['has_ensure_drf_response']
        )
        
        status = "✅" if has_any_validator else "❌"
        
        print(f"  {status} {name}")
        
        if decorator_info['has_ensure_drf_response']:
            print(f"    - Has ensure_drf_response decorator")
        if decorator_info['has_validate_response_type']:
            print(f"    - Has validate_response_type decorator")
        if decorator_info['has_log_response_type']:
            print(f"    - Has log_response_type decorator")
        
        if not has_any_validator:
            issues_found.append({
                'view': name,
                'module': 'authentication.password_views',
                'critical': False,
                'issue': 'Missing response validation decorator'
            })
    
    # Summary
    print(f"\n📊 Audit Summary:")
    print(f"  Total view functions checked: {len(auth_view_functions) + len(password_view_functions)}")
    print(f"  Total view classes checked: {len(auth_view_classes)}")
    print(f"  Issues found: {len(issues_found)}")
    
    if issues_found:
        print(f"\n⚠️  Issues Found:")
        for issue in issues_found:
            critical_marker = " (CRITICAL)" if issue['critical'] else ""
            print(f"  - {issue['module']}.{issue['view']}{critical_marker}: {issue['issue']}")
    else:
        print(f"\n✅ All authentication views have proper response validation!")
    
    # Check for potential TemplateResponse usage
    print(f"\n🔍 Checking for potential TemplateResponse usage:")
    
    modules_to_check = [auth_views, password_views]
    template_response_found = False
    
    for module in modules_to_check:
        try:
            source = inspect.getsource(module)
            if 'TemplateResponse' in source:
                print(f"  ⚠️  TemplateResponse import found in {module.__name__}")
                template_response_found = True
            if 'render(' in source and 'from django.shortcuts import' in source:
                print(f"  ⚠️  Django render function usage found in {module.__name__}")
                template_response_found = True
        except Exception as e:
            print(f"  ❓ Could not check {module.__name__}: {e}")
    
    if not template_response_found:
        print(f"  ✅ No TemplateResponse usage detected")
    
    return len(issues_found) == 0

def main():
    """Run the audit."""
    print("Authentication Views Response Type Audit")
    print("=" * 50)
    
    success = audit_authentication_views()
    
    if success:
        print(f"\n🎉 Audit completed successfully! All authentication views are properly configured.")
        return True
    else:
        print(f"\n❌ Audit found issues that need to be addressed.")
        return False

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)