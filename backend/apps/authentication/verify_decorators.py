#!/usr/bin/env python
"""
Simple verification script to check that authentication views have response validation decorators.
"""

import os
import re

def check_file_for_decorators(file_path):
    """Check a Python file for response validation decorators."""
    if not os.path.exists(file_path):
        return None
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Find all function definitions with decorators
    function_pattern = r'(@[\w_]+\s*\n)*\s*def\s+(\w+)\s*\('
    matches = re.finditer(function_pattern, content, re.MULTILINE)
    
    results = {}
    
    for match in matches:
        func_name = match.group(2)
        # Get the decorators for this function
        start_pos = match.start()
        
        # Look backwards to find all decorators
        lines_before = content[:start_pos].split('\n')
        decorators = []
        
        # Look at lines before the function definition
        for i in range(len(lines_before) - 1, -1, -1):
            line = lines_before[i].strip()
            if line.startswith('@'):
                decorators.insert(0, line)
            elif line and not line.startswith('#'):
                # Stop if we hit a non-decorator, non-comment line
                break
        
        results[func_name] = {
            'decorators': decorators,
            'has_response_validation': any(
                '@validate_response_type' in decorator or 
                '@ensure_drf_response' in decorator or 
                '@log_response_type' in decorator
                for decorator in decorators
            )
        }
    
    return results

def main():
    """Check authentication views for response validation decorators."""
    print("Verifying Response Validation Decorators")
    print("=" * 45)
    
    # Files to check
    files_to_check = [
        'authentication/views.py',
        'authentication/password_views.py'
    ]
    
    critical_functions = [
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
    
    all_good = True
    
    for file_path in files_to_check:
        print(f"\n📁 Checking {file_path}:")
        
        results = check_file_for_decorators(file_path)
        if results is None:
            print(f"  ❌ File not found: {file_path}")
            all_good = False
            continue
        
        for func_name, info in results.items():
            # Skip helper functions and private functions
            if func_name.startswith('_') or func_name in ['get_client_ip', 'authenticate']:
                continue
            
            is_critical = func_name in critical_functions
            has_validation = info['has_response_validation']
            
            status = "✅" if has_validation else "❌"
            critical_marker = " (CRITICAL)" if is_critical else ""
            
            print(f"  {status} {func_name}{critical_marker}")
            
            if info['decorators']:
                for decorator in info['decorators']:
                    if ('@validate_response_type' in decorator or 
                        '@ensure_drf_response' in decorator or 
                        '@log_response_type' in decorator):
                        print(f"    ✓ {decorator}")
                    elif decorator.startswith('@'):
                        print(f"    - {decorator}")
            
            if not has_validation:
                all_good = False
                if is_critical:
                    print(f"    ⚠️  CRITICAL: Missing response validation decorator!")
    
    print(f"\n📊 Summary:")
    if all_good:
        print("✅ All authentication views have proper response validation decorators!")
    else:
        print("❌ Some views are missing response validation decorators.")
    
    # Check for imports
    print(f"\n🔍 Checking imports:")
    for file_path in files_to_check:
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                content = f.read()
            
            if 'from .response_validators import' in content:
                print(f"  ✅ {file_path} imports response validators")
            else:
                print(f"  ❌ {file_path} missing response validator imports")
                all_good = False
    
    return all_good

if __name__ == '__main__':
    success = main()
    exit(0 if success else 1)