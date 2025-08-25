#!/usr/bin/env python
"""
Improved verification script to check that authentication views have response validation decorators.
"""

import os
import re
import ast

def extract_function_decorators(file_path):
    """Extract function names and their decorators using AST parsing."""
    if not os.path.exists(file_path):
        return None
    
    with open(file_path, 'r') as f:
        try:
            tree = ast.parse(f.read())
        except SyntaxError as e:
            print(f"Syntax error in {file_path}: {e}")
            return None
    
    functions = {}
    
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            decorators = []
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Name):
                    decorators.append(f"@{decorator.id}")
                elif isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Name):
                    decorators.append(f"@{decorator.func.id}")
                elif isinstance(decorator, ast.Attribute):
                    # Handle decorators like @api_view
                    decorators.append(f"@{ast.unparse(decorator)}")
            
            # Check for response validation decorators
            has_validation = any(
                'validate_response_type' in dec or 
                'ensure_drf_response' in dec or 
                'log_response_type' in dec
                for dec in decorators
            )
            
            functions[node.name] = {
                'decorators': decorators,
                'has_response_validation': has_validation,
                'line_number': node.lineno
            }
    
    return functions

def main():
    """Check authentication views for response validation decorators."""
    print("Verifying Response Validation Decorators (Improved)")
    print("=" * 50)
    
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
    total_functions = 0
    validated_functions = 0
    critical_validated = 0
    critical_total = 0
    
    for file_path in files_to_check:
        print(f"\n📁 Checking {file_path}:")
        
        functions = extract_function_decorators(file_path)
        if functions is None:
            print(f"  ❌ Could not parse file: {file_path}")
            all_good = False
            continue
        
        # Filter out private functions and class methods
        public_functions = {
            name: info for name, info in functions.items() 
            if not name.startswith('_') and name not in ['get_queryset', 'get_serializer_class', 'perform_create', 'get_object', 'destroy']
        }
        
        for func_name, info in public_functions.items():
            total_functions += 1
            is_critical = func_name in critical_functions
            has_validation = info['has_response_validation']
            
            if is_critical:
                critical_total += 1
                if has_validation:
                    critical_validated += 1
            
            if has_validation:
                validated_functions += 1
            
            status = "✅" if has_validation else "❌"
            critical_marker = " (CRITICAL)" if is_critical else ""
            
            print(f"  {status} {func_name}{critical_marker} (line {info['line_number']})")
            
            # Show response validation decorators
            validation_decorators = [
                dec for dec in info['decorators'] 
                if 'validate_response_type' in dec or 'ensure_drf_response' in dec or 'log_response_type' in dec
            ]
            
            if validation_decorators:
                for decorator in validation_decorators:
                    print(f"    ✓ {decorator}")
            elif is_critical:
                print(f"    ⚠️  CRITICAL: Missing response validation decorator!")
                all_good = False
    
    print(f"\n📊 Summary:")
    print(f"  Total functions checked: {total_functions}")
    print(f"  Functions with validation: {validated_functions}")
    print(f"  Critical functions: {critical_total}")
    print(f"  Critical functions validated: {critical_validated}")
    
    if critical_validated == critical_total:
        print("✅ All critical authentication views have response validation decorators!")
    else:
        print(f"❌ {critical_total - critical_validated} critical views missing response validation decorators.")
        all_good = False
    
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