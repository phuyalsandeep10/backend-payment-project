#!/usr/bin/env python
"""
Test script to verify that the validation fixes are working correctly
"""

import os
import sys
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from core.security.input_validation_service import input_validator

def test_validation_fixes():
    """Test that the validation fixes work correctly"""
    
    print("🧪 Testing validation fixes...")
    
    # Test data that was previously flagged as command injection
    test_cases = [
        ("client_id", "123"),
        ("deal_name", "Test Deal (Project Alpha)"),
        ("payment_status", "full_payment"),
        ("source_type", "linkedin"),
        ("currency", "USD"),
        ("deal_value", "$1000.00"),
        ("deal_date", "2025-01-15"),
        ("due_date", "2025-02-15"),
        ("payment_method", "bank"),
        ("deal_remarks", "This is a test deal with some (parentheses) and $symbols"),
        ("payments[0][payment_date]", "2025-01-15"),
        ("payments[0][received_amount]", "1000.00"),
        ("payments[0][cheque_number]", "CHQ-12345"),
        ("payments[0][payment_remarks]", "Initial payment for project"),
        ("payments[0][receipt_file]", "receipt.pdf"),
    ]
    
    print("\n📋 Testing individual field validation:")
    
    all_passed = True
    for field_name, value in test_cases:
        # Test command injection detection
        is_command_injection = input_validator.check_command_injection(value)
        
        # Test overall validation
        validation_result = input_validator.validate_input(value, field_name)
        
        status = "✅ PASS" if validation_result.is_valid else "❌ FAIL"
        print(f"  {status} {field_name}: '{value}' -> Valid: {validation_result.is_valid}")
        
        if not validation_result.is_valid:
            print(f"    Errors: {validation_result.errors}")
            all_passed = False
    
    print(f"\n🎯 Overall result: {'✅ ALL TESTS PASSED' if all_passed else '❌ SOME TESTS FAILED'}")
    
    # Test the safe field detection
    print("\n🔒 Testing safe field detection:")
    safe_fields = [
        "client_id", "deal_name", "payment_status", "source_type", 
        "currency", "deal_value", "payments[0][payment_date]"
    ]
    
    for field in safe_fields:
        is_safe = input_validator._is_safe_form_field(field)
        status = "✅ SAFE" if is_safe else "❌ NOT SAFE"
        print(f"  {status} {field}")
    
    # Test legitimate form data detection
    print("\n📝 Testing legitimate form data detection:")
    legitimate_values = [
        "1000.00", "$1000.00", "full_payment", "linkedin", "USD", 
        "2025-01-15", "Test Deal (Project Alpha)", "CHQ-12345"
    ]
    
    for value in legitimate_values:
        is_legitimate = input_validator._is_legitimate_form_data(value)
        status = "✅ LEGITIMATE" if is_legitimate else "❌ SUSPICIOUS"
        print(f"  {status} '{value}'")
    
    return all_passed

if __name__ == "__main__":
    success = test_validation_fixes()
    sys.exit(0 if success else 1)