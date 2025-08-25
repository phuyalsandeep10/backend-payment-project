#!/usr/bin/env python3
"""
Test script for Tasks 1.1.2 and 1.1.3 - Database Security and SQL Injection Testing
"""
import os
import sys
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from core_config.database_security import DatabaseSecurityValidator
from core_config.sql_injection_testing import SQLInjectionTestSuite


def test_database_security():
    """Test database security configuration (Task 1.1.2)"""
    print("🔒 Testing Database Security Configuration (Task 1.1.2)")
    print("=" * 60)
    
    try:
        validator = DatabaseSecurityValidator()
        success = validator.validate_connection_security()
        
        print(f"\n📊 Database Security Results:")
        print(f"  Security Checks: {len(validator.security_checks)}")
        print(f"  Warnings: {len(validator.warnings)}")
        print(f"  Errors: {len(validator.errors)}")
        
        if success:
            print("✅ Task 1.1.2 - Database Security: PASSED")
            return True
        else:
            print("❌ Task 1.1.2 - Database Security: FAILED")
            return False
            
    except Exception as e:
        print(f"❌ Database security test failed: {str(e)}")
        return False


def test_sql_injection_framework():
    """Test SQL injection testing framework (Task 1.1.3)"""
    print("\n🔒 Testing SQL Injection Testing Framework (Task 1.1.3)")
    print("=" * 60)
    
    try:
        test_suite = SQLInjectionTestSuite()
        
        # Run a subset of tests for validation
        print("Running sample SQL injection tests...")
        
        # Test basic payloads
        basic_payloads = [
            ("' OR '1'='1", True),  # Should be blocked
            ("admin'--", True),     # Should be blocked
            ("john.doe@example.com", False),  # Should not be blocked
            ("normal_username", False),       # Should not be blocked
        ]
        
        passed_tests = 0
        total_tests = len(basic_payloads)
        
        for payload, should_block in basic_payloads:
            test_suite._test_payload(payload, 'Sample Test', should_block)
            # Check if test passed
            last_test = test_suite.test_results['test_details'][-1]
            if last_test['passed']:
                passed_tests += 1
        
        success_rate = (passed_tests / total_tests) * 100
        
        print(f"\n📊 SQL Injection Testing Results:")
        print(f"  Sample Tests: {passed_tests}/{total_tests} ({success_rate:.1f}%)")
        print(f"  Framework Status: {'Working' if passed_tests > 0 else 'Failed'}")
        
        if success_rate >= 75:  # At least 75% of sample tests should pass
            print("✅ Task 1.1.3 - SQL Injection Testing: PASSED")
            return True
        else:
            print("❌ Task 1.1.3 - SQL Injection Testing: FAILED")
            return False
            
    except Exception as e:
        print(f"❌ SQL injection testing failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


def test_management_commands():
    """Test management commands are available"""
    print("\n🔧 Testing Management Commands")
    print("=" * 40)
    
    try:
        from django.core.management import get_commands
        commands = get_commands()
        
        required_commands = ['validate_db_security', 'test_sql_injection']
        available_commands = []
        
        for cmd in required_commands:
            if cmd in commands:
                available_commands.append(cmd)
                print(f"  ✅ {cmd} - Available")
            else:
                print(f"  ❌ {cmd} - Not found")
        
        success = len(available_commands) == len(required_commands)
        print(f"\nManagement Commands: {len(available_commands)}/{len(required_commands)} available")
        
        return success
        
    except Exception as e:
        print(f"❌ Management commands test failed: {str(e)}")
        return False


def main():
    """Main test function"""
    print("🔒 SECURITY TASKS 1.1.2 & 1.1.3 VALIDATION")
    print("Testing Database Security and SQL Injection Framework")
    print("=" * 70)
    
    results = []
    
    # Test Task 1.1.2 - Database Security
    results.append(test_database_security())
    
    # Test Task 1.1.3 - SQL Injection Testing
    results.append(test_sql_injection_framework())
    
    # Test Management Commands
    results.append(test_management_commands())
    
    # Summary
    passed_tests = sum(results)
    total_tests = len(results)
    
    print("\n" + "=" * 70)
    print("FINAL RESULTS")
    print("=" * 70)
    print(f"Tests Passed: {passed_tests}/{total_tests}")
    
    if passed_tests == total_tests:
        print("🎉 ALL TESTS PASSED!")
        print("✅ Task 1.1.2 (Database Security) - COMPLETED")
        print("✅ Task 1.1.3 (SQL Injection Testing) - COMPLETED")
        print("\n🔒 Security Features Implemented:")
        print("  • Database SSL configuration and validation")
        print("  • Connection security monitoring")
        print("  • Comprehensive SQL injection testing framework")
        print("  • Automated security testing for CI/CD")
        print("  • Management commands for security validation")
        return True
    else:
        print("❌ SOME TESTS FAILED")
        print("🔧 Please review failed tests and fix issues")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)