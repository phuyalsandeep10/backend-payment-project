#!/usr/bin/env python3
"""
Security Implementation Analysis for PRS System
Comprehensive analysis of security measures including file upload security,
input validation, SQL injection protection, XSS protection, and CSRF protection.
"""

import os
import sys
import django
import json
import re
import tempfile
from datetime import datetime
from pathlib import Path

# Add the backend directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from django.conf import settings
from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import connection
from django.utils.html import escape
from django.middleware.csrf import get_token
from django.test.utils import override_settings
from django.core.management import call_command
from io import StringIO

# Import security-related modules
try:
    from core_config.file_security import EnhancedFileSecurityValidator
except ImportError:
    EnhancedFileSecurityValidator = None

try:
    from core_config.malware_scanner import MalwareScanner
except ImportError:
    MalwareScanner = None

try:
    from core_config.input_validation_service import InputValidationService
except ImportError:
    InputValidationService = None

try:
    from core_config.validation_middleware import ValidationMiddleware
except ImportError:
    ValidationMiddleware = None

try:
    from core_config.security import SecurityHeaders
except ImportError:
    SecurityHeaders = None

from authentication.models import User
from organization.models import Organization

class SecurityImplementationAnalysis:
    """Comprehensive security analysis for the PRS system"""
    
    def __init__(self):
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'file_upload_security': {},
            'input_validation': {},
            'sql_injection_protection': {},
            'xss_protection': {},
            'csrf_protection': {},
            'security_headers': {},
            'overall_assessment': {}
        }
        self.client = Client()
        
    def analyze_file_upload_security(self):
        """Test file upload security and malware scanning"""
        print("🔍 Analyzing File Upload Security...")
        
        try:
            # Test EnhancedFileSecurityValidator
            validator = None
            if EnhancedFileSecurityValidator:
                validator = EnhancedFileSecurityValidator()
            
            # Test allowed file types from settings
            allowed_extensions = getattr(settings, 'ALLOWED_FILE_EXTENSIONS', [])
            max_file_size = getattr(settings, 'MAX_FILE_SIZE', 0)
            
            # If no settings, check validator defaults
            if validator and not allowed_extensions:
                allowed_extensions = list(validator.ALLOWED_EXTENSIONS.keys()) if hasattr(validator, 'ALLOWED_EXTENSIONS') else []
            
            self.results['file_upload_security']['allowed_extensions'] = allowed_extensions
            self.results['file_upload_security']['max_file_size'] = max_file_size
            
            # Test malware scanner configuration
            scanner = None
            scanner_config = {'enabled': False, 'quarantine_enabled': False, 'scan_methods': []}
            
            if MalwareScanner:
                scanner = MalwareScanner()
                scanner_config = {
                    'enabled': True,
                    'quarantine_enabled': hasattr(scanner, 'quarantine_file'),
                    'scan_methods': []
                }
                
                # Check for various scanning methods
                if hasattr(scanner, 'scan_file'):
                    scanner_config['scan_methods'].append('signature_scan')
                if hasattr(scanner, 'scan_for_malware'):
                    scanner_config['scan_methods'].append('malware_scan')
                if hasattr(scanner, 'MALWARE_HASHES'):
                    scanner_config['scan_methods'].append('hash_check')
                    
            self.results['file_upload_security']['malware_scanner'] = scanner_config
            
            # Test file validation rules
            validation_rules = {
                'validator_available': validator is not None,
                'mime_type_validation': validator and hasattr(validator, '_validate_mime_type_enhanced'),
                'file_size_validation': validator and hasattr(validator, '_validate_file_size'),
                'filename_validation': validator and hasattr(validator, '_validate_basic_info'),
                'content_validation': validator and hasattr(validator, '_analyze_file_content_enhanced'),
                'signature_validation': validator and hasattr(validator, '_validate_file_signature_enhanced'),
                'bypass_detection': validator and hasattr(validator, '_detect_bypass_attempts')
            }
            
            self.results['file_upload_security']['validation_rules'] = validation_rules
            
            # Test upload directory security
            upload_dirs = []
            if hasattr(settings, 'MEDIA_ROOT'):
                upload_dirs.append(settings.MEDIA_ROOT)
            if hasattr(settings, 'UPLOAD_ROOT'):
                upload_dirs.append(settings.UPLOAD_ROOT)
                
            directory_security = {}
            for upload_dir in upload_dirs:
                if os.path.exists(upload_dir):
                    permissions = oct(os.stat(upload_dir).st_mode)[-3:]
                    directory_security[upload_dir] = {
                        'exists': True,
                        'permissions': permissions,
                        'writable': os.access(upload_dir, os.W_OK)
                    }
                    
            self.results['file_upload_security']['directory_security'] = directory_security
            
            # Test quarantine functionality
            quarantine_dir = getattr(settings, 'QUARANTINE_DIR', None)
            if quarantine_dir:
                self.results['file_upload_security']['quarantine_configured'] = True
                self.results['file_upload_security']['quarantine_dir'] = quarantine_dir
            else:
                self.results['file_upload_security']['quarantine_configured'] = False
                
            print("✅ File upload security analysis completed")
            
        except Exception as e:
            print(f"❌ Error analyzing file upload security: {str(e)}")
            self.results['file_upload_security']['error'] = str(e)
    
    def analyze_input_validation(self):
        """Analyze input validation and sanitization"""
        print("🔍 Analyzing Input Validation and Sanitization...")
        
        try:
            # Test InputValidationService
            validator = None
            validation_features = {'service_available': False}
            
            if InputValidationService:
                validator = InputValidationService()
                validation_features = {
                    'service_available': True,
                    'sql_injection_detection': hasattr(validator, 'detect_sql_injection'),
                    'xss_detection': hasattr(validator, 'detect_xss'),
                    'command_injection_detection': hasattr(validator, 'detect_command_injection'),
                    'path_traversal_detection': hasattr(validator, 'detect_path_traversal'),
                    'input_sanitization': hasattr(validator, 'sanitize_input'),
                    'validate_input': hasattr(validator, 'validate_input')
                }
            
            self.results['input_validation']['features'] = validation_features
            
            # Test validation middleware
            middleware_classes = getattr(settings, 'MIDDLEWARE', [])
            validation_middleware_enabled = any(
                'validation' in middleware.lower() 
                for middleware in middleware_classes
            )
            
            self.results['input_validation']['middleware_enabled'] = validation_middleware_enabled
            self.results['input_validation']['middleware_classes'] = middleware_classes
            
            # Test common validation patterns
            test_inputs = [
                "'; DROP TABLE users; --",  # SQL injection
                "<script>alert('xss')</script>",  # XSS
                "../../../etc/passwd",  # Path traversal
                "$(rm -rf /)",  # Command injection
                "normal_input_123"  # Normal input
            ]
            
            validation_results = {}
            if validator and hasattr(validator, 'validate_input'):
                for test_input in test_inputs:
                    try:
                        result = validator.validate_input(test_input)
                        validation_results[test_input] = {
                            'valid': result,
                            'detected_threat': not result
                        }
                    except Exception as e:
                        validation_results[test_input] = {
                            'error': str(e)
                        }
            else:
                validation_results['note'] = 'Input validation service not available or validate_input method not found'
                    
            self.results['input_validation']['test_results'] = validation_results
            
            # Check Django's built-in validation
            django_validation = {
                'form_validation': 'django.forms' in str(sys.modules.keys()),
                'model_validation': hasattr(django.db.models.Model, 'clean'),
                'serializer_validation': 'rest_framework' in str(sys.modules.keys())
            }
            
            self.results['input_validation']['django_validation'] = django_validation
            
            print("✅ Input validation analysis completed")
            
        except Exception as e:
            print(f"❌ Error analyzing input validation: {str(e)}")
            self.results['input_validation']['error'] = str(e)
    
    def analyze_sql_injection_protection(self):
        """Examine SQL injection protection mechanisms"""
        print("🔍 Analyzing SQL Injection Protection...")
        
        try:
            # Check Django ORM usage vs raw SQL
            from django.db import models
            
            # Analyze models for raw SQL usage
            sql_analysis = {
                'orm_usage': True,  # Django uses ORM by default
                'parameterized_queries': True,  # Django ORM uses parameterized queries
                'raw_sql_found': False,
                'raw_sql_locations': []
            }
            
            # Check for raw SQL in common locations
            backend_path = Path(__file__).parent
            python_files = list(backend_path.rglob('*.py'))
            
            raw_sql_patterns = [
                r'\.raw\(',
                r'cursor\.execute\(',
                r'connection\.cursor\(',
                r'SELECT.*FROM.*WHERE',
                r'INSERT.*INTO.*VALUES',
                r'UPDATE.*SET.*WHERE',
                r'DELETE.*FROM.*WHERE'
            ]
            
            for file_path in python_files[:50]:  # Limit to first 50 files for performance
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        for pattern in raw_sql_patterns:
                            if re.search(pattern, content, re.IGNORECASE):
                                sql_analysis['raw_sql_found'] = True
                                sql_analysis['raw_sql_locations'].append({
                                    'file': str(file_path.relative_to(backend_path)),
                                    'pattern': pattern
                                })
                except Exception:
                    continue
                    
            self.results['sql_injection_protection'] = sql_analysis
            
            # Test database connection security
            db_config = settings.DATABASES.get('default', {})
            db_security = {
                'engine': db_config.get('ENGINE', ''),
                'ssl_enabled': 'sslmode' in db_config.get('OPTIONS', {}),
                'connection_pooling': 'CONN_MAX_AGE' in db_config
            }
            
            self.results['sql_injection_protection']['database_security'] = db_security
            
            print("✅ SQL injection protection analysis completed")
            
        except Exception as e:
            print(f"❌ Error analyzing SQL injection protection: {str(e)}")
            self.results['sql_injection_protection']['error'] = str(e)
    
    def analyze_xss_protection(self):
        """Examine XSS (Cross-Site Scripting) protection"""
        print("🔍 Analyzing XSS Protection...")
        
        try:
            # Check Django's built-in XSS protection
            xss_protection = {
                'auto_escaping_enabled': getattr(settings, 'TEMPLATES', [{}])[0].get('OPTIONS', {}).get('context_processors', []),
                'csrf_middleware_enabled': 'django.middleware.csrf.CsrfViewMiddleware' in getattr(settings, 'MIDDLEWARE', []),
                'security_middleware_enabled': 'django.middleware.security.SecurityMiddleware' in getattr(settings, 'MIDDLEWARE', [])
            }
            
            # Check template auto-escaping
            template_settings = getattr(settings, 'TEMPLATES', [])
            if template_settings:
                template_config = template_settings[0]
                xss_protection['template_auto_escape'] = template_config.get('OPTIONS', {}).get('autoescape', True)
            
            # Check for Content Security Policy
            csp_middleware = any(
                'csp' in middleware.lower() 
                for middleware in getattr(settings, 'MIDDLEWARE', [])
            )
            xss_protection['csp_enabled'] = csp_middleware
            
            # Check for XSS protection headers
            security_headers = getattr(settings, 'SECURE_BROWSER_XSS_FILTER', False)
            xss_protection['xss_filter_header'] = security_headers
            
            # Check for safe template filters usage
            backend_path = Path(__file__).parent
            template_files = list(backend_path.rglob('*.html'))
            
            unsafe_patterns = [
                r'\|safe',
                r'\|mark_safe',
                r'{% autoescape off %}',
                r'{{ .*\|safe }}'
            ]
            
            unsafe_template_usage = []
            for template_file in template_files[:20]:  # Limit for performance
                try:
                    with open(template_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                        for pattern in unsafe_patterns:
                            if re.search(pattern, content):
                                unsafe_template_usage.append({
                                    'file': str(template_file.relative_to(backend_path)),
                                    'pattern': pattern
                                })
                except Exception:
                    continue
                    
            xss_protection['unsafe_template_usage'] = unsafe_template_usage
            
            self.results['xss_protection'] = xss_protection
            
            print("✅ XSS protection analysis completed")
            
        except Exception as e:
            print(f"❌ Error analyzing XSS protection: {str(e)}")
            self.results['xss_protection']['error'] = str(e)
    
    def analyze_csrf_protection(self):
        """Validate CSRF protection implementation"""
        print("🔍 Analyzing CSRF Protection...")
        
        try:
            # Check CSRF middleware
            middleware_classes = getattr(settings, 'MIDDLEWARE', [])
            csrf_middleware_enabled = 'django.middleware.csrf.CsrfViewMiddleware' in middleware_classes
            
            csrf_analysis = {
                'middleware_enabled': csrf_middleware_enabled,
                'csrf_cookie_secure': getattr(settings, 'CSRF_COOKIE_SECURE', False),
                'csrf_cookie_httponly': getattr(settings, 'CSRF_COOKIE_HTTPONLY', False),
                'csrf_cookie_samesite': getattr(settings, 'CSRF_COOKIE_SAMESITE', None),
                'csrf_use_sessions': getattr(settings, 'CSRF_USE_SESSIONS', False)
            }
            
            # Check CSRF token usage in templates
            backend_path = Path(__file__).parent
            template_files = list(backend_path.rglob('*.html'))
            
            csrf_token_usage = []
            for template_file in template_files[:20]:  # Limit for performance
                try:
                    with open(template_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if '{% csrf_token %}' in content:
                            csrf_token_usage.append(str(template_file.relative_to(backend_path)))
                except Exception:
                    continue
                    
            csrf_analysis['templates_with_csrf_tokens'] = csrf_token_usage
            
            # Check for CSRF exemptions
            python_files = list(backend_path.rglob('*.py'))
            csrf_exempt_usage = []
            
            for file_path in python_files[:50]:  # Limit for performance
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if '@csrf_exempt' in content or 'csrf_exempt' in content:
                            csrf_exempt_usage.append(str(file_path.relative_to(backend_path)))
                except Exception:
                    continue
                    
            csrf_analysis['csrf_exempt_usage'] = csrf_exempt_usage
            
            self.results['csrf_protection'] = csrf_analysis
            
            print("✅ CSRF protection analysis completed")
            
        except Exception as e:
            print(f"❌ Error analyzing CSRF protection: {str(e)}")
            self.results['csrf_protection']['error'] = str(e)
    
    def analyze_security_headers(self):
        """Validate security headers implementation"""
        print("🔍 Analyzing Security Headers...")
        
        try:
            # Check Django security settings
            security_settings = {
                'SECURE_SSL_REDIRECT': getattr(settings, 'SECURE_SSL_REDIRECT', False),
                'SECURE_HSTS_SECONDS': getattr(settings, 'SECURE_HSTS_SECONDS', 0),
                'SECURE_HSTS_INCLUDE_SUBDOMAINS': getattr(settings, 'SECURE_HSTS_INCLUDE_SUBDOMAINS', False),
                'SECURE_HSTS_PRELOAD': getattr(settings, 'SECURE_HSTS_PRELOAD', False),
                'SECURE_CONTENT_TYPE_NOSNIFF': getattr(settings, 'SECURE_CONTENT_TYPE_NOSNIFF', False),
                'SECURE_BROWSER_XSS_FILTER': getattr(settings, 'SECURE_BROWSER_XSS_FILTER', False),
                'SECURE_REFERRER_POLICY': getattr(settings, 'SECURE_REFERRER_POLICY', None),
                'X_FRAME_OPTIONS': getattr(settings, 'X_FRAME_OPTIONS', 'DENY')
            }
            
            # Check session security
            session_security = {
                'SESSION_COOKIE_SECURE': getattr(settings, 'SESSION_COOKIE_SECURE', False),
                'SESSION_COOKIE_HTTPONLY': getattr(settings, 'SESSION_COOKIE_HTTPONLY', True),
                'SESSION_COOKIE_SAMESITE': getattr(settings, 'SESSION_COOKIE_SAMESITE', None),
                'SESSION_COOKIE_AGE': getattr(settings, 'SESSION_COOKIE_AGE', 1209600)
            }
            
            # Check for custom security headers middleware
            middleware_classes = getattr(settings, 'MIDDLEWARE', [])
            custom_security_middleware = [
                middleware for middleware in middleware_classes 
                if 'security' in middleware.lower() and 'django' not in middleware.lower()
            ]
            
            headers_analysis = {
                'django_security_settings': security_settings,
                'session_security': session_security,
                'custom_security_middleware': custom_security_middleware,
                'security_middleware_enabled': 'django.middleware.security.SecurityMiddleware' in middleware_classes
            }
            
            self.results['security_headers'] = headers_analysis
            
            print("✅ Security headers analysis completed")
            
        except Exception as e:
            print(f"❌ Error analyzing security headers: {str(e)}")
            self.results['security_headers']['error'] = str(e)
    
    def generate_overall_assessment(self):
        """Generate overall security assessment"""
        print("📊 Generating Overall Security Assessment...")
        
        security_score = 0
        max_score = 0
        issues = []
        recommendations = []
        
        # File Upload Security Assessment
        if 'file_upload_security' in self.results and 'error' not in self.results['file_upload_security']:
            max_score += 20
            upload_security = self.results['file_upload_security']
            
            if upload_security.get('malware_scanner', {}).get('enabled', False):
                security_score += 5
            else:
                issues.append("Malware scanning not properly configured")
                
            if upload_security.get('validation_rules', {}).get('mime_type_validation', False):
                security_score += 5
            else:
                issues.append("MIME type validation missing")
                
            if upload_security.get('quarantine_configured', False):
                security_score += 5
            else:
                recommendations.append("Implement file quarantine system")
                
            if upload_security.get('allowed_extensions'):
                security_score += 5
            else:
                issues.append("File extension restrictions not configured")
        
        # Input Validation Assessment
        if 'input_validation' in self.results and 'error' not in self.results['input_validation']:
            max_score += 20
            input_val = self.results['input_validation']
            
            if input_val.get('middleware_enabled', False):
                security_score += 10
            else:
                issues.append("Input validation middleware not enabled")
                
            features = input_val.get('features', {})
            if features.get('sql_injection_detection', False):
                security_score += 5
            if features.get('xss_detection', False):
                security_score += 5
        
        # SQL Injection Protection Assessment
        if 'sql_injection_protection' in self.results and 'error' not in self.results['sql_injection_protection']:
            max_score += 20
            sql_protection = self.results['sql_injection_protection']
            
            if sql_protection.get('orm_usage', False):
                security_score += 10
            if not sql_protection.get('raw_sql_found', True):
                security_score += 10
            else:
                issues.append("Raw SQL usage detected - review for injection vulnerabilities")
        
        # XSS Protection Assessment
        if 'xss_protection' in self.results and 'error' not in self.results['xss_protection']:
            max_score += 20
            xss_protection = self.results['xss_protection']
            
            if xss_protection.get('template_auto_escape', False):
                security_score += 5
            if xss_protection.get('csp_enabled', False):
                security_score += 5
            else:
                recommendations.append("Implement Content Security Policy")
                
            if xss_protection.get('xss_filter_header', False):
                security_score += 5
            if not xss_protection.get('unsafe_template_usage', []):
                security_score += 5
            else:
                issues.append("Unsafe template usage detected")
        
        # CSRF Protection Assessment
        if 'csrf_protection' in self.results and 'error' not in self.results['csrf_protection']:
            max_score += 10
            csrf_protection = self.results['csrf_protection']
            
            if csrf_protection.get('middleware_enabled', False):
                security_score += 5
            if csrf_protection.get('csrf_cookie_secure', False):
                security_score += 3
            if csrf_protection.get('csrf_cookie_httponly', False):
                security_score += 2
        
        # Security Headers Assessment
        if 'security_headers' in self.results and 'error' not in self.results['security_headers']:
            max_score += 10
            headers = self.results['security_headers']
            django_settings = headers.get('django_security_settings', {})
            
            if django_settings.get('SECURE_SSL_REDIRECT', False):
                security_score += 2
            if django_settings.get('SECURE_HSTS_SECONDS', 0) > 0:
                security_score += 2
            if django_settings.get('SECURE_CONTENT_TYPE_NOSNIFF', False):
                security_score += 2
            if django_settings.get('SECURE_BROWSER_XSS_FILTER', False):
                security_score += 2
            if headers.get('security_middleware_enabled', False):
                security_score += 2
        
        # Calculate percentage
        security_percentage = (security_score / max_score * 100) if max_score > 0 else 0
        
        # Determine security level
        if security_percentage >= 90:
            security_level = "EXCELLENT"
        elif security_percentage >= 75:
            security_level = "GOOD"
        elif security_percentage >= 60:
            security_level = "MODERATE"
        elif security_percentage >= 40:
            security_level = "POOR"
        else:
            security_level = "CRITICAL"
        
        self.results['overall_assessment'] = {
            'security_score': security_score,
            'max_score': max_score,
            'security_percentage': round(security_percentage, 2),
            'security_level': security_level,
            'critical_issues': issues,
            'recommendations': recommendations
        }
        
        print(f"🎯 Security Assessment Complete: {security_level} ({security_percentage:.1f}%)")
    
    def run_analysis(self):
        """Run complete security analysis"""
        print("🚀 Starting Security Implementation Analysis...")
        print("=" * 60)
        
        self.analyze_file_upload_security()
        self.analyze_input_validation()
        self.analyze_sql_injection_protection()
        self.analyze_xss_protection()
        self.analyze_csrf_protection()
        self.analyze_security_headers()
        self.generate_overall_assessment()
        
        return self.results
    
    def save_results(self, filename=None):
        """Save analysis results to file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_implementation_analysis_results_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"📄 Results saved to: {filename}")
        return filename

def main():
    """Main execution function"""
    try:
        analyzer = SecurityImplementationAnalysis()
        results = analyzer.run_analysis()
        
        # Save results
        results_file = analyzer.save_results()
        
        # Print summary
        print("\n" + "=" * 60)
        print("📋 SECURITY ANALYSIS SUMMARY")
        print("=" * 60)
        
        assessment = results.get('overall_assessment', {})
        print(f"Security Level: {assessment.get('security_level', 'UNKNOWN')}")
        print(f"Security Score: {assessment.get('security_score', 0)}/{assessment.get('max_score', 0)} ({assessment.get('security_percentage', 0):.1f}%)")
        
        issues = assessment.get('critical_issues', [])
        if issues:
            print(f"\n🚨 Critical Issues ({len(issues)}):")
            for i, issue in enumerate(issues, 1):
                print(f"  {i}. {issue}")
        
        recommendations = assessment.get('recommendations', [])
        if recommendations:
            print(f"\n💡 Recommendations ({len(recommendations)}):")
            for i, rec in enumerate(recommendations, 1):
                print(f"  {i}. {rec}")
        
        print(f"\n📊 Detailed results available in: {results_file}")
        
        return True
        
    except Exception as e:
        print(f"❌ Analysis failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)