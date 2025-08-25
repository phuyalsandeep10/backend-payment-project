# Comprehensive Security Testing Framework

## Overview

This directory contains a comprehensive security testing framework for the Backend_PRS application. The framework includes automated security testing, vulnerability scanning, penetration testing, and security regression testing capabilities.

## Task 6.1.1: Security Test Framework ✅ COMPLETED

### Components

#### 1. Security Test Framework (`security_test_framework.py`)
- **Purpose**: Comprehensive automated security testing suite
- **Features**: 
  - Authentication & authorization testing
  - SQL injection detection
  - XSS vulnerability scanning
  - CSRF protection validation
  - File upload security testing
  - Session management analysis
  - Input validation testing
  - Access control verification

#### 2. Vulnerability Scanner (`vulnerability_scanner.py`)
- **Purpose**: Static code analysis and dependency vulnerability scanning
- **Features**:
  - Pattern-based vulnerability detection
  - Dependency security scanning
  - Configuration security analysis
  - File permission auditing
  - Risk scoring and reporting

#### 3. Penetration Testing (`penetration_testing.py`)
- **Purpose**: Automated penetration testing capabilities
- **Features**:
  - Web application reconnaissance
  - Authentication bypass testing
  - Business logic vulnerability testing
  - Session security assessment
  - Error handling analysis

#### 4. Comprehensive Test Runner (`run_all_security_tests.py`)
- **Purpose**: Unified entry point for all security testing
- **Features**:
  - Orchestrates all security testing components
  - Generates consolidated reports
  - Provides compliance assessment
  - Supports selective test execution

## Usage

### Quick Start

```bash
# Run all security tests
python run_all_security_tests.py

# Run with specific options
python run_all_security_tests.py --project-path /path/to/project --target-url http://localhost:8000

# Run only vulnerability scanner
python run_all_security_tests.py --scanner --no-framework --no-regression

# Run with penetration testing
python run_all_security_tests.py --pentest --target-url http://localhost:8000
```

### Django Management Command

```bash
# Run security tests via Django management command
python manage.py run_security_tests

# Run specific categories
python manage.py run_security_tests --category authentication

# Generate detailed report
python manage.py run_security_tests --format json --output security_report.json

# Set failure threshold
python manage.py run_security_tests --fail-on medium
```

### Individual Components

#### Security Test Framework
```python
from security_test_framework import SecurityTestFramework

framework = SecurityTestFramework()
report = framework.run_comprehensive_security_tests()
```

#### Vulnerability Scanner
```python
from vulnerability_scanner import VulnerabilityScanner

scanner = VulnerabilityScanner('/path/to/project')
report = scanner.run_comprehensive_scan()
```

#### Penetration Testing
```python
from penetration_testing import PenetrationTester, PenTestTarget

target = PenTestTarget(base_url='http://localhost:8000')
tester = PenetrationTester(target)
report = tester.run_comprehensive_pentest()
```

## Configuration

### Environment Variables

```bash
# Optional: Configure test timeouts
export SECURITY_TEST_TIMEOUT=300

# Optional: Set custom report directory
export SECURITY_REPORT_DIR=/path/to/reports

# Optional: Configure test database
export TEST_DATABASE_URL=postgresql://test:test@localhost/test_db
```

### Test Configuration

Create `security_test_config.json` in the tests directory:

```json
{
  "framework_options": {
    "run_authentication_tests": true,
    "run_injection_tests": true,
    "run_xss_tests": true,
    "test_timeout_seconds": 30
  },
  "scanner_options": {
    "exclude_directories": ["node_modules", "venv", ".git"],
    "scan_extensions": [".py", ".js", ".html"],
    "severity_threshold": "medium"
  },
  "pentest_options": {
    "max_requests_per_minute": 60,
    "authentication": {
      "username": "testuser",
      "password": "testpass"
    }
  }
}
```

## Security Test Categories

### 1. Authentication & Authorization
- Password strength validation
- Account lockout mechanisms
- Session management
- Multi-factor authentication
- Privilege escalation

### 2. Injection Attacks
- SQL injection
- Command injection
- LDAP injection
- NoSQL injection
- XPath injection

### 3. Cross-Site Scripting (XSS)
- Reflected XSS
- Stored XSS
- DOM-based XSS
- Content Security Policy validation

### 4. Cross-Site Request Forgery (CSRF)
- CSRF token validation
- SameSite cookie attributes
- Referer header checks

### 5. File Upload Security
- File type validation
- Malicious file detection
- Path traversal prevention
- File size limits

### 6. Session Management
- Session fixation
- Session hijacking
- Cookie security attributes
- Session timeout

### 7. Configuration Security
- Debug mode detection
- Security headers analysis
- SSL/TLS configuration
- Default credentials

### 8. Input Validation
- Parameter tampering
- Buffer overflow
- Format string vulnerabilities
- Unicode attacks

### 9. Access Control
- Broken access control
- Insecure direct object references
- Missing function level access control
- Privilege escalation

### 10. Business Logic
- Workflow bypass
- Parameter manipulation
- Race conditions
- Time-based attacks

## Report Generation

### Report Formats

The framework generates reports in multiple formats:

1. **JSON Report** - Machine-readable detailed results
2. **HTML Report** - Human-readable web format
3. **Text Summary** - Console-friendly overview
4. **CSV Export** - Spreadsheet-compatible format

### Report Contents

Each report includes:
- Executive summary with risk scores
- Detailed vulnerability findings
- Evidence and proof-of-concept
- Remediation recommendations
- Compliance assessment
- Test execution metrics

### Sample Report Structure

```json
{
  "report_metadata": {
    "generated_at": "2024-01-15T10:30:00Z",
    "framework_version": "1.0.0",
    "total_execution_time_ms": 45000
  },
  "executive_summary": {
    "overall_security_score": 85,
    "risk_level": "MEDIUM",
    "total_tests": 156,
    "tests_passed": 142,
    "tests_failed": 14,
    "vulnerabilities_found": 3
  },
  "vulnerability_summary": {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 0,
    "info": 0
  },
  "recommendations": [
    {
      "category": "injection",
      "priority": "high",
      "recommendation": "Implement parameterized queries to prevent SQL injection",
      "affected_components": ["user_search", "product_filter"]
    }
  ]
}
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Testing

on: [push, pull_request]

jobs:
  security-tests:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: 3.9
    
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
    
    - name: Run security tests
      run: |
        cd tests/security
        python run_all_security_tests.py --output security_report.json
    
    - name: Upload security report
      uses: actions/upload-artifact@v2
      with:
        name: security-report
        path: tests/security/security_report.json
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('Security Tests') {
            steps {
                script {
                    sh '''
                        cd tests/security
                        python run_all_security_tests.py --format json --output ${WORKSPACE}/security_report.json
                    '''
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'security_report.json', fingerprint: true
                    publishHTML([
                        allowMissing: false,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: 'tests/security',
                        reportFiles: 'security_report.html',
                        reportName: 'Security Test Report'
                    ])
                }
            }
        }
    }
}
```

## Best Practices

### 1. Regular Testing Schedule
- Run full security suite weekly
- Run critical tests on every deployment
- Schedule monthly penetration tests
- Perform quarterly comprehensive assessments

### 2. Test Environment Management
- Use dedicated test environments
- Isolate security tests from production
- Maintain test data consistency
- Clean up after tests

### 3. Results Analysis
- Triage findings by risk level
- Track remediation progress
- Monitor for regressions
- Document false positives

### 4. Continuous Improvement
- Update test patterns regularly
- Add new vulnerability checks
- Refine detection algorithms
- Incorporate threat intelligence

## Troubleshooting

### Common Issues

#### 1. Import Errors
```bash
# Ensure Python path includes tests directory
export PYTHONPATH="${PYTHONPATH}:/path/to/Backend_PRS/tests"
```

#### 2. Database Connection Issues
```bash
# Set test database URL
export DATABASE_URL="sqlite:///test.db"

# Or use Django test database
python manage.py test --settings=core_config.test_settings
```

#### 3. Permission Errors
```bash
# Ensure proper file permissions
chmod +x run_all_security_tests.py

# Run with appropriate user permissions
sudo -u www-data python run_security_tests.py
```

#### 4. Network Timeouts
```bash
# Increase timeout values
export SECURITY_TEST_TIMEOUT=600

# Or configure in test files
TEST_TIMEOUT = 300  # 5 minutes
```

### Debug Mode

Enable debug mode for detailed output:

```bash
# Enable verbose logging
python run_all_security_tests.py --verbose

# Enable debug mode in code
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Security Considerations

### Test Data Security
- Use synthetic test data only
- Never test against production data
- Encrypt sensitive test configurations
- Implement proper access controls

### Test Environment Isolation
- Isolate test networks
- Use containerized environments
- Implement proper firewall rules
- Monitor test activities

### Results Protection
- Encrypt security reports
- Implement access controls
- Store results securely
- Follow data retention policies

## Contributing

### Adding New Tests

1. **Create test class** extending base security test
2. **Implement test methods** following naming conventions
3. **Add vulnerability patterns** to scanner configuration
4. **Update documentation** with new test descriptions
5. **Add test cases** for new functionality

### Code Style

- Follow PEP 8 Python style guidelines
- Use type hints for better code clarity
- Document all public methods and classes
- Write comprehensive docstrings

### Testing Guidelines

- Test all new security test functionality
- Ensure backwards compatibility
- Validate report generation
- Test error handling scenarios

## Support

For issues and questions:
- Create GitHub issues for bugs
- Submit pull requests for enhancements
- Contact security team for urgent vulnerabilities
- Review documentation for common solutions

## License

This security testing framework is proprietary software. All rights reserved.
