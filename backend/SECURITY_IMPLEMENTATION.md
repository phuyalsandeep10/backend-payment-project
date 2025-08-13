# Security Implementation Guide

## Overview

This document describes the comprehensive security implementation for the PRS (Payment Receiving System) that addresses critical vulnerabilities and implements defense-in-depth security measures.

## Components Implemented

### 1. Enhanced File Security Validator (`core_config/file_security.py`)

The `EnhancedFileSecurityValidator` provides comprehensive file upload security:

#### Features:
- **Multi-layer Validation**: Extension, size, signature, MIME type, and content validation
- **Malware Detection**: Advanced signature-based and heuristic malware scanning
- **Bypass Prevention**: Prevents common file upload bypass techniques
- **Type-specific Validation**: Specialized validation for images, PDFs, and documents
- **Polyglot Detection**: Identifies files valid in multiple formats
- **Entropy Analysis**: Detects packed or encrypted malicious content
- **Hash-based Detection**: Maintains database of known malware hashes

#### Usage:
```python
from core_config.file_security import EnhancedFileSecurityValidator

validator = EnhancedFileSecurityValidator()
result = validator.validate_file_comprehensive(uploaded_file)
```

### 2. Advanced Malware Scanner (`core_config/malware_scanner.py`)

The `MalwareScanner` provides advanced threat detection:

#### Features:
- **Signature Database**: Maintains database of known malware signatures
- **Pattern Matching**: Detects suspicious code patterns and injection attempts
- **Heuristic Analysis**: Identifies unknown threats through behavioral analysis
- **Entropy Analysis**: Detects packed/encrypted malicious content
- **Structure Analysis**: Identifies polyglot files and embedded content
- **Performance Optimized**: Efficient scanning with minimal resource usage

#### Usage:
```python
from core_config.malware_scanner import scan_file_for_malware

scan_result = scan_file_for_malware(file_obj, filename)
```

### 3. Secure Error Handling System (`core_config/error_handling.py`)

The error handling system provides secure, standardized error responses:

#### Features:
- **Standardized Responses**: Consistent error format across all endpoints
- **Information Sanitization**: Removes sensitive data from error messages
- **Correlation IDs**: Unique identifiers for error tracking and debugging
- **Secure Logging**: Sanitizes logs to prevent sensitive data leakage
- **Security Event Logging**: Structured logging for security-related events
- **Custom Exception Handler**: DRF integration for automatic error handling

#### Usage:
```python
from core_config.error_handling import StandardErrorResponse, security_event_logger

# Create standardized error response
error = StandardErrorResponse(
    error_code='VALIDATION_ERROR',
    message='Custom error message',
    details={'field': 'error details'}
)

# Log security events
security_event_logger.log_authentication_attempt(
    request, user_email, success=False, failure_reason='Invalid password'
)
```

### 4. Input Validation Service (`core_config/security.py`)

The `InputValidationService` provides comprehensive input validation and sanitization:

#### Features:
- **SQL Injection Protection**: Detects and blocks SQL injection patterns
- **XSS Protection**: Prevents cross-site scripting attacks
- **Path Traversal Protection**: Blocks directory traversal attempts
- **Command Injection Protection**: Prevents command execution attacks
- **HTML Sanitization**: Safely handles HTML content using bleach
- **Data Type Validation**: Validates emails, phone numbers, financial amounts
- **Nested Data Support**: Recursively validates complex data structures

#### Usage:
```python
from core_config.security import input_validator

# Validate and sanitize data
sanitized_data = input_validator.validate_and_sanitize(
    request_data, 
    validation_schema
)
```

### 2. Validation Schemas (`core_config/validation_schemas.py`)

Centralized validation rules for all API endpoints:

#### Available Schemas:
- `USER_REGISTRATION_SCHEMA`: User registration validation
- `LOGIN_SCHEMA`: Login credential validation
- `CLIENT_CREATE_SCHEMA`: Client creation validation
- `DEAL_CREATE_SCHEMA`: Deal creation validation
- `PAYMENT_CREATE_SCHEMA`: Payment validation
- And many more...

#### Usage:
```python
from core_config.validation_schemas import ValidationSchemas

schema = ValidationSchemas.get_endpoint_schema('auth/login', 'POST')
```

### 3. Validation Middleware (`core_config/validation_middleware.py`)

Automatic input validation for all API requests:

#### Features:
- **Automatic Validation**: Validates all API requests automatically
- **CSRF Protection**: Enforces CSRF tokens for state-changing operations
- **Rate Limiting**: Implements distributed rate limiting
- **Security Headers**: Adds comprehensive security headers
- **Request Sanitization**: Sanitizes all input data before processing

#### Configuration:
The middleware is automatically applied to all requests. Configure in `settings.py`:

```python
MIDDLEWARE = [
    # ... other middleware ...
    "core_config.validation_middleware.InputValidationMiddleware",
    "core_config.validation_middleware.SecurityHeadersMiddleware",
    "core_config.validation_middleware.RateLimitMiddleware",
    # ... other middleware ...
]
```

### 4. Security Decorators (`core_config/decorators.py`)

Convenient decorators for view-level security:

#### Available Decorators:
- `@validate_input(schema_name='LOGIN_SCHEMA')`: Apply input validation
- `@require_secure_headers`: Add security headers
- `@rate_limit(limit=60, window=60)`: Apply rate limiting
- `@log_security_event('LOGIN_ATTEMPT')`: Log security events
- `@require_authentication`: Require user authentication
- `@require_permission('view_users')`: Require specific permissions
- `@sanitize_output`: Sanitize response data

#### Usage:
```python
from core_config.decorators import validate_input, rate_limit

@validate_input(schema_name='LOGIN_SCHEMA')
@rate_limit(limit=5, window=300)
@api_view(['POST'])
def login_view(request):
    # View logic here
    pass
```

## Security Features

### 1. Input Validation Patterns

#### SQL Injection Detection:
- Detects SQL keywords (SELECT, INSERT, UPDATE, DELETE, etc.)
- Identifies SQL comments (-- and /* */)
- Catches UNION attacks
- Blocks system table access attempts

#### XSS Protection:
- Removes script tags and JavaScript URLs
- Blocks event handlers (onload, onerror, etc.)
- Prevents iframe and object tag injection
- Sanitizes data URLs

#### Path Traversal Protection:
- Blocks ../ and ..\ patterns
- Prevents URL-encoded traversal attempts
- Catches various encoding bypasses

#### Command Injection Protection:
- Blocks shell metacharacters
- Prevents command chaining
- Detects common system commands

### 2. Data Sanitization

#### String Sanitization:
- Trims whitespace
- Removes null bytes and control characters
- HTML escapes dangerous characters
- Normalizes Unicode characters

#### HTML Sanitization:
- Uses bleach library for safe HTML cleaning
- Configurable allowed tags and attributes
- Strips dangerous elements while preserving content

#### Email Sanitization:
- Converts to lowercase
- Validates format using Django validators
- Checks for injection attempts

### 3. Rate Limiting

#### Endpoint-Specific Limits:
- Authentication endpoints: 5 requests per 5 minutes
- Password reset: 3 requests per 10 minutes
- File uploads: 10 requests per minute
- General API: 100 requests per minute (read), 30 per minute (write)

#### Features:
- Distributed caching support with Redis
- IP-based limiting
- Configurable limits per endpoint
- Exponential backoff support

### 4. File Upload Security

#### Multi-layer File Validation:
- **Extension Validation**: Whitelist of allowed file extensions
- **Size Limits**: Configurable size limits by file type
- **MIME Type Validation**: Verifies MIME type matches extension
- **File Signature Validation**: Checks magic numbers/file headers
- **Content Analysis**: Scans file content for malicious patterns
- **Malware Detection**: Advanced signature and heuristic scanning

#### Supported File Types:
- **Images**: JPEG, PNG, GIF, WebP, BMP, TIFF
- **Documents**: PDF, DOC, DOCX, XLS, XLSX, PPT, PPTX, TXT, RTF, CSV
- **Configurable**: Easy to add/remove supported types

#### Threat Detection:
- **Executable Files**: PE, ELF, Mach-O executables
- **Script Injection**: JavaScript, PHP, VBScript
- **SQL Injection**: Malicious SQL patterns
- **Archive Bombs**: ZIP bombs and nested archives
- **Polyglot Files**: Files valid in multiple formats
- **High Entropy Content**: Packed/encrypted malware

### 5. Error Response Security

#### Standardized Error Format:
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Input validation failed",
    "correlation_id": "abc12345",
    "details": {
      "field": ["This field is required"]
    },
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

#### Information Sanitization:
- **Database URLs**: Connection strings are redacted
- **API Keys/Tokens**: Authentication credentials are removed
- **File Paths**: System paths are sanitized
- **Email Addresses**: Personal information is protected
- **Stack Traces**: Debug information is filtered in production

#### Security Event Logging:
- **Authentication Events**: Login attempts, failures, and successes
- **Authorization Events**: Permission denials and access violations
- **Suspicious Activities**: Injection attempts and malicious patterns
- **File Upload Threats**: Malware detection and dangerous files
- **Rate Limiting**: Threshold violations and abuse attempts

### 6. Security Headers

#### Implemented Headers:
- `Content-Security-Policy`: Prevents XSS and injection attacks
- `X-Content-Type-Options`: Prevents MIME sniffing
- `X-Frame-Options`: Prevents clickjacking
- `X-XSS-Protection`: Browser XSS protection
- `Referrer-Policy`: Controls referrer information
- `Strict-Transport-Security`: Enforces HTTPS
- `Permissions-Policy`: Controls browser features

## Testing

### 1. Automated Tests

Run the comprehensive test suite:

```bash
python manage.py test test_input_validation
```

### 2. Security Testing Commands

Test security implementations:

```bash
# Test all security features
python manage.py test_security

# Test specific features
python manage.py test_security --test-type sql-injection
python manage.py test_security --test-type xss
python manage.py test_security --test-type path-traversal
python manage.py test_security --test-type validation

# Test file security features
python manage.py test_file_security

# Test specific file security features
python manage.py test_file_security --test-type validation
python manage.py test_file_security --test-type malware
python manage.py test_file_security --test-type integration

# Create sample malicious files for testing
python manage.py test_file_security --create-samples

# Test error handling and logging
python manage.py test_error_handling

# Test specific error handling features
python manage.py test_error_handling --test-type responses
python manage.py test_error_handling --test-type logging
python manage.py test_error_handling --test-type sanitization
python manage.py test_error_handling --test-type security-events
```

### 3. Manual Testing

#### Test SQL Injection:
```bash
curl -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"email": "admin'\''--", "password": "password"}'
```

#### Test XSS:
```bash
curl -X POST http://localhost:8000/api/clients/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Token YOUR_TOKEN" \
  -d '{"client_name": "<script>alert(\"xss\")</script>"}'
```

## Configuration

### 1. Environment Variables

Add to your `.env` file:

```env
# Security settings
SECURITY_VALIDATION_ENABLED=True
SECURITY_RATE_LIMITING_ENABLED=True
SECURITY_CSRF_PROTECTION_ENABLED=True
```

### 2. Django Settings

Update `settings.py`:

```python
# Security validation settings
SECURITY_VALIDATION_ENABLED = env.bool('SECURITY_VALIDATION_ENABLED', True)
SECURITY_RATE_LIMITING_ENABLED = env.bool('SECURITY_RATE_LIMITING_ENABLED', True)
SECURITY_CSRF_PROTECTION_ENABLED = env.bool('SECURITY_CSRF_PROTECTION_ENABLED', True)

# Logging configuration for security events
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'security_file': {
            'level': 'WARNING',
            'class': 'logging.FileHandler',
            'filename': BASE_DIR / 'logs' / 'security.log',
        },
    },
    'loggers': {
        'security': {
            'handlers': ['security_file'],
            'level': 'WARNING',
            'propagate': True,
        },
    },
}
```

## Monitoring and Alerting

### 1. Security Logs

Security events are logged to `logs/security.log`:

```
2024-01-15 10:30:15 WARNING SQL injection attempt detected in field 'email': admin'--
2024-01-15 10:31:22 ERROR Rate limit exceeded for IP 192.168.1.100 on path /api/auth/login/
2024-01-15 10:32:45 INFO Input validation successful for POST /api/clients/
```

### 2. Metrics to Monitor

- Failed validation attempts per minute
- Rate limit violations per hour
- Suspicious pattern detections
- Authentication failures
- Permission denied events

### 3. Alerting Rules

Set up alerts for:
- More than 10 validation failures per minute from single IP
- More than 5 SQL injection attempts per hour
- More than 3 XSS attempts per hour
- Rate limit violations exceeding threshold

## Best Practices

### 1. Development

- Always use validation schemas for new endpoints
- Apply appropriate decorators to views
- Test with malicious inputs during development
- Review security logs regularly

### 2. Deployment

- Enable all security middleware in production
- Configure proper rate limits for your traffic
- Set up monitoring and alerting
- Regularly update security dependencies

### 3. Maintenance

- Review and update validation patterns monthly
- Monitor security logs for new attack patterns
- Update validation schemas when adding new fields
- Conduct regular security testing

## Dependencies

The security implementation requires:

```
bleach==6.1.0          # HTML sanitization
python-magic==0.4.27   # File type detection
```

Add to your `requirements.txt` and install:

```bash
pip install bleach==6.1.0 python-magic==0.4.27
```

**Note**: On Windows, you may need to install `python-magic-bin` instead:
```bash
pip install python-magic-bin==0.4.14
```

## Performance Impact

The security implementation is designed for minimal performance impact:

- Input validation adds ~1-2ms per request
- Rate limiting uses efficient Redis operations
- Validation schemas are cached in memory
- Regex patterns are compiled once at startup

## Troubleshooting

### Common Issues

1. **Validation Errors**: Check validation schemas match your data structure
2. **Rate Limiting**: Adjust limits in middleware configuration
3. **CSRF Errors**: Ensure CSRF tokens are included in requests
4. **Performance**: Monitor validation overhead and optimize schemas

### Debug Mode

Enable debug logging:

```python
LOGGING['loggers']['security']['level'] = 'DEBUG'
```

This comprehensive security implementation provides robust protection against common web vulnerabilities while maintaining good performance and usability.