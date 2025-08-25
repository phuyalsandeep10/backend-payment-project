# PRS API Error Handling Guide

## Overview

The Payment Receiving System (PRS) API provides standardized error responses with detailed information to help developers handle errors gracefully and provide meaningful feedback to users.

---

## 🚨 Error Response Format

### Standard Error Structure

All API errors follow a consistent format:

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": {
      "field_name": ["Specific validation error"]
    },
    "correlation_id": "abc-123-def-456",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

### Simple Error Format

For basic errors (like 401 Unauthorized):

```json
{
  "detail": "Authentication credentials were not provided."
}
```

---

## 📋 Error Code Reference

### Authentication Errors (401)

| Error Code | Message | Description | Resolution |
|------------|---------|-------------|------------|
| `AUTHENTICATION_ERROR` | Invalid credentials | Email/password combination is incorrect | Verify credentials and retry |
| `TOKEN_EXPIRED` | Authentication token has expired | Token is no longer valid | Re-authenticate to get new token |
| `TOKEN_INVALID` | Invalid authentication token | Token format is incorrect or corrupted | Re-authenticate to get new token |
| `ACCOUNT_DISABLED` | User account is disabled | Account has been deactivated | Contact administrator |
| `ACCOUNT_LOCKED` | Account temporarily locked | Too many failed login attempts | Wait or contact administrator |

### Permission Errors (403)

| Error Code | Message | Description | Resolution |
|------------|---------|-------------|------------|
| `PERMISSION_DENIED` | Insufficient permissions | User doesn't have required permissions | Contact administrator for access |
| `ORGANIZATION_ACCESS` | Organization access required | User not member of required organization | Join organization or request access |
| `ROLE_REQUIRED` | Higher role required | User role insufficient for action | Contact administrator for role upgrade |
| `RESOURCE_FORBIDDEN` | Access to resource forbidden | Specific resource access denied | Check ownership or permissions |

### Validation Errors (400)

| Error Code | Message | Description | Resolution |
|------------|---------|-------------|------------|
| `VALIDATION_ERROR` | Input validation failed | Request data doesn't meet requirements | Fix validation errors and retry |
| `REQUIRED_FIELD` | Field is required | Required field is missing or empty | Provide required field value |
| `INVALID_FORMAT` | Invalid field format | Field format is incorrect | Use correct format (e.g., email, date) |
| `VALUE_TOO_LONG` | Value exceeds maximum length | Field value is too long | Shorten field value |
| `INVALID_CHOICE` | Invalid choice for field | Value not in allowed choices | Use valid choice from options |
| `DUPLICATE_VALUE` | Duplicate value not allowed | Value already exists | Use unique value |

### Business Logic Errors (422)

| Error Code | Message | Description | Resolution |
|------------|---------|-------------|------------|
| `INSUFFICIENT_FUNDS` | Insufficient account balance | Payment amount exceeds available funds | Add funds or reduce amount |
| `DEAL_NOT_ACTIVE` | Deal is not active | Operation requires active deal | Activate deal first |
| `PAYMENT_ALREADY_PROCESSED` | Payment already processed | Cannot process duplicate payment | Check payment status |
| `COMMISSION_ALREADY_CALCULATED` | Commission already calculated | Cannot recalculate commission | Use existing calculation |
| `INVALID_WORKFLOW_STATE` | Invalid workflow state transition | State change not allowed | Follow proper workflow |

### Resource Errors (404)

| Error Code | Message | Description | Resolution |
|------------|---------|-------------|------------|
| `NOT_FOUND` | Resource not found | Requested resource doesn't exist | Verify resource ID and retry |
| `DEAL_NOT_FOUND` | Deal not found | Deal with specified ID doesn't exist | Check deal ID |
| `USER_NOT_FOUND` | User not found | User with specified ID doesn't exist | Check user ID |
| `CLIENT_NOT_FOUND` | Client not found | Client with specified ID doesn't exist | Check client ID |

### Rate Limiting Errors (429)

| Error Code | Message | Description | Resolution |
|------------|---------|-------------|------------|
| `RATE_LIMIT_EXCEEDED` | Too many requests | Request rate limit exceeded | Wait before retrying |
| `LOGIN_ATTEMPTS_EXCEEDED` | Too many login attempts | Login rate limit exceeded | Wait 5 minutes and retry |
| `OTP_ATTEMPTS_EXCEEDED` | Too many OTP attempts | OTP verification limit exceeded | Request new OTP |

### Server Errors (500)

| Error Code | Message | Description | Resolution |
|------------|---------|-------------|------------|
| `INTERNAL_ERROR` | An internal error occurred | Unexpected server error | Retry or contact support |
| `DATABASE_ERROR` | Database operation failed | Database connectivity issue | Retry or contact support |
| `EXTERNAL_SERVICE_ERROR` | External service unavailable | Third-party service failure | Retry later |
| `TIMEOUT_ERROR` | Request timeout | Request processing timeout | Retry with smaller payload |

---

## 💻 Error Handling Implementation

### Python Error Handling

```python
import requests
import json
import time
from typing import Optional, Dict, Any

class PRSAPIError(Exception):
    """Base exception for PRS API errors"""
    def __init__(self, error_code: str, message: str, details: Dict = None, status_code: int = None):
        self.error_code = error_code
        self.message = message
        self.details = details or {}
        self.status_code = status_code
        super().__init__(f"{error_code}: {message}")

class PRSAPIClient:
    def __init__(self, base_url: str, max_retries: int = 3):
        self.base_url = base_url
        self.session = requests.Session()
        self.max_retries = max_retries
        self.token = None
    
    def _handle_response(self, response: requests.Response) -> Dict[str, Any]:
        """Handle API response and raise appropriate exceptions"""
        try:
            data = response.json()
        except json.JSONDecodeError:
            data = {"detail": response.text}
        
        if response.status_code >= 400:
            self._raise_api_error(response.status_code, data)
        
        return data
    
    def _raise_api_error(self, status_code: int, data: Dict[str, Any]):
        """Raise appropriate exception based on error response"""
        
        # Handle standardized error format
        if 'error' in data:
            error_info = data['error']
            raise PRSAPIError(
                error_code=error_info.get('code', 'UNKNOWN_ERROR'),
                message=error_info.get('message', 'An error occurred'),
                details=error_info.get('details', {}),
                status_code=status_code
            )
        
        # Handle simple error format
        elif 'detail' in data:
            error_code = self._get_error_code_from_status(status_code)
            raise PRSAPIError(
                error_code=error_code,
                message=data['detail'],
                status_code=status_code
            )
        
        # Handle validation errors
        elif status_code == 400 and isinstance(data, dict):
            raise PRSAPIError(
                error_code='VALIDATION_ERROR',
                message='Input validation failed',
                details=data,
                status_code=status_code
            )
        
        # Generic error
        else:
            raise PRSAPIError(
                error_code='UNKNOWN_ERROR',
                message=f'HTTP {status_code} error',
                status_code=status_code
            )
    
    def _get_error_code_from_status(self, status_code: int) -> str:
        """Map HTTP status codes to error codes"""
        mapping = {
            400: 'BAD_REQUEST',
            401: 'AUTHENTICATION_ERROR',
            403: 'PERMISSION_DENIED',
            404: 'NOT_FOUND',
            429: 'RATE_LIMIT_EXCEEDED',
            500: 'INTERNAL_ERROR'
        }
        return mapping.get(status_code, 'UNKNOWN_ERROR')
    
    def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make API request with error handling and retry logic"""
        url = f"{self.base_url}{endpoint}"
        
        # Add authorization header if token exists
        headers = kwargs.get('headers', {})
        if self.token:
            headers['Authorization'] = f'Token {self.token}'
        kwargs['headers'] = headers
        
        for attempt in range(self.max_retries + 1):
            try:
                response = self.session.request(method, url, **kwargs)
                return self._handle_response(response)
            
            except PRSAPIError as e:
                # Don't retry certain error types
                if e.status_code in [400, 401, 403, 404]:
                    raise
                
                # Retry rate limit errors with backoff
                if e.error_code == 'RATE_LIMIT_EXCEEDED' and attempt < self.max_retries:
                    wait_time = 2 ** attempt  # Exponential backoff
                    print(f"Rate limited, waiting {wait_time} seconds...")
                    time.sleep(wait_time)
                    continue
                
                # Retry server errors
                if e.status_code >= 500 and attempt < self.max_retries:
                    wait_time = 2 ** attempt
                    print(f"Server error, retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                    continue
                
                raise
            
            except requests.exceptions.RequestException as e:
                if attempt < self.max_retries:
                    wait_time = 2 ** attempt
                    print(f"Network error, retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                    continue
                raise PRSAPIError('NETWORK_ERROR', str(e))
        
        raise PRSAPIError('MAX_RETRIES_EXCEEDED', 'Maximum retry attempts exceeded')
    
    def login(self, email: str, password: str) -> Dict[str, Any]:
        """Login with comprehensive error handling"""
        try:
            data = self._make_request('POST', '/auth/login/', json={
                'email': email,
                'password': password
            })
            self.token = data['token']
            return data
        
        except PRSAPIError as e:
            if e.error_code == 'AUTHENTICATION_ERROR':
                print("Login failed: Invalid email or password")
            elif e.error_code == 'RATE_LIMIT_EXCEEDED':
                print("Too many login attempts. Please wait before trying again.")
            elif e.error_code == 'ACCOUNT_DISABLED':
                print("Your account has been disabled. Please contact support.")
            else:
                print(f"Login error: {e.message}")
            raise
    
    def create_deal(self, deal_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create deal with validation error handling"""
        try:
            return self._make_request('POST', '/deals/', json=deal_data)
        
        except PRSAPIError as e:
            if e.error_code == 'VALIDATION_ERROR':
                print("Deal creation failed due to validation errors:")
                for field, errors in e.details.items():
                    print(f"  {field}: {', '.join(errors)}")
            elif e.error_code == 'PERMISSION_DENIED':
                print("You don't have permission to create deals")
            else:
                print(f"Deal creation error: {e.message}")
            raise

# Usage example
client = PRSAPIClient('http://localhost:8000/api')

try:
    # Login with error handling
    user = client.login('user@example.com', 'password123')
    print(f"Logged in as {user['user']['first_name']}")
    
    # Create deal with validation error handling
    deal = client.create_deal({
        'title': 'New Deal',
        'client': 1,
        'deal_value': '50000.00'
    })
    print(f"Created deal: {deal['id']}")

except PRSAPIError as e:
    print(f"API Error ({e.error_code}): {e.message}")
    if e.details:
        print(f"Details: {e.details}")
```

### JavaScript Error Handling

```javascript
class PRSAPIError extends Error {
    constructor(errorCode, message, details = {}, statusCode = null) {
        super(`${errorCode}: ${message}`);
        this.errorCode = errorCode;
        this.details = details;
        this.statusCode = statusCode;
        this.name = 'PRSAPIError';
    }
}

class PRSAPIClient {
    constructor(baseUrl, maxRetries = 3) {
        this.baseUrl = baseUrl;
        this.maxRetries = maxRetries;
        this.token = null;
    }
    
    async _handleResponse(response) {
        let data;
        try {
            data = await response.json();
        } catch {
            data = { detail: await response.text() };
        }
        
        if (!response.ok) {
            this._throwAPIError(response.status, data);
        }
        
        return data;
    }
    
    _throwAPIError(statusCode, data) {
        // Handle standardized error format
        if (data.error) {
            const error = data.error;
            throw new PRSAPIError(
                error.code || 'UNKNOWN_ERROR',
                error.message || 'An error occurred',
                error.details || {},
                statusCode
            );
        }
        
        // Handle simple error format
        if (data.detail) {
            const errorCode = this._getErrorCodeFromStatus(statusCode);
            throw new PRSAPIError(errorCode, data.detail, {}, statusCode);
        }
        
        // Handle validation errors
        if (statusCode === 400 && typeof data === 'object') {
            throw new PRSAPIError('VALIDATION_ERROR', 'Input validation failed', data, statusCode);
        }
        
        throw new PRSAPIError('UNKNOWN_ERROR', `HTTP ${statusCode} error`, {}, statusCode);
    }
    
    _getErrorCodeFromStatus(statusCode) {
        const mapping = {
            400: 'BAD_REQUEST',
            401: 'AUTHENTICATION_ERROR',
            403: 'PERMISSION_DENIED',
            404: 'NOT_FOUND',
            429: 'RATE_LIMIT_EXCEEDED',
            500: 'INTERNAL_ERROR'
        };
        return mapping[statusCode] || 'UNKNOWN_ERROR';
    }
    
    async _makeRequest(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        
        // Add authorization header
        const headers = { ...options.headers };
        if (this.token) {
            headers['Authorization'] = `Token ${this.token}`;
        }
        
        const requestOptions = {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...headers
            }
        };
        
        for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
            try {
                const response = await fetch(url, requestOptions);
                return await this._handleResponse(response);
            } catch (error) {
                if (error instanceof PRSAPIError) {
                    // Don't retry certain error types
                    if ([400, 401, 403, 404].includes(error.statusCode)) {
                        throw error;
                    }
                    
                    // Retry with backoff for server errors and rate limits
                    if ((error.statusCode >= 500 || error.errorCode === 'RATE_LIMIT_EXCEEDED') && 
                        attempt < this.maxRetries) {
                        const waitTime = Math.pow(2, attempt) * 1000;
                        console.log(`${error.errorCode}, retrying in ${waitTime/1000} seconds...`);
                        await new Promise(resolve => setTimeout(resolve, waitTime));
                        continue;
                    }
                }
                
                if (attempt < this.maxRetries) {
                    const waitTime = Math.pow(2, attempt) * 1000;
                    console.log(`Network error, retrying in ${waitTime/1000} seconds...`);
                    await new Promise(resolve => setTimeout(resolve, waitTime));
                    continue;
                }
                
                throw error;
            }
        }
    }
    
    async login(email, password) {
        try {
            const data = await this._makeRequest('/auth/login/', {
                method: 'POST',
                body: JSON.stringify({ email, password })
            });
            
            this.token = data.token;
            return data;
        } catch (error) {
            if (error instanceof PRSAPIError) {
                switch (error.errorCode) {
                    case 'AUTHENTICATION_ERROR':
                        console.error('Login failed: Invalid email or password');
                        break;
                    case 'RATE_LIMIT_EXCEEDED':
                        console.error('Too many login attempts. Please wait before trying again.');
                        break;
                    case 'ACCOUNT_DISABLED':
                        console.error('Your account has been disabled. Please contact support.');
                        break;
                    default:
                        console.error(`Login error: ${error.message}`);
                }
            }
            throw error;
        }
    }
    
    async createDeal(dealData) {
        try {
            return await this._makeRequest('/deals/', {
                method: 'POST',
                body: JSON.stringify(dealData)
            });
        } catch (error) {
            if (error instanceof PRSAPIError) {
                switch (error.errorCode) {
                    case 'VALIDATION_ERROR':
                        console.error('Deal creation failed due to validation errors:');
                        Object.entries(error.details).forEach(([field, errors]) => {
                            console.error(`  ${field}: ${errors.join(', ')}`);
                        });
                        break;
                    case 'PERMISSION_DENIED':
                        console.error("You don't have permission to create deals");
                        break;
                    default:
                        console.error(`Deal creation error: ${error.message}`);
                }
            }
            throw error;
        }
    }
}

// Usage example
const client = new PRSAPIClient('http://localhost:8000/api');

async function example() {
    try {
        // Login with error handling
        const result = await client.login('user@example.com', 'password123');
        console.log(`Logged in as ${result.user.first_name}`);
        
        // Create deal with validation error handling
        const deal = await client.createDeal({
            title: 'New Deal',
            client: 1,
            deal_value: '50000.00'
        });
        console.log(`Created deal: ${deal.id}`);
        
    } catch (error) {
        if (error instanceof PRSAPIError) {
            console.error(`API Error (${error.errorCode}): ${error.message}`);
            if (Object.keys(error.details).length > 0) {
                console.error('Details:', error.details);
            }
        } else {
            console.error('Network error:', error.message);
        }
    }
}

example();
```

---

## 🔄 Retry Logic and Best Practices

### When to Retry

**Retry These Errors:**
- `RATE_LIMIT_EXCEEDED` (429) - Wait and retry with exponential backoff
- `INTERNAL_ERROR` (500) - Temporary server issue
- `DATABASE_ERROR` (500) - Temporary database connectivity issue
- `TIMEOUT_ERROR` (500) - Request timeout
- Network connectivity errors

**Don't Retry These Errors:**
- `AUTHENTICATION_ERROR` (401) - Invalid credentials
- `PERMISSION_DENIED` (403) - Insufficient permissions
- `VALIDATION_ERROR` (400) - Invalid input data
- `NOT_FOUND` (404) - Resource doesn't exist
- `DUPLICATE_VALUE` (400) - Business logic violation

### Exponential Backoff

```python
import time
import random

def exponential_backoff(attempt: int, base_delay: float = 1.0, max_delay: float = 60.0) -> float:
    """Calculate exponential backoff with jitter"""
    delay = min(base_delay * (2 ** attempt), max_delay)
    # Add jitter to prevent thundering herd
    jitter = random.uniform(0, delay * 0.1)
    return delay + jitter

# Usage in retry logic
for attempt in range(max_retries):
    try:
        return api_call()
    except PRSAPIError as e:
        if e.error_code == 'RATE_LIMIT_EXCEEDED' and attempt < max_retries - 1:
            delay = exponential_backoff(attempt)
            time.sleep(delay)
            continue
        raise
```

---

## 🎯 User-Friendly Error Messages

### Error Message Mapping

```python
ERROR_MESSAGES = {
    'AUTHENTICATION_ERROR': "Invalid email or password. Please check your credentials and try again.",
    'TOKEN_EXPIRED': "Your session has expired. Please log in again.",
    'PERMISSION_DENIED': "You don't have permission to perform this action. Please contact your administrator.",
    'VALIDATION_ERROR': "Please check the highlighted fields and correct any errors.",
    'RATE_LIMIT_EXCEEDED': "Too many requests. Please wait a moment and try again.",
    'NOT_FOUND': "The requested item could not be found. It may have been deleted or moved.",
    'INTERNAL_ERROR': "Something went wrong on our end. Please try again in a few minutes.",
    'NETWORK_ERROR': "Unable to connect. Please check your internet connection and try again."
}

def get_user_friendly_message(error_code: str) -> str:
    return ERROR_MESSAGES.get(error_code, "An unexpected error occurred. Please try again.")
```

### Form Validation Errors

```javascript
function displayValidationErrors(errors) {
    // Clear previous errors
    document.querySelectorAll('.error-message').forEach(el => el.remove());
    document.querySelectorAll('.error').forEach(el => el.classList.remove('error'));
    
    // Display new errors
    Object.entries(errors).forEach(([field, messages]) => {
        const fieldElement = document.querySelector(`[name="${field}"]`);
        if (fieldElement) {
            fieldElement.classList.add('error');
            
            const errorDiv = document.createElement('div');
            errorDiv.className = 'error-message';
            errorDiv.textContent = messages.join(', ');
            
            fieldElement.parentNode.appendChild(errorDiv);
        }
    });
}

// Usage with PRS API errors
try {
    await client.createDeal(dealData);
} catch (error) {
    if (error.errorCode === 'VALIDATION_ERROR') {
        displayValidationErrors(error.details);
    } else {
        showNotification(getUserFriendlyMessage(error.errorCode), 'error');
    }
}
```

---

## 🔍 Error Logging and Monitoring

### Client-Side Error Logging

```javascript
function logError(error, context = {}) {
    const errorData = {
        timestamp: new Date().toISOString(),
        error_code: error.errorCode || 'UNKNOWN',
        message: error.message,
        status_code: error.statusCode,
        details: error.details || {},
        stack: error.stack,
        url: window.location.href,
        user_agent: navigator.userAgent,
        context: context
    };
    
    // Log to console for development
    console.error('PRS API Error:', errorData);
    
    // Send to logging service in production
    if (window.environment === 'production') {
        fetch('/api/client-errors/', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(errorData)
        }).catch(() => {
            // Silently fail if logging service is down
        });
    }
}

// Usage
try {
    await client.createDeal(dealData);
} catch (error) {
    logError(error, { action: 'create_deal', deal_data: dealData });
    throw error;
}
```

### Server-Side Error Correlation

When an error occurs, use the `correlation_id` from the error response to correlate with server logs:

```python
try:
    deal = client.create_deal(deal_data)
except PRSAPIError as e:
    print(f"Error creating deal. Correlation ID: {e.details.get('correlation_id')}")
    # Include correlation ID when reporting to support
```

---

## 🧪 Testing Error Scenarios

### Unit Tests for Error Handling

```python
import unittest
from unittest.mock import patch, Mock
import responses

class TestErrorHandling(unittest.TestCase):
    
    def setUp(self):
        self.client = PRSAPIClient('http://localhost:8000/api')
    
    @responses.activate
    def test_authentication_error(self):
        responses.add(
            responses.POST,
            'http://localhost:8000/api/auth/login/',
            json={
                'error': {
                    'code': 'AUTHENTICATION_ERROR',
                    'message': 'Invalid credentials'
                }
            },
            status=401
        )
        
        with self.assertRaises(PRSAPIError) as cm:
            self.client.login('invalid@example.com', 'wrongpass')
        
        self.assertEqual(cm.exception.error_code, 'AUTHENTICATION_ERROR')
        self.assertEqual(cm.exception.status_code, 401)
    
    @responses.activate
    def test_validation_error(self):
        responses.add(
            responses.POST,
            'http://localhost:8000/api/deals/',
            json={
                'title': ['This field is required.'],
                'deal_value': ['Ensure this value is greater than 0.']
            },
            status=400
        )
        
        with self.assertRaises(PRSAPIError) as cm:
            self.client.create_deal({'client': 1})
        
        self.assertEqual(cm.exception.error_code, 'VALIDATION_ERROR')
        self.assertIn('title', cm.exception.details)
        self.assertIn('deal_value', cm.exception.details)
    
    @responses.activate
    def test_rate_limit_with_retry(self):
        # First request: rate limited
        responses.add(
            responses.POST,
            'http://localhost:8000/api/deals/',
            json={'detail': 'Rate limit exceeded'},
            status=429
        )
        
        # Second request: success
        responses.add(
            responses.POST,
            'http://localhost:8000/api/deals/',
            json={'id': 1, 'title': 'Test Deal'},
            status=201
        )
        
        # Should succeed after retry
        result = self.client.create_deal({'title': 'Test Deal', 'client': 1})
        self.assertEqual(result['id'], 1)

if __name__ == '__main__':
    unittest.main()
```

### Integration Tests

```bash
#!/bin/bash

echo "Testing error scenarios..."

API_URL="http://localhost:8000/api"

# Test invalid credentials
echo "Testing invalid credentials..."
RESPONSE=$(curl -s -X POST "$API_URL/auth/login/" \
    -H "Content-Type: application/json" \
    -d '{"email":"invalid@example.com","password":"wrongpass"}')

echo "$RESPONSE" | grep -q "AUTHENTICATION_ERROR" && echo "✅ Authentication error handled correctly"

# Test missing required fields
echo "Testing validation errors..."
RESPONSE=$(curl -s -X POST "$API_URL/deals/" \
    -H "Content-Type: application/json" \
    -d '{"title":""}')

echo "$RESPONSE" | grep -q "required\|validation" && echo "✅ Validation error handled correctly"

# Test rate limiting (requires multiple rapid requests)
echo "Testing rate limiting..."
for i in {1..6}; do
    curl -s -X POST "$API_URL/auth/login/" \
        -H "Content-Type: application/json" \
        -d '{"email":"test@example.com","password":"wrongpass"}' > /dev/null
done

RESPONSE=$(curl -s -X POST "$API_URL/auth/login/" \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"wrongpass"}')

echo "$RESPONSE" | grep -q "Rate limit\|429" && echo "✅ Rate limiting working correctly"

echo "Error scenario tests completed!"
```

---

## 📞 Getting Help

### Support Channels

1. **Developer Documentation**: http://localhost:8000/swagger/
2. **API Support**: api-support@prs.local
3. **Emergency Issues**: Contact system administrator
4. **Bug Reports**: Include correlation ID from error response

### Information to Include

When reporting errors, include:
- **Correlation ID** from error response
- **Error code** and message
- **Steps to reproduce** the error
- **Request payload** (sanitized)
- **Timestamp** when error occurred
- **Environment** (development/staging/production)

### Self-Service Resources

- **API Documentation**: Interactive Swagger UI
- **Status Page**: Check system status and known issues
- **Error Code Reference**: This document
- **Integration Examples**: Sample code repositories

---

## 📚 Related Documentation

- [Authentication Guide](AUTHENTICATION_GUIDE.md)
- [API Integration Guide](INTEGRATION_GUIDE.md)
- [API Testing Guide](../scripts/api_docs/API_TESTING_GUIDE.md)
- [Development Guide](../development/DEVELOPMENT_GUIDE.md)
