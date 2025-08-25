# PRS API Authentication Guide

## Overview

The Payment Receiving System (PRS) API uses **Token-based Authentication** for secure access to all protected endpoints. This guide covers all authentication methods, security considerations, and implementation examples.

---

## 🔐 Authentication Methods

### 1. Regular User Authentication

For standard users (sales persons, team members):

#### Request
```http
POST /api/auth/login/
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securepassword123"
}
```

#### Response
```json
{
  "token": "9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b",
  "user": {
    "id": 1,
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "role": "sales_person"
  },
  "message": "Login successful"
}
```

### 2. Admin Authentication (Two-Factor)

Admin users require two-factor authentication with OTP (One-Time Password):

#### Step 1: Initiate Login
```http
POST /api/auth/login/super-admin/
Content-Type: application/json

{
  "email": "admin@example.com",
  "password": "adminsecurepass123"
}
```

#### Response
```json
{
  "message": "OTP sent to your registered email",
  "expires_in": 300
}
```

#### Step 2: Verify OTP
```http
POST /api/auth/login/super-admin/verify/
Content-Type: application/json

{
  "email": "admin@example.com",
  "otp": "123456"
}
```

#### Response
```json
{
  "token": "admin_9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b",
  "user": {
    "id": 1,
    "email": "admin@example.com",
    "first_name": "Admin",
    "last_name": "User",
    "role": "super_admin",
    "permissions": ["manage_users", "view_reports", "system_admin"]
  },
  "session": {
    "expires_at": "2024-01-16T10:30:00Z",
    "session_id": "sess_abc123def456"
  }
}
```

### 3. Organization Admin Authentication

Similar to super admin but with organization-scoped access:

#### Step 1: Initiate Login
```http
POST /api/auth/login/org-admin/
Content-Type: application/json

{
  "email": "orgadmin@example.com",
  "password": "orgadminsecurepass123"
}
```

#### Step 2: Verify OTP
```http
POST /api/auth/login/org-admin/verify/
Content-Type: application/json

{
  "email": "orgadmin@example.com",
  "otp": "123456"
}
```

---

## 🔑 Using Authentication Tokens

### Include Token in Requests

For all authenticated API requests, include the token in the `Authorization` header:

```http
Authorization: Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b
```

### Example Authenticated Request

```http
GET /api/deals/
Authorization: Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b
```

---

## 💻 Code Examples

### Python Implementation

```python
import requests

class PRSAPIClient:
    def __init__(self, base_url="http://localhost:8000/api"):
        self.base_url = base_url
        self.token = None
        self.session = requests.Session()
    
    def login(self, email, password):
        """Regular user login"""
        response = self.session.post(
            f"{self.base_url}/auth/login/",
            json={"email": email, "password": password}
        )
        response.raise_for_status()
        
        data = response.json()
        self.token = data['token']
        self.session.headers.update({
            'Authorization': f'Token {self.token}'
        })
        return data['user']
    
    def admin_login(self, email, password, otp=None):
        """Admin login with OTP"""
        if otp is None:
            # Step 1: Initiate login
            response = self.session.post(
                f"{self.base_url}/auth/login/super-admin/",
                json={"email": email, "password": password}
            )
            response.raise_for_status()
            print("OTP sent to your email. Call admin_login again with OTP.")
            return response.json()
        else:
            # Step 2: Verify OTP
            response = self.session.post(
                f"{self.base_url}/auth/login/super-admin/verify/",
                json={"email": email, "otp": otp}
            )
            response.raise_for_status()
            
            data = response.json()
            self.token = data['token']
            self.session.headers.update({
                'Authorization': f'Token {self.token}'
            })
            return data['user']
    
    def logout(self):
        """Logout and invalidate token"""
        if self.token:
            self.session.post(f"{self.base_url}/auth/logout/")
            self.token = None
            del self.session.headers['Authorization']
    
    def get_profile(self):
        """Get user profile"""
        response = self.session.get(f"{self.base_url}/auth/profile/")
        response.raise_for_status()
        return response.json()

# Usage example
client = PRSAPIClient()

# Regular user login
user = client.login("user@example.com", "password123")
print(f"Logged in as: {user['first_name']} {user['last_name']}")

# Get user profile
profile = client.get_profile()
print(f"User role: {profile['role']}")

# Logout
client.logout()
```

### JavaScript Implementation

```javascript
class PRSAPIClient {
    constructor(baseUrl = 'http://localhost:8000/api') {
        this.baseUrl = baseUrl;
        this.token = null;
    }
    
    async login(email, password) {
        const response = await fetch(`${this.baseUrl}/auth/login/`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({email, password})
        });
        
        if (!response.ok) {
            throw new Error(`Login failed: ${response.statusText}`);
        }
        
        const data = await response.json();
        this.token = data.token;
        return data.user;
    }
    
    async adminLogin(email, password, otp = null) {
        if (!otp) {
            // Step 1: Initiate login
            const response = await fetch(`${this.baseUrl}/auth/login/super-admin/`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({email, password})
            });
            
            if (!response.ok) {
                throw new Error(`Admin login failed: ${response.statusText}`);
            }
            
            return await response.json();
        } else {
            // Step 2: Verify OTP
            const response = await fetch(`${this.baseUrl}/auth/login/super-admin/verify/`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({email, otp})
            });
            
            if (!response.ok) {
                throw new Error(`OTP verification failed: ${response.statusText}`);
            }
            
            const data = await response.json();
            this.token = data.token;
            return data.user;
        }
    }
    
    getHeaders() {
        const headers = {'Content-Type': 'application/json'};
        if (this.token) {
            headers['Authorization'] = `Token ${this.token}`;
        }
        return headers;
    }
    
    async apiRequest(endpoint, options = {}) {
        const response = await fetch(`${this.baseUrl}${endpoint}`, {
            ...options,
            headers: {...this.getHeaders(), ...options.headers}
        });
        
        if (!response.ok) {
            throw new Error(`API request failed: ${response.statusText}`);
        }
        
        return await response.json();
    }
    
    async getProfile() {
        return await this.apiRequest('/auth/profile/');
    }
    
    async logout() {
        if (this.token) {
            await this.apiRequest('/auth/logout/', {method: 'POST'});
            this.token = null;
        }
    }
}

// Usage example
const client = new PRSAPIClient();

try {
    // Regular user login
    const user = await client.login('user@example.com', 'password123');
    console.log(`Logged in as: ${user.first_name} ${user.last_name}`);
    
    // Get user profile
    const profile = await client.getProfile();
    console.log(`User role: ${profile.role}`);
    
    // Logout
    await client.logout();
} catch (error) {
    console.error('Authentication error:', error.message);
}
```

### cURL Examples

```bash
#!/bin/bash

# Regular user login
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login/ \
    -H "Content-Type: application/json" \
    -d '{"email":"user@example.com","password":"password123"}' | \
    python3 -c "import json,sys; print(json.load(sys.stdin)['token'])")

echo "Token: $TOKEN"

# Use token for API requests
curl -X GET http://localhost:8000/api/deals/ \
    -H "Authorization: Token $TOKEN"

# Admin login (two steps)
# Step 1: Initiate login
curl -X POST http://localhost:8000/api/auth/login/super-admin/ \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@example.com","password":"adminpass123"}'

# Step 2: Verify OTP (replace 123456 with actual OTP from email)
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login/super-admin/verify/ \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@example.com","otp":"123456"}' | \
    python3 -c "import json,sys; print(json.load(sys.stdin)['token'])")

echo "Admin Token: $ADMIN_TOKEN"

# Use admin token
curl -X GET http://localhost:8000/api/auth/users/ \
    -H "Authorization: Token $ADMIN_TOKEN"
```

---

## 🛡️ Security Considerations

### Token Security

1. **Never expose tokens** in client-side code, logs, or URLs
2. **Store tokens securely** (e.g., secure cookies, encrypted storage)
3. **Tokens don't expire** automatically - manage session lifecycle
4. **Use HTTPS** in production to protect token transmission

### Rate Limiting

Authentication endpoints are rate-limited:
- **Login attempts**: 5 attempts per 5 minutes per IP
- **OTP verification**: 3 attempts per OTP
- **General API**: 1000 requests/hour for authenticated users

### OTP Security

- OTPs expire in **5 minutes**
- Each OTP can only be used **once**
- Failed OTP attempts are logged for security monitoring
- After 3 failed attempts, the OTP is invalidated

### Password Requirements

- Minimum 8 characters
- Must contain at least one uppercase letter
- Must contain at least one lowercase letter  
- Must contain at least one number
- Cannot be a common password

---

## 🚨 Error Handling

### Authentication Errors

#### Invalid Credentials
```json
{
  "error": {
    "code": "AUTHENTICATION_ERROR",
    "message": "Invalid credentials",
    "correlation_id": "abc-123-def"
  }
}
```

#### Rate Limit Exceeded
```json
{
  "detail": "Rate limit exceeded. Try again in 5 minutes."
}
```

#### Invalid OTP
```json
{
  "error": {
    "code": "INVALID_OTP", 
    "message": "Invalid or expired OTP",
    "correlation_id": "abc-123-def"
  }
}
```

#### Token Authentication Failed
```json
{
  "detail": "Invalid token."
}
```

### Error Handling in Code

```python
import requests

def safe_api_call(client, endpoint):
    try:
        response = client.session.get(f"{client.base_url}{endpoint}")
        response.raise_for_status()
        return response.json()
    
    except requests.exceptions.HTTPError as e:
        if response.status_code == 401:
            print("Authentication required - token may be invalid")
            # Attempt to refresh token or re-login
        elif response.status_code == 403:
            print("Permission denied")
        elif response.status_code == 429:
            print("Rate limit exceeded - wait before retrying")
        else:
            print(f"HTTP error: {e}")
    
    except requests.exceptions.RequestException as e:
        print(f"Request error: {e}")
    
    return None
```

---

## 🔄 Session Management

### Logout

Always logout users properly to invalidate tokens:

```http
POST /api/auth/logout/
Authorization: Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b
```

### Session Monitoring

For admin users, session information is provided:

```json
{
  "session": {
    "expires_at": "2024-01-16T10:30:00Z",
    "session_id": "sess_abc123def456"
  }
}
```

Monitor session expiry and prompt for re-authentication as needed.

---

## 📝 Best Practices

### 1. Token Management
- Store tokens securely (not in localStorage for web apps)
- Implement automatic logout on token expiry
- Clear tokens on logout
- Use token refresh patterns when available

### 2. Error Handling
- Always handle authentication errors gracefully
- Provide user-friendly error messages
- Implement retry logic with exponential backoff
- Log authentication events for security monitoring

### 3. Security
- Use HTTPS in production
- Validate SSL certificates
- Implement proper CORS policies
- Monitor for suspicious authentication patterns

### 4. User Experience
- Show loading states during authentication
- Provide clear feedback for authentication status
- Implement "remember me" functionality securely
- Guide users through OTP process for admin login

---

## 🧪 Testing Authentication

### Unit Tests

```python
import unittest
from unittest.mock import patch, Mock
import requests

class TestPRSAuthentication(unittest.TestCase):
    
    def setUp(self):
        self.client = PRSAPIClient()
    
    @patch('requests.Session.post')
    def test_login_success(self, mock_post):
        # Mock successful login response
        mock_response = Mock()
        mock_response.json.return_value = {
            'token': 'test_token_123',
            'user': {'id': 1, 'email': 'test@example.com'}
        }
        mock_post.return_value = mock_response
        
        # Test login
        user = self.client.login('test@example.com', 'password123')
        
        # Assertions
        self.assertEqual(self.client.token, 'test_token_123')
        self.assertEqual(user['email'], 'test@example.com')
        self.assertIn('Authorization', self.client.session.headers)
    
    @patch('requests.Session.post')
    def test_login_failure(self, mock_post):
        # Mock failed login response
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError()
        mock_post.return_value = mock_response
        
        # Test login failure
        with self.assertRaises(requests.exceptions.HTTPError):
            self.client.login('wrong@example.com', 'wrongpassword')

if __name__ == '__main__':
    unittest.main()
```

### Integration Tests

```bash
#!/bin/bash

# Test authentication flow
echo "Testing authentication flow..."

# Test invalid credentials
echo "Testing invalid credentials..."
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:8000/api/auth/login/ \
    -H "Content-Type: application/json" \
    -d '{"email":"invalid@example.com","password":"wrongpass"}')

if [ "$RESPONSE" = "400" ] || [ "$RESPONSE" = "401" ]; then
    echo "✅ Invalid credentials correctly rejected"
else
    echo "❌ Invalid credentials test failed"
fi

# Test valid credentials
echo "Testing valid credentials..."
RESPONSE=$(curl -s -X POST http://localhost:8000/api/auth/login/ \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"testpass123"}')

TOKEN=$(echo $RESPONSE | python3 -c "import json,sys; print(json.load(sys.stdin).get('token', ''))")

if [ -n "$TOKEN" ]; then
    echo "✅ Login successful, token received"
    
    # Test authenticated request
    AUTH_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -X GET http://localhost:8000/api/auth/profile/ \
        -H "Authorization: Token $TOKEN")
    
    if [ "$AUTH_RESPONSE" = "200" ]; then
        echo "✅ Authenticated request successful"
    else
        echo "❌ Authenticated request failed"
    fi
else
    echo "❌ Login failed"
fi

echo "Authentication tests completed!"
```

---

## 📞 Support

For authentication-related questions or issues:

- **Email**: auth-support@prs.local
- **Documentation**: http://localhost:8000/swagger/
- **Emergency**: Contact system administrator

## 📚 Related Documentation

- [API Integration Guide](INTEGRATION_GUIDE.md)
- [Error Handling Guide](ERROR_HANDLING_GUIDE.md)
- [API Testing Guide](../scripts/api_docs/API_TESTING_GUIDE.md)
- [Security Documentation](../architecture/SECURITY.md)
