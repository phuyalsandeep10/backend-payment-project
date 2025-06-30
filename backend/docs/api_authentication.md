# 🔑 Authentication API Guide

## Complete Authentication System Documentation

This guide covers all authentication-related endpoints and workflows in the PRS system.

---

## 🎯 **AUTHENTICATION OVERVIEW**

The PRS system uses **Token-based Authentication** with two different login flows:
1. **Regular User Login**: Standard email/password authentication
2. **Super Admin Login**: Two-factor authentication with OTP via email

---

## 🔐 **AUTHENTICATION FLOWS**

### **1. Regular User Authentication**

```mermaid
sequenceDiagram
    participant F as Frontend
    participant A as API
    participant D as Database
    participant E as Email

    F->>A: POST /auth/login/ {email, password}
    A->>D: Validate credentials
    D->>A: User data
    A->>A: Generate token
    A->>F: {token, user_data}
    F->>A: Subsequent requests with Authorization header
```

### **2. Super Admin Authentication**

```mermaid
sequenceDiagram
    participant F as Frontend
    participant A as API
    participant D as Database
    participant E as Email

    F->>A: POST /auth/super-admin/login/ {email, password}
    A->>D: Validate super admin credentials
    D->>A: User verified
    A->>A: Generate OTP
    A->>E: Send OTP email
    A->>F: {message: "OTP sent"}
    F->>F: User enters OTP
    F->>A: POST /auth/super-admin/verify/ {email, otp}
    A->>A: Verify OTP
    A->>A: Generate token
    A->>F: {token, user_data}
```

---

## 📋 **AUTHENTICATION ENDPOINTS**

### **Regular User Login**

#### **POST** `/api/v1/auth/login/`

**Description**: Authenticate regular users with email and password.

**Request Body**:
```json
{
    "email": "user@example.com",
    "password": "user_password"
}
```

**Success Response (200)**:
```json
{
    "token": "9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b",
    "user": {
        "id": 5,
        "email": "user@example.com",
        "username": "john_doe",
        "first_name": "John",
        "last_name": "Doe",
        "role": {
            "id": 3,
            "name": "Team Member",
            "permissions": [
                {
                    "id": 1,
                    "codename": "view_clients",
                    "name": "Can view clients"
                }
            ]
        },
        "organization": {
            "id": 2,
            "name": "Tech Corp",
            "business_type": "technology"
        },
        "is_active": true,
        "date_joined": "2024-01-15T10:30:00Z",
        "last_login": "2024-01-15T14:25:00Z"
    }
}
```

**Error Responses**:
```json
// Invalid credentials (401)
{
    "error": "Unable to log in with provided credentials."
}

// Rate limited (429)
{
    "error": "Rate limit exceeded. Try again in 15 minutes."
}

// Validation error (400)
{
    "error": "Invalid input data",
    "details": {
        "email": ["This field is required."],
        "password": ["This field is required."]
    }
}
```

---

### **Super Admin Login (Step 1)**

#### **POST** `/api/v1/auth/super-admin/login/`

**Description**: Initiate super admin login by requesting OTP.

**Request Body**:
```json
{
    "email": "admin@example.com",
    "password": "admin_password"
}
```

**Success Response (200)**:
```json
{
    "message": "An OTP has been sent to the designated admin email. It is valid for 5 minutes."
}
```

**Error Responses**:
```json
// Invalid credentials (401)
{
    "error": "Invalid credentials or not a Super Admin."
}

// Rate limited (429)
{
    "error": "Rate limit exceeded. Try again in 30 minutes."
}

// Email sending failed (500)
{
    "error": "Failed to send OTP. Please try again."
}
```

---

### **Super Admin Login (Step 2)**

#### **POST** `/api/v1/auth/super-admin/verify/`

**Description**: Complete super admin login by verifying OTP.

**Request Body**:
```json
{
    "email": "admin@example.com",
    "otp": "AB12CD34"
}
```

**Success Response (200)**:
```json
{
    "token": "1234567890abcdef1234567890abcdef12345678",
    "user_id": 1,
    "email": "admin@example.com",
    "role": "Super Admin"
}
```

**Error Responses**:
```json
// Invalid OTP (400)
{
    "error": "Invalid OTP. 2 attempts remaining"
}

// OTP expired (400)
{
    "error": "OTP expired or not found"
}

// Too many attempts (400)
{
    "error": "Too many invalid attempts"
}

// User not found (404)
{
    "error": "User not found."
}
```

---

### **Logout**

#### **POST** `/api/v1/auth/logout/`

**Description**: Logout current user and invalidate token.

**Headers Required**:
```
Authorization: Token your_token_here
```

**Request Body**: None

**Success Response (200)**:
```json
{
    "message": "Successfully logged out."
}
```

**Error Response**:
```json
// Unauthorized (401)
{
    "error": "Authentication credentials were not provided."
}
```

---

## 🛡️ **SESSION MANAGEMENT**

### **List User Sessions**

#### **GET** `/api/v1/auth/sessions/`

**Description**: Get list of active sessions for the authenticated user.

**Headers Required**:
```
Authorization: Token your_token_here
```

**Success Response (200)**:
```json
[
    {
        "id": 15,
        "session_key": "abc123def456...",
        "ip_address": "192.168.1.100",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "created_at": "2024-01-15T10:30:00Z",
        "last_activity": "2024-01-15T14:25:00Z",
        "is_current": true
    },
    {
        "id": 12,
        "session_key": "xyz789uvw012...",
        "ip_address": "192.168.1.50",
        "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)",
        "created_at": "2024-01-14T08:15:00Z",
        "last_activity": "2024-01-14T18:45:00Z",
        "is_current": false
    }
]
```

### **Revoke Session**

#### **DELETE** `/api/v1/auth/sessions/{session_id}/`

**Description**: Revoke a specific session.

**Headers Required**:
```
Authorization: Token your_token_here
```

**Success Response (204)**:
```json
{
    "message": "Session successfully revoked."
}
```

**Error Responses**:
```json
// Session not found (404)
{
    "error": "Session not found."
}

// Cannot revoke other user's session (403)
{
    "error": "You can only revoke your own sessions."
}
```

---

## 🔒 **TOKEN USAGE**

### **Making Authenticated Requests**

All protected endpoints require the authentication token in the Authorization header:

```javascript
// JavaScript example
const response = await fetch('http://localhost:8000/api/v1/auth/users/', {
    headers: {
        'Authorization': 'Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b',
        'Content-Type': 'application/json'
    }
});
```

```python
# Python example
import requests

headers = {
    'Authorization': 'Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b',
    'Content-Type': 'application/json'
}

response = requests.get('http://localhost:8000/api/v1/auth/users/', headers=headers)
```

```bash
# cURL example
curl -H "Authorization: Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b" \
     -H "Content-Type: application/json" \
     http://localhost:8000/api/v1/auth/users/
```

### **Token Storage**

**Frontend Best Practices**:
```javascript
// Store token securely
localStorage.setItem('prs_token', token);

// Include in API calls
const api = {
    token: localStorage.getItem('prs_token'),
    
    async request(endpoint, options = {}) {
        return fetch(`${API_BASE_URL}${endpoint}`, {
            ...options,
            headers: {
                'Authorization': `Token ${this.token}`,
                'Content-Type': 'application/json',
                ...options.headers
            }
        });
    }
};

// Clear on logout
localStorage.removeItem('prs_token');
```

---

## 🚨 **SECURITY FEATURES**

### **Rate Limiting**

The authentication system includes rate limiting to prevent brute force attacks:

- **Regular Login**: 5 attempts per 15 minutes per IP
- **Super Admin Login**: 3 attempts per 30 minutes per IP
- **OTP Verification**: 3 attempts per OTP, then OTP expires

### **OTP Security**

- **OTP Length**: 8 characters (alphanumeric)
- **Validity**: 5 minutes
- **Attempts**: Maximum 3 attempts before expiration
- **Generation**: Cryptographically secure random generation
- **Storage**: Hashed before storage

### **Session Security**

- **Token Generation**: Cryptographically secure
- **Session Tracking**: IP address and user agent logged
- **Automatic Cleanup**: Old sessions automatically removed
- **Concurrent Sessions**: Multiple sessions allowed per user

### **Password Security**

- **Hashing**: Django's PBKDF2 with SHA256
- **Validation**: Minimum length and complexity requirements
- **Rate Limiting**: Login attempt restrictions

---

## 🧪 **TESTING AUTHENTICATION**

### **Test Regular Login**

```javascript
async function testRegularLogin() {
    const response = await fetch('http://localhost:8000/api/v1/auth/login/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            email: 'test@example.com',
            password: 'testpassword123'
        })
    });
    
    const data = await response.json();
    
    if (response.ok) {
        console.log('Login successful:', data);
        localStorage.setItem('prs_token', data.token);
    } else {
        console.error('Login failed:', data.error);
    }
}
```

### **Test Super Admin Login**

```javascript
async function testSuperAdminLogin() {
    // Step 1: Request OTP
    const step1Response = await fetch('http://localhost:8000/api/v1/auth/super-admin/login/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            email: 'admin@example.com',
            password: 'admin_password'
        })
    });
    
    const step1Data = await step1Response.json();
    
    if (step1Response.ok) {
        console.log('OTP sent:', step1Data.message);
        
        // Step 2: Get OTP from user and verify
        const otp = prompt('Enter OTP from email:');
        
        const step2Response = await fetch('http://localhost:8000/api/v1/auth/super-admin/verify/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email: 'admin@example.com',
                otp: otp
            })
        });
        
        const step2Data = await step2Response.json();
        
        if (step2Response.ok) {
            console.log('Super admin login successful:', step2Data);
            localStorage.setItem('prs_token', step2Data.token);
        } else {
            console.error('OTP verification failed:', step2Data.error);
        }
    } else {
        console.error('Super admin login failed:', step1Data.error);
    }
}
```

### **Test Token Validation**

```javascript
async function testTokenValidation() {
    const token = localStorage.getItem('prs_token');
    
    if (!token) {
        console.error('No token found');
        return;
    }
    
    const response = await fetch('http://localhost:8000/api/v1/auth/users/', {
        headers: {
            'Authorization': `Token ${token}`,
            'Content-Type': 'application/json'
        }
    });
    
    if (response.ok) {
        console.log('Token is valid');
    } else if (response.status === 401) {
        console.log('Token is invalid or expired');
        localStorage.removeItem('prs_token');
    } else {
        console.error('Token validation error:', response.status);
    }
}
```

---

## 🔧 **TROUBLESHOOTING**

### **Common Issues**

#### **1. "Invalid credentials" error**
- Verify email and password are correct
- Check if user account is active
- Ensure correct endpoint for user type (regular vs super admin)

#### **2. "Rate limit exceeded" error**
- Wait for the specified time period
- Check if there are multiple failed attempts from same IP
- Consider implementing exponential backoff in frontend

#### **3. "OTP expired or not found" error**
- Request new OTP (start super admin login again)
- Check email for OTP (might be in spam folder)
- Verify OTP was entered correctly

#### **4. "Authentication credentials were not provided" error**
- Include Authorization header in request
- Verify token format: `Token your_token_here`
- Check if token is still valid

#### **5. "Failed to send OTP" error**
- Check email configuration in backend
- Verify SMTP settings are correct
- Check console output for email content (development mode)

### **Debug Commands**

```bash
# Check user exists and is active
python manage.py shell
>>> from authentication.models import User
>>> user = User.objects.get(email='admin@example.com')
>>> print(f"Active: {user.is_active}, Superuser: {user.is_superuser}")

# Test email configuration
python manage.py shell
>>> from core_config.email_backend import EmailService
>>> result = EmailService.test_email_connection()
>>> print(result)

# Check authentication settings
python manage.py shell
>>> from django.conf import settings
>>> print(f"Email backend: {settings.EMAIL_BACKEND}")
>>> print(f"OTP email: {settings.SUPER_ADMIN_OTP_EMAIL}")
```

---

For complete API documentation, see [API Reference](./api_reference.md).
For frontend integration examples, see [Frontend Integration Guide](./frontend_integration.md).

**Secure authentication implemented! 🔒** 