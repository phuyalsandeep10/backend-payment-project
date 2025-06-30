# 📊 Complete API Reference

## PRS Backend API Documentation

This document provides a complete reference for all API endpoints in the PRS system.

---

## 🌐 **BASE CONFIGURATION**

### **API Base URL**
```
Development: http://localhost:8000/api/v1/
Production: https://your-domain.com/api/v1/
```

### **Authentication**
All authenticated endpoints require a token in the Authorization header:
```
Authorization: Token your_token_here
```

### **Response Format**
All responses are in JSON format:
```json
{
    "data": { ... },
    "message": "Success message",
    "status": "success"
}
```

### **Error Format**
```json
{
    "error": "Error message",
    "details": {
        "field_name": ["Field-specific error"]
    },
    "status": "error"
}
```

---

## 🔑 **AUTHENTICATION ENDPOINTS**

### **POST** `/auth/login/`
Regular user login
```javascript
// Request
{
    "email": "user@example.com",
    "password": "password123"
}

// Response (200)
{
    "token": "abc123def456...",
    "user": {
        "id": 1,
        "email": "user@example.com",
        "username": "user123",
        "role": {
            "id": 2,
            "name": "Team Member"
        },
        "organization": {
            "id": 1,
            "name": "Tech Corp"
        }
    }
}
```

### **POST** `/auth/super-admin/login/`
Super admin login step 1 (request OTP)
```javascript
// Request
{
    "email": "admin@example.com",
    "password": "admin_password"
}

// Response (200)
{
    "message": "An OTP has been sent to the designated admin email. It is valid for 5 minutes."
}
```

### **POST** `/auth/super-admin/verify/`
Super admin login step 2 (verify OTP)
```javascript
// Request
{
    "email": "admin@example.com",
    "otp": "AB12CD34"
}

// Response (200)
{
    "token": "xyz789abc123...",
    "user_id": 1,
    "email": "admin@example.com",
    "role": "Super Admin"
}
```

### **POST** `/auth/logout/`
Logout current session
```javascript
// Request: No body required

// Response (200)
{
    "message": "Successfully logged out."
}
```

### **GET** `/auth/sessions/`
List user sessions
```javascript
// Response (200)
[
    {
        "id": 1,
        "ip_address": "192.168.1.100",
        "user_agent": "Mozilla/5.0...",
        "created_at": "2024-01-15T10:30:00Z",
        "last_activity": "2024-01-15T14:25:00Z"
    }
]
```

### **DELETE** `/auth/sessions/{id}/`
Delete specific session
```javascript
// Response (204)
{
    "message": "Session successfully revoked."
}
```

---

## 👥 **USER MANAGEMENT**

### **GET** `/auth/users/`
List users (with filtering)
```javascript
// Query parameters
?organization=1&role=2&is_active=true&search=john

// Response (200)
{
    "count": 25,
    "next": "http://localhost:8000/api/v1/auth/users/?page=2",
    "previous": null,
    "results": [
        {
            "id": 1,
            "email": "john@example.com",
            "username": "john_doe",
            "first_name": "John",
            "last_name": "Doe",
            "role": {
                "id": 2,
                "name": "Team Member"
            },
            "organization": {
                "id": 1,
                "name": "Tech Corp"
            },
            "is_active": true,
            "date_joined": "2024-01-15T10:30:00Z"
        }
    ]
}
```

### **POST** `/auth/users/`
Create new user
```javascript
// Request
{
    "email": "new@example.com",
    "username": "new_user",
    "password": "SecurePass123!",
    "first_name": "New",
    "last_name": "User",
    "role": 2,
    "organization": 1
}

// Response (201)
{
    "id": 26,
    "email": "new@example.com",
    "username": "new_user",
    "first_name": "New",
    "last_name": "User",
    "role": {
        "id": 2,
        "name": "Team Member"
    },
    "organization": {
        "id": 1,
        "name": "Tech Corp"
    },
    "is_active": true,
    "date_joined": "2024-01-15T15:45:00Z"
}
```

### **GET** `/auth/users/{id}/`
Get user details
```javascript
// Response (200)
{
    "id": 1,
    "email": "john@example.com",
    "username": "john_doe",
    "first_name": "John",
    "last_name": "Doe",
    "role": {
        "id": 2,
        "name": "Team Member",
        "permissions": [
            {
                "id": 1,
                "name": "view_clients",
                "codename": "view_clients"
            }
        ]
    },
    "organization": {
        "id": 1,
        "name": "Tech Corp",
        "business_type": "technology"
    },
    "is_active": true,
    "date_joined": "2024-01-15T10:30:00Z",
    "last_login": "2024-01-15T14:25:00Z"
}
```

### **PUT** `/auth/users/{id}/`
Update user
```javascript
// Request
{
    "first_name": "John Updated",
    "last_name": "Doe Updated",
    "role": 3
}

// Response (200)
{
    "id": 1,
    "email": "john@example.com",
    "username": "john_doe",
    "first_name": "John Updated",
    "last_name": "Doe Updated",
    "role": {
        "id": 3,
        "name": "Team Lead"
    }
    // ... other fields
}
```

### **DELETE** `/auth/users/{id}/`
Delete user
```javascript
// Response (204)
// No content
```

---

## 🏢 **ORGANIZATION MANAGEMENT**

### **POST** `/register/`
Register new organization
```javascript
// Request
{
    "name": "New Tech Corp",
    "business_type": "technology",
    "address": "123 Tech Street, City",
    "phone": "+1234567890",
    "admin_email": "admin@newtechcorp.com",
    "admin_password": "SecureAdminPass123!"
}

// Response (201)
{
    "organization": {
        "id": 5,
        "name": "New Tech Corp",
        "business_type": "technology",
        "address": "123 Tech Street, City",
        "phone": "+1234567890",
        "created_at": "2024-01-15T16:00:00Z"
    },
    "admin_user": {
        "id": 30,
        "email": "admin@newtechcorp.com",
        "username": "admin@newtechcorp.com",
        "role": {
            "id": 8,
            "name": "Organization Admin"
        }
    },
    "message": "Organization and admin user created successfully."
}
```

### **GET** `/organizations/`
List organizations (super admin only)
```javascript
// Response (200)
[
    {
        "id": 1,
        "name": "Tech Corp",
        "business_type": "technology",
        "address": "456 Business Ave",
        "phone": "+1987654321",
        "created_at": "2024-01-01T00:00:00Z",
        "user_count": 15,
        "admin_email": "admin@techcorp.com"
    }
]
```

### **GET** `/organizations/{id}/`
Get organization details
```javascript
// Response (200)
{
    "id": 1,
    "name": "Tech Corp",
    "business_type": "technology",
    "address": "456 Business Ave",
    "phone": "+1987654321",
    "created_at": "2024-01-01T00:00:00Z",
    "users": [
        {
            "id": 1,
            "email": "john@techcorp.com",
            "username": "john_doe",
            "role": "Team Member"
        }
    ],
    "clients_count": 25,
    "deals_count": 12,
    "total_commission": "15000.00"
}
```

---

## 👤 **CLIENT MANAGEMENT**

### **GET** `/clients/`
List clients
```javascript
// Query parameters
?organization=1&search=john&is_active=true

// Response (200)
{
    "count": 15,
    "next": null,
    "previous": null,
    "results": [
        {
            "id": 1,
            "name": "John Client",
            "email": "john.client@example.com",
            "phone": "+1234567890",
            "address": "789 Client Street",
            "organization": {
                "id": 1,
                "name": "Tech Corp"
            },
            "created_at": "2024-01-10T09:00:00Z",
            "is_active": true,
            "deals_count": 3,
            "total_deals_value": "25000.00"
        }
    ]
}
```

### **POST** `/clients/`
Create new client
```javascript
// Request
{
    "name": "New Client",
    "email": "new.client@example.com",
    "phone": "+1122334455",
    "address": "123 New Client Ave",
    "organization": 1
}

// Response (201)
{
    "id": 16,
    "name": "New Client",
    "email": "new.client@example.com",
    "phone": "+1122334455",
    "address": "123 New Client Ave",
    "organization": {
        "id": 1,
        "name": "Tech Corp"
    },
    "created_at": "2024-01-15T17:00:00Z",
    "is_active": true,
    "deals_count": 0,
    "total_deals_value": "0.00"
}
```

### **GET** `/clients/{id}/`
Get client details
```javascript
// Response (200)
{
    "id": 1,
    "name": "John Client",
    "email": "john.client@example.com",
    "phone": "+1234567890",
    "address": "789 Client Street",
    "organization": {
        "id": 1,
        "name": "Tech Corp"
    },
    "created_at": "2024-01-10T09:00:00Z",
    "is_active": true,
    "deals": [
        {
            "id": 1,
            "title": "Website Development",
            "amount": "10000.00",
            "status": "completed",
            "created_at": "2024-01-12T10:00:00Z"
        }
    ],
    "total_deals_value": "25000.00"
}
```

---

## 💰 **COMMISSION MANAGEMENT**

### **GET** `/commissions/`
List commissions
```javascript
// Query parameters
?user=1&organization=1&date_from=2024-01-01&date_to=2024-01-31

// Response (200)
{
    "count": 8,
    "next": null,
    "previous": null,
    "results": [
        {
            "id": 1,
            "user": {
                "id": 1,
                "email": "john@techcorp.com",
                "username": "john_doe"
            },
            "organization": {
                "id": 1,
                "name": "Tech Corp"
            },
            "amount": "500.00",
            "commission_type": "deal_commission",
            "description": "Commission for Deal #1",
            "related_deal": {
                "id": 1,
                "title": "Website Development",
                "amount": "10000.00"
            },
            "created_at": "2024-01-15T12:00:00Z",
            "is_paid": false
        }
    ]
}
```

### **POST** `/commissions/`
Create commission
```javascript
// Request
{
    "user": 1,
    "organization": 1,
    "amount": "750.00",
    "commission_type": "bonus",
    "description": "Performance bonus for Q1"
}

// Response (201)
{
    "id": 9,
    "user": {
        "id": 1,
        "email": "john@techcorp.com",
        "username": "john_doe"
    },
    "organization": {
        "id": 1,
        "name": "Tech Corp"
    },
    "amount": "750.00",
    "commission_type": "bonus",
    "description": "Performance bonus for Q1",
    "created_at": "2024-01-15T18:00:00Z",
    "is_paid": false
}
```

---

## 🔒 **PERMISSIONS & ROLES**

### **GET** `/permissions/roles/`
List roles
```javascript
// Response (200)
[
    {
        "id": 1,
        "name": "Super Admin",
        "organization": null,
        "permissions": [
            {
                "id": 1,
                "name": "view_all_users",
                "codename": "view_all_users"
            }
        ]
    },
    {
        "id": 2,
        "name": "Organization Admin",
        "organization": {
            "id": 1,
            "name": "Tech Corp"
        },
        "permissions": [
            {
                "id": 2,
                "name": "create_user",
                "codename": "create_user"
            }
        ]
    }
]
```

### **GET** `/permissions/permissions/`
List all permissions
```javascript
// Response (200)
[
    {
        "id": 1,
        "name": "view_all_users",
        "codename": "view_all_users",
        "description": "Can view all users in the system"
    },
    {
        "id": 2,
        "name": "create_user",
        "codename": "create_user",
        "description": "Can create new users"
    }
]
```

---

## 📈 **HTTP STATUS CODES**

### **Success Codes**
- `200 OK` - Request successful
- `201 Created` - Resource created successfully
- `204 No Content` - Request successful, no content returned

### **Client Error Codes**
- `400 Bad Request` - Invalid request data
- `401 Unauthorized` - Authentication required
- `403 Forbidden` - Permission denied
- `404 Not Found` - Resource not found
- `429 Too Many Requests` - Rate limit exceeded

### **Server Error Codes**
- `500 Internal Server Error` - Server error

---

## 🔄 **PAGINATION**

All list endpoints support pagination:
```javascript
// Request
GET /api/v1/auth/users/?page=2&page_size=10

// Response
{
    "count": 25,
    "next": "http://localhost:8000/api/v1/auth/users/?page=3",
    "previous": "http://localhost:8000/api/v1/auth/users/?page=1",
    "results": [...]
}
```

---

## 🔍 **FILTERING & SEARCH**

Most list endpoints support filtering and search:
```javascript
// Users
GET /api/v1/auth/users/?search=john&organization=1&is_active=true

// Clients
GET /api/v1/clients/?search=client&organization=1

// Commissions
GET /api/v1/commissions/?user=1&date_from=2024-01-01&date_to=2024-01-31
```

---

## 📝 **EXAMPLE REQUESTS**

### **JavaScript Fetch**
```javascript
// GET request
const response = await fetch('http://localhost:8000/api/v1/auth/users/', {
    headers: {
        'Authorization': 'Token your_token_here',
        'Content-Type': 'application/json'
    }
});
const data = await response.json();

// POST request
const response = await fetch('http://localhost:8000/api/v1/clients/', {
    method: 'POST',
    headers: {
        'Authorization': 'Token your_token_here',
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        name: 'New Client',
        email: 'client@example.com'
    })
});
```

### **cURL**
```bash
# GET request
curl -H "Authorization: Token your_token_here" \
     -H "Content-Type: application/json" \
     http://localhost:8000/api/v1/auth/users/

# POST request
curl -X POST \
     -H "Authorization: Token your_token_here" \
     -H "Content-Type: application/json" \
     -d '{"name":"New Client","email":"client@example.com"}' \
     http://localhost:8000/api/v1/clients/
```

---

For frontend integration examples, see the [Frontend Integration Guide](./frontend_integration.md).

**Happy coding! 🚀** 