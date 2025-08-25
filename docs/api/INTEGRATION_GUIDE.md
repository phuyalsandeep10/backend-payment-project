# PRS API Integration Guide

Generated on: 2025-08-17 15:19:47

## Overview

This guide provides comprehensive information for integrating with the Payment Receiving System (PRS) API.

## Base URLs

- **Development**: `http://localhost:8000/api/`
- **Production**: `https://your-domain.com/api/`

## Authentication

The PRS API uses Token-based authentication. Include your token in the Authorization header:

```http
Authorization: Token <your-token-here>
```

### Getting Your Token

#### Regular Users
```http
POST /api/auth/login/
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "your-password"
}
```

#### Admin Users (with OTP)
```http
# Step 1: Initiate login
POST /api/auth/login/super-admin/
Content-Type: application/json

{
  "email": "admin@example.com", 
  "password": "your-password"
}

# Step 2: Verify OTP
POST /api/auth/login/super-admin/verify/
Content-Type: application/json

{
  "email": "admin@example.com",
  "otp": "123456"
}
```

## API Modules


### Organization Module

Documentation coverage: 0.0% (0/2 endpoints)

**Key endpoints:**
- `POST /api/organization/` - A public endpoint for registering a new organization and its first admin user.
- `POST, GET /api/organization/` - API endpoint for OrganizationWithAdminCreateView


### Commission Module

Documentation coverage: 0.0% (0/5 endpoints)

**Key endpoints:**
- `GET /api/commission/` - Retrieve all commission records for a specific user.
- `GET /api/commission/` - Get commission data for all salespeople in the organization for org-admin.
- `GET /api/commission/` - Get all supported currencies with their details.
- `GET /api/commission/` - Get all supported nationalities/countries for nationality selection.
- `GET /api/commission/` - Get all supported country codes with their calling codes.


### Deals Module

Documentation coverage: 0.0% (0/5 endpoints)

**Key endpoints:**
- `POST /api/deals/` - Handle chunked file uploads for large receipts and invoices.
Optimizes server performance by process
- `POST /api/deals/` - API endpoints for atomic deal operations
- `POST /api/deals/` - API endpoints for atomic bulk operations
- `POST /api/deals/` - API endpoints for atomic commission operations
- `POST, GET /api/deals/` - API endpoints for optimistic locking operations


### Notifications Module

Documentation coverage: 0.0% (0/2 endpoints)

**Key endpoints:**
- `GET /api/notifications/` - Dashboard view for notification system overview.
- `POST /api/notifications/` - View for testing notification system (admin only).


## Error Handling

The API returns standardized error responses:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Input validation failed",
    "details": {
      "field": ["This field is required"]
    },
    "correlation_id": "abc-123-def"
  }
}
```

### Common Error Codes

- `VALIDATION_ERROR` - Input validation failed
- `AUTHENTICATION_ERROR` - Authentication required
- `PERMISSION_DENIED` - Insufficient permissions
- `NOT_FOUND` - Resource not found
- `RATE_LIMIT_EXCEEDED` - Too many requests

## Rate Limiting

API endpoints are rate limited to prevent abuse:
- **Authenticated users**: 1000 requests/hour
- **Anonymous users**: 100 requests/hour
- **Login attempts**: 5 attempts/5 minutes

## Pagination

List endpoints support pagination:

```http
GET /api/deals/?page=2&page_size=50
```

Response format:
```json
{
  "count": 150,
  "next": "http://api.example.com/deals/?page=3",
  "previous": "http://api.example.com/deals/?page=1",
  "results": [...]
}
```

## SDKs and Examples

### Python Example
```python
import requests

# Authentication
response = requests.post('http://localhost:8000/api/auth/login/', {
    'email': 'user@example.com',
    'password': 'password'
})
token = response.json()['token']

# API Request
headers = {'Authorization': f'Token {token}'}
response = requests.get('http://localhost:8000/api/deals/', headers=headers)
deals = response.json()
```

### JavaScript Example
```javascript
// Authentication
const authResponse = await fetch('http://localhost:8000/api/auth/login/', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    email: 'user@example.com',
    password: 'password'
  })
});
const { token } = await authResponse.json();

// API Request
const response = await fetch('http://localhost:8000/api/deals/', {
  headers: {'Authorization': `Token ${token}`}
});
const deals = await response.json();
```

## Testing

Use the interactive API documentation:
- **Swagger UI**: `http://localhost:8000/swagger/`
- **ReDoc**: `http://localhost:8000/redoc/`

## Support

For API support and questions:
- Email: contact@prs.local
- Documentation: Full API reference available in Swagger UI
