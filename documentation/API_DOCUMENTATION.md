# API Documentation - Backend_PRS

## Overview

This document provides comprehensive API documentation for the Backend_PRS Payment Receiving System. The API follows RESTful principles and uses JSON for data exchange.

## Base URL

```
Development: http://localhost:8000/api/
Production: https://your-domain.com/api/
```

## Authentication

### Token Authentication

All API endpoints (except public endpoints) require authentication using Token Authentication:

```http
Authorization: Token <your-token-here>
```

### Authentication Flow

#### Regular Users
```http
POST /api/auth/login/
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}
```

#### Admin Users (Multi-Factor Authentication)
```http
# Step 1: Send OTP
POST /api/auth/login/super-admin/
Content-Type: application/json

{
  "email": "admin@example.com",
  "password": "admin123"
}

# Step 2: Verify OTP
POST /api/auth/login/super-admin/verify/
Content-Type: application/json

{
  "email": "admin@example.com",
  "otp": "123456"
}
```

## API Endpoints

### Authentication (`/api/auth/`)

#### User Authentication
- `POST /api/auth/login/` - Regular user login
- `POST /api/auth/login/super-admin/` - Super admin login (step 1)
- `POST /api/auth/login/super-admin/verify/` - Super admin OTP verification
- `POST /api/auth/login/org-admin/` - Organization admin login
- `POST /api/auth/login/org-admin/verify/` - Organization admin OTP verification
- `POST /api/auth/register/` - User registration
- `POST /api/auth/logout/` - User logout
- `POST /api/auth/change-password/` - Change password with temporary token

#### User Management
- `GET /api/auth/users/` - List users (filtered by organization)
- `POST /api/auth/users/` - Create new user
- `GET /api/auth/users/{id}/` - Get user details
- `PUT /api/auth/users/{id}/` - Update user
- `DELETE /api/auth/users/{id}/` - Delete user

#### Profile Management
- `GET /api/auth/profile/` - Get user profile
- `PUT /api/auth/profile/` - Update user profile
- `POST /api/auth/users/set-sales-target/` - Set sales target

#### Session Management
- `GET /api/auth/sessions/` - List active sessions
- `DELETE /api/auth/sessions/{id}/` - Revoke session

### Organizations (`/api/organizations/`)

- `GET /api/organizations/` - List organizations (Super Admin only)
- `POST /api/organizations/` - Create organization (Super Admin only)
- `GET /api/organizations/{id}/` - Get organization details
- `PUT /api/organizations/{id}/` - Update organization
- `DELETE /api/organizations/{id}/` - Delete organization
- `POST /api/organizations/register/` - Public organization registration

### Clients (`/api/clients/`)

- `GET /api/clients/` - List clients (filtered by permissions)
- `POST /api/clients/` - Create new client
- `GET /api/clients/{id}/` - Get client details
- `PUT /api/clients/{id}/` - Update client
- `DELETE /api/clients/{id}/` - Delete client

#### Nested Client Resources
- `GET /api/clients/{client_id}/deals/` - List client deals
- `POST /api/clients/{client_id}/deals/` - Create deal for client
- `GET /api/clients/{client_id}/deals/{deal_id}/payments/` - List deal payments
- `POST /api/clients/{client_id}/deals/{deal_id}/payments/` - Create payment

### Deals (`/api/deals/`)

#### Deal Management
- `GET /api/deals/deals/` - List deals (filtered by permissions)
- `POST /api/deals/deals/` - Create new deal
- `GET /api/deals/deals/{id}/` - Get deal details
- `PUT /api/deals/deals/{id}/` - Update deal
- `DELETE /api/deals/deals/{id}/` - Delete deal
- `GET /api/deals/deals/{id}/expand/` - Get expanded deal view

#### Payment Management
- `GET /api/deals/payments/` - List payments
- `POST /api/deals/payments/` - Create payment
- `GET /api/deals/payments/{id}/` - Get payment details
- `PUT /api/deals/payments/{id}/` - Update payment
- `DELETE /api/deals/payments/{id}/` - Delete payment

#### Supporting Resources
- `GET /api/deals/activity-logs/` - List activity logs
- `GET /api/deals/invoices/` - List invoices
- `GET /api/deals/approvals/` - List payment approvals

### Commission (`/api/commission/`)

- `GET /api/commission/commissions/` - List commissions
- `POST /api/commission/commissions/` - Create commission
- `GET /api/commission/commissions/{id}/` - Get commission details
- `PUT /api/commission/commissions/{id}/` - Update commission
- `DELETE /api/commission/commissions/{id}/` - Delete commission
- `PUT /api/commission/commissions/bulk/` - Bulk update commissions
- `POST /api/commission/commissions/{id}/calculate/` - Recalculate commission

### Teams (`/api/team/`)

- `GET /api/team/teams/` - List teams
- `POST /api/team/teams/` - Create team
- `GET /api/team/teams/{id}/` - Get team details
- `PUT /api/team/teams/{id}/` - Update team
- `DELETE /api/team/teams/{id}/` - Delete team

### Projects (`/api/project/`)

- `GET /api/project/projects/` - List projects
- `POST /api/project/projects/` - Create project
- `GET /api/project/projects/{id}/` - Get project details
- `PUT /api/project/projects/{id}/` - Update project
- `DELETE /api/project/projects/{id}/` - Delete project

### Notifications (`/api/notifications/`)

- `GET /api/notifications/` - List user notifications
- `GET /api/notifications/{id}/` - Get notification details
- `POST /api/notifications/mark_all_as_read/` - Mark all as read
- `POST /api/notifications/{id}/mark_as_read/` - Mark notification as read
- `GET /api/notifications/unread_count/` - Get unread count
- `GET /api/notifications/stats/` - Get notification statistics

### Sales Dashboard (`/api/dashboard/`)

- `GET /api/dashboard/` - Main dashboard data
- `GET /api/dashboard/streaks/` - Streak information
- `POST /api/dashboard/streaks/` - Recalculate streaks
- `GET /api/dashboard/standings/` - Sales standings
- `GET /api/dashboard/commission/` - Commission overview
- `GET /api/dashboard/clients/` - Client list with payment status
- `GET /api/dashboard/chart/` - Chart data
- `GET /api/dashboard/goals/` - Sales goals progress

### Verifier Dashboard (`/api/verifier/`)

- `GET /api/verifier/dashboard/` - Verifier dashboard stats
- `GET /api/verifier/invoices/` - List invoices for verification
- `GET /api/verifier/dashboard/verification-queue/` - Pending verifications
- `GET /api/verifier/verifier-form/{payment_id}/` - Payment verification form
- `POST /api/verifier/verifier-form/{payment_id}/` - Submit verification
- `GET /api/verifier/deals/` - Deals for verification
- `GET /api/verifier/payment-approvals/` - Payment approvals

## Request/Response Format

### Standard Response Format

#### Success Response
```json
{
  "success": true,
  "data": {
    "id": 1,
    "name": "Example",
    "created_at": "2023-01-01T00:00:00Z"
  },
  "message": "Operation successful"
}
```

#### Error Response
```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input data",
    "details": {
      "field": ["This field is required"]
    }
  }
}
```

### Pagination

List endpoints support pagination:

```json
{
  "success": true,
  "data": {
    "count": 100,
    "next": "http://api.example.com/users/?page=2",
    "previous": null,
    "results": [
      {
        "id": 1,
        "name": "User 1"
      }
    ]
  }
}
```

## Data Models

### User Model
```json
{
  "id": 1,
  "email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "organization": 1,
  "role": "salesperson",
  "is_active": true,
  "created_at": "2023-01-01T00:00:00Z",
  "updated_at": "2023-01-01T00:00:00Z"
}
```

### Deal Model
```json
{
  "id": "uuid-string",
  "deal_id": "DLID0001",
  "client": 1,
  "amount": "10000.00",
  "currency": "USD",
  "status": "pending",
  "payment_method": "bank_transfer",
  "created_by": 1,
  "organization": 1,
  "created_at": "2023-01-01T00:00:00Z",
  "updated_at": "2023-01-01T00:00:00Z"
}
```

### Payment Model
```json
{
  "id": 1,
  "deal": "uuid-string",
  "transaction_id": "TXN-0001",
  "amount": "5000.00",
  "payment_method": "bank_transfer",
  "status": "verified",
  "receipt_image": "https://cloudinary.com/image.jpg",
  "created_at": "2023-01-01T00:00:00Z"
}
```

### Client Model
```json
{
  "id": 1,
  "name": "ABC Company",
  "email": "contact@abc.com",
  "phone": "+1234567890",
  "address": "123 Main St",
  "organization": 1,
  "created_by": 1,
  "satisfaction_rating": 4.5,
  "created_at": "2023-01-01T00:00:00Z"
}
```

## Permissions

### Role-Based Access Control

The system uses role-based permissions:

- **Super Admin**: Full system access
- **Organization Admin**: Organization-wide access
- **Salesperson**: Sales and client management
- **Verifier**: Payment verification
- **Team Lead**: Team management

### Permission Levels

- `view_all_*` - View all records in organization
- `view_own_*` - View only own records
- `create_*` - Create new records
- `edit_*` - Edit existing records
- `delete_*` - Delete records
- `verify_*` - Verify payments/deals

## Error Codes

### Authentication Errors
- `INVALID_CREDENTIALS` - Invalid email/password
- `ACCOUNT_DISABLED` - User account is disabled
- `OTP_REQUIRED` - OTP verification required
- `INVALID_OTP` - Invalid OTP code
- `OTP_EXPIRED` - OTP has expired

### Authorization Errors
- `PERMISSION_DENIED` - User lacks required permissions
- `ORGANIZATION_MISMATCH` - User not in required organization
- `ROLE_INSUFFICIENT` - User role insufficient for action

### Validation Errors
- `VALIDATION_ERROR` - General validation error
- `REQUIRED_FIELD` - Required field missing
- `INVALID_FORMAT` - Invalid field format
- `DUPLICATE_VALUE` - Duplicate value not allowed

### Business Logic Errors
- `DEAL_NOT_FOUND` - Deal does not exist
- `PAYMENT_ALREADY_VERIFIED` - Payment already verified
- `INSUFFICIENT_BALANCE` - Insufficient account balance
- `INVALID_STATUS_TRANSITION` - Invalid status change

## Rate Limiting

### Rate Limits
- Anonymous users: 100 requests/hour
- Authenticated users: 1000 requests/hour
- Login attempts: 5 requests/minute
- OTP requests: 3 requests/minute

### Rate Limit Headers
```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1640995200
```

## File Upload

### Supported Formats
- Images: JPG, PNG, WEBP
- Documents: PDF
- Maximum size: 5MB

### Upload Process
1. Use multipart/form-data encoding
2. Include file in request body
3. Files are validated for security
4. Images are automatically compressed
5. Files are stored in Cloudinary

### Example Upload
```javascript
const formData = new FormData();
formData.append('receipt_image', file);
formData.append('amount', '1000.00');

fetch('/api/deals/payments/', {
  method: 'POST',
  headers: {
    'Authorization': 'Token your-token-here'
  },
  body: formData
});
```

## WebSocket Notifications

### Connection
```javascript
const socket = new WebSocket('ws://localhost:8000/ws/notifications/');
```

### Message Format
```json
{
  "type": "notification",
  "data": {
    "id": 1,
    "title": "New Payment",
    "message": "Payment received for deal DLID0001",
    "timestamp": "2023-01-01T00:00:00Z"
  }
}
```

## SDKs and Tools

### API Testing
- **Swagger UI**: Available at `/swagger/`
- **ReDoc**: Available at `/redoc/`
- **Postman Collection**: Available on request

### Python SDK Example
```python
import requests

class PRSClient:
    def __init__(self, base_url, token):
        self.base_url = base_url
        self.headers = {
            'Authorization': f'Token {token}',
            'Content-Type': 'application/json'
        }
    
    def get_deals(self):
        response = requests.get(
            f'{self.base_url}/deals/deals/',
            headers=self.headers
        )
        return response.json()
```

### JavaScript SDK Example
```javascript
class PRSClient {
  constructor(baseURL, token) {
    this.baseURL = baseURL;
    this.headers = {
      'Authorization': `Token ${token}`,
      'Content-Type': 'application/json'
    };
  }
  
  async getDeals() {
    const response = await fetch(`${this.baseURL}/deals/deals/`, {
      headers: this.headers
    });
    return response.json();
  }
}
```

## Best Practices

### Request Optimization
1. Use pagination for large datasets
2. Include only required fields using `fields` parameter
3. Use filtering to reduce response size
4. Implement proper caching strategies

### Error Handling
1. Always check response status codes
2. Handle rate limiting gracefully
3. Implement retry logic for transient failures
4. Log errors for debugging

### Security
1. Never expose API tokens in client-side code
2. Use HTTPS in production
3. Implement proper CORS policies
4. Validate all input data

### Performance
1. Cache frequently accessed data
2. Use compression for large responses
3. Implement request batching where possible
4. Monitor API performance metrics

## Support

For API support, please:

1. Check the Swagger documentation at `/swagger/`
2. Review this documentation
3. Check the troubleshooting guide
4. Contact the development team

## Changelog

### Version 1.4.0
- Added WebSocket notifications
- Enhanced file upload security
- Improved error handling
- Added rate limiting

### Version 1.3.0
- Added real-time notifications
- Enhanced permission system
- Improved API documentation
- Added bulk operations

### Version 1.2.0
- Added multi-factor authentication
- Enhanced security features
- Improved error responses
- Added pagination support

### Version 1.1.0
- Added multi-tenant support
- Enhanced role-based permissions
- Improved API consistency
- Added comprehensive testing

### Version 1.0.0
- Initial API release
- Core functionality implementation
- Basic authentication
- CRUD operations for all entities