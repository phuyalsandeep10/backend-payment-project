# 📮 Postman API Testing Guide - PRS (Payment Receiving System)

## 🚀 Quick Setup

### Base URL
```
http://127.0.0.1:8000
```

### Authentication
All protected endpoints require a **Token** in the Authorization header:
```
Authorization: Token <your_token_here>
```

---

## 📁 Collection Structure

### 1. Authentication
### 2. Dashboard & Streak System  
### 3. User Management
### 4. Clients & Deals
### 5. Commission & Analytics

---

## 🔐 1. AUTHENTICATION

### 1.1 Standard Login
**POST** `/api/v1/auth/login/`

**Headers:**
```
Content-Type: application/json
```

**Body (JSON):**
```json
{
  "email": "testlogin@example.com",
  "password": "testpass123"
}
```

**Success Response (200):**
```json
{
  "token": "31fcebe1383206d70ca9dcf9418ad846dd0e4bbdfc6ee4b",
  "user_id": 195,
  "username": "testlogin",
  "email": "testlogin@example.com",
  "organization": "Test Organization",
  "role": "No Role",
  "message": "Login successful"
}
```

### 1.2 Enhanced Login (With Streak Calculation)
**POST** `/api/v1/auth/login/enhanced/`

**Headers:**
```
Content-Type: application/json
```

**Body (JSON):**
```json
{
  "email": "testlogin@example.com",
  "password": "testpass123"
}
```

**Success Response (200):**
```json
{
  "token": "31fcebe1383206d70ca9dcf9418ad846dd0e4bbdfc6ee4b",
  "user_id": 195,
  "username": "testlogin",
  "email": "testlogin@example.com",
  "first_name": "Test",
  "last_name": "Login",
  "organization": "Test Organization",
  "role": "No Role",
  "sales_target": "15000.0",
  "streak": 0,
  "last_login": "2025-07-02T16:46:58.123456Z",
  "message": "Login successful! Streak calculated and updated."
}
```

### 1.3 Logout
**POST** `/api/v1/auth/logout/`

**Headers:**
```
Authorization: Token <your_token>
Content-Type: application/json
```

---

## 📊 2. DASHBOARD & STREAK SYSTEM

### 2.1 Main Dashboard
**GET** `/api/v1/dashboard/`

**Headers:**
```
Authorization: Token <your_token>
```

**Query Parameters (Optional):**
- `period`: daily, weekly, monthly, yearly (default: monthly)
- `include_charts`: true/false (default: true)

**Example URL:**
```
/api/v1/dashboard/?period=monthly&include_charts=true
```

### 2.2 Streak Information (GET)
**GET** `/api/v1/dashboard/streak/`

**Headers:**
```
Authorization: Token <your_token>
```

**Success Response (200):**
```json
{
  "current_streak": 0,
  "streak_emoji": "💤",
  "streak_level": "New",
  "days_until_next_level": 1,
  "recent_history": [
    {
      "date": "2025-07-02",
      "deals_closed": 0,
      "total_value": "0.00",
      "streak_updated": true
    }
  ],
  "streak_statistics": {
    "longest_streak": 0,
    "total_days_tracked": 1,
    "average_deals_per_day": 0.0
  },
  "performance_insights": [
    "Keep going! Start with just one deal to begin your streak.",
    "Focus on deals worth $101+ to increase your streak."
  ]
}
```

### 2.3 Manual Streak Recalculation (POST)
**POST** `/api/v1/dashboard/streak/`

**Headers:**
```
Authorization: Token <your_token>
Content-Type: application/json
```

**Body (JSON) - Optional:**
```json
{
  "force_recalculate": true,
  "recalculate_from_date": "2025-07-01"
}
```

### 2.4 Streak Leaderboard
**GET** `/api/v1/dashboard/streak/leaderboard/`

**Headers:**
```
Authorization: Token <your_token>
```

**Query Parameters (Optional):**
- `limit`: number of results (default: 20)
- `period`: current, monthly, quarterly, yearly (default: current)

### 2.5 Daily Standings
**GET** `/api/v1/dashboard/standings/`

**Headers:**
```
Authorization: Token <your_token>
```

**Query Parameters:**
- `type`: individual, team (required)

**Examples:**
```
/api/v1/dashboard/standings/?type=individual
/api/v1/dashboard/standings/?type=team
```

### 2.6 Commission Overview
**GET** `/api/v1/dashboard/commission/`

**Headers:**
```
Authorization: Token <your_token>
```

### 2.7 Client List
**GET** `/api/v1/dashboard/clients/`

**Headers:**
```
Authorization: Token <your_token>
```

**Query Parameters (Optional):**
- `period`: week, month, quarter (default: month)

---

## 👤 3. USER MANAGEMENT

### 3.1 Get User Profile
**GET** `/api/v1/auth/profile/`

**Headers:**
```
Authorization: Token <your_token>
```

### 3.2 Update User Profile
**PUT** `/api/v1/auth/profile/update/`

**Headers:**
```
Authorization: Token <your_token>
Content-Type: application/json
```

**Body (JSON):**
```json
{
  "first_name": "Updated",
  "last_name": "Name",
  "contact_number": "+1234567890"
}
```

### 3.3 Change Password
**POST** `/api/v1/auth/password/change/`

**Headers:**
```
Authorization: Token <your_token>
Content-Type: application/json
```

**Body (JSON):**
```json
{
  "old_password": "currentpassword",
  "new_password": "newpassword123",
  "confirm_password": "newpassword123"
}
```

---

## 🏢 4. CLIENTS & DEALS

### 4.1 List Clients
**GET** `/api/v1/clients/`

**Headers:**
```
Authorization: Token <your_token>
```

### 4.2 Create Client
**POST** `/api/v1/clients/`

**Headers:**
```
Authorization: Token <your_token>
Content-Type: application/json
```

**Body (JSON):**
```json
{
  "name": "Test Client",
  "email": "client@example.com",
  "phone": "+1234567890",
  "address": "123 Test Street"
}
```

### 4.3 List Deals
**GET** `/api/v1/deals/`

**Headers:**
```
Authorization: Token <your_token>
```

### 4.4 Create Deal
**POST** `/api/v1/deals/`

**Headers:**
```
Authorization: Token <your_token>
Content-Type: application/json
```

**Body (JSON):**
```json
{
  "client_name": "Test Client",
  "deal_value": 500.00,
  "deal_status": "pending",
  "pay_status": "pending",
  "deal_date": "2025-07-02",
  "due_date": "2025-08-01"
}
```

---

## 💰 5. COMMISSION & ANALYTICS

### 5.1 List Commissions
**GET** `/api/v1/commission/`

**Headers:**
```
Authorization: Token <your_token>
```

### 5.2 Create Commission
**POST** `/api/v1/commission/`

**Headers:**
```
Authorization: Token <your_token>
Content-Type: application/json
```

**Body (JSON):**
```json
{
  "deal": 1,
  "commission_percentage": 10.0,
  "commission_amount": 50.00
}
```

---

## 🛠️ Testing Workflow

### Step 1: Set up Authentication
1. **Create a request**: POST `/api/v1/auth/login/enhanced/`
2. **Add body**: `{"email": "your@email.com", "password": "yourpassword"}`
3. **Send request** and copy the `token` from response
4. **Save token** as a Postman variable: `{{auth_token}}`

### Step 2: Set up Environment Variables
Create a Postman Environment with:
```
base_url: http://127.0.0.1:8000
auth_token: <your_token_from_login>
```

### Step 3: Use Variables in Requests
- **URL**: `{{base_url}}/api/v1/dashboard/streak/`
- **Authorization**: `Token {{auth_token}}`

---

## 🚨 Common Error Responses

### 400 Bad Request
```json
{
  "non_field_errors": ["Invalid credentials"]
}
```

### 401 Unauthorized
```json
{
  "detail": "Authentication credentials were not provided."
}
```

### 403 Forbidden
```json
{
  "detail": "You do not have permission to perform this action."
}
```

### 500 Internal Server Error
```json
{
  "error": "Internal server error message"
}
```

---

## 📋 Quick Test Checklist

- [ ] Login with valid credentials ✅
- [ ] Login with invalid credentials (should get 400) ✅
- [ ] Access protected endpoint without token (should get 401) ✅
- [ ] Access dashboard with token ✅
- [ ] Get streak information ✅
- [ ] View leaderboard ✅
- [ ] Create/view clients ✅
- [ ] Create/view deals ✅

---

## 🔗 API Documentation

For complete API documentation with interactive testing:
- **Swagger UI**: http://127.0.0.1:8000/swagger/
- **ReDoc**: http://127.0.0.1:8000/redoc/

---

## 💡 Pro Tips for Postman

1. **Use Environment Variables** for base_url and auth_token
2. **Create a Pre-request Script** to automatically refresh tokens
3. **Use Tests Tab** to automatically extract tokens from login responses
4. **Organize requests** in folders by functionality
5. **Save example responses** for reference

### Auto-Extract Token Script (Tests Tab for Login):
```javascript
if (pm.response.code === 200) {
    const response = pm.response.json();
    pm.environment.set("auth_token", response.token);
    console.log("Token saved:", response.token);
}
```

This will automatically save the token when you login! 