# API Testing Guide

This document provides step-by-step instructions for testing key features of the PRS API using `curl`.

## 1. Setup

For the following tests, you will use the pre-configured salesperson account:
-   **Email:** `salesperson@apex.com`
-   **Password:** `salespassword`

## 2. Authentication (2-Step OTP Login)

Our API uses a secure, two-step login process. First, you initiate the login to receive an OTP, then you verify the OTP to get an authentication token.

### Step 1: Initiate Login & Get OTP

Run the following command in your terminal to request an OTP.

```bash
curl -X POST -H "Content-Type: application/json" -d '{"email": "salesperson@apex.com", "password": "salespassword"}' http://127.0.0.1:8000/api/v1/auth/login/
```

**Expected Response:**

The API will respond with a `session_id`. In the console where your Django server is running, you will see the OTP printed.

-   **API Response:**
    ```json
    {
        "message": "OTP sent to your email.",
        "session_id": "a1b2c3d4-e5f6-g7h8-i9j0-k1l2m3n4o5p6"
    }
    ```
-   **Console Output:**
    ```
    Login OTP for salesperson@apex.com: 123456
    ```

Copy the `session_id` from the API response and the `OTP` from the console for the next step.

### Step 2: Verify OTP & Get Token

Use the `session_id` and `otp` to complete the login and receive your authentication token.

```bash
curl -X POST -H "Content-Type: application/json" -d '{"session_id": "YOUR_SESSION_ID", "otp": "YOUR_OTP"}' http://127.0.0.1:8000/api/v1/auth/login/verify/
```

**Expected Response:**

You will receive an authentication `token` and the user's details.

```json
{
    "token": "YOUR_AUTH_TOKEN",
    "user": {
        "id": 1,
        "username": "salesperson",
        "email": "salesperson@apex.com",
        // ... other user details
    }
}
```

Copy the `token` value. You will need it to access protected endpoints.

## 3. Testing the Commission Dashboard

Now that you are authenticated, you can test the commission dashboard endpoint.

### Get Commission Overview

Use the `token` you received to make an authenticated request.

```bash
curl -X GET -H "Authorization: Token YOUR_AUTH_TOKEN" http://127.0.0.1:8000/api/v1/dashboard/commission-overview/
```

**Expected Response:**

The API will return a JSON object containing the salesperson's commission data, including total earnings, recent commissions, and performance metrics.

```json
{
    "total_commission_earned": "1500.00",
    "commission_this_month": "500.00",
    "top_performing_products": [
        // ... list of products
    ],
    "recent_commissions": [
        // ... list of recent commission records
    ]
}
```

This confirms that the user is properly authenticated and can access their protected data. 