# 🌐 Shared Access Guide for VS Code Dev Tunnel

This guide helps colleagues access and test the Django API through the VS Code dev tunnel.

## 🚀 Quick Start

### 1. **Get the Tunnel URL**
Ask the developer for the current tunnel URL. It should look like:
```
https://abc123-8000.inc1.devtunnels.ms
```

### 2. **Test Basic Connectivity**
Open your browser and visit:
```
https://YOUR_TUNNEL_URL/api/v1/
```

You should see a JSON response or an API root page.

### 3. **Test Health Check Endpoint**
Visit the health check endpoint (no authentication required):
```
https://YOUR_TUNNEL_URL/api/v1/auth/health/
```

Expected response:
```json
{
    "status": "healthy",
    "message": "API is accessible",
    "timestamp": "2025-07-08T...",
    "debug": true,
    "cors_enabled": true
}
```

## 🧪 Testing Commands

### Using cURL (Command Line)
```bash
# Test basic connectivity
curl -X GET "https://YOUR_TUNNEL_URL/api/v1/"

# Test health check
curl -X GET "https://YOUR_TUNNEL_URL/api/v1/auth/health/"

# Test login endpoint
curl -X POST "https://YOUR_TUNNEL_URL/api/v1/auth/login/" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password"}'
```

### Using PowerShell
```powershell
# Test basic connectivity
Invoke-WebRequest -Uri "https://YOUR_TUNNEL_URL/api/v1/" -Method GET

# Test health check
Invoke-WebRequest -Uri "https://YOUR_TUNNEL_URL/api/v1/auth/health/" -Method GET

# Test login endpoint
$body = @{
    email = "test@example.com"
    password = "password"
} | ConvertTo-Json

Invoke-WebRequest -Uri "https://YOUR_TUNNEL_URL/api/v1/auth/login/" -Method POST -Body $body -ContentType "application/json"
```

### Using JavaScript/Fetch
```javascript
// Test basic connectivity
fetch('https://YOUR_TUNNEL_URL/api/v1/')
  .then(response => response.json())
  .then(data => console.log('Success:', data))
  .catch(error => console.error('Error:', error));

// Test health check
fetch('https://YOUR_TUNNEL_URL/api/v1/auth/health/')
  .then(response => response.json())
  .then(data => console.log('Health:', data))
  .catch(error => console.error('Error:', error));

// Test login
fetch('https://YOUR_TUNNEL_URL/api/v1/auth/login/', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    email: 'test@example.com',
    password: 'password'
  })
})
.then(response => response.json())
.then(data => console.log('Login:', data))
.catch(error => console.error('Error:', error));
```

## 🔧 Troubleshooting

### ❌ "Access Denied" or CORS Errors

**Symptoms:**
- Browser console shows CORS errors
- "Access to fetch at '...' from origin '...' has been blocked by CORS policy"
- Network tab shows OPTIONS request failing

**Solutions:**
1. **Check if Django server is running**
   - Ask the developer to confirm Django is running on port 8000
   - The tunnel should forward requests to localhost:8000

2. **Verify tunnel URL**
   - Make sure you're using the correct tunnel URL
   - Tunnel URLs change when VS Code is restarted

3. **Check browser console**
   - Open Developer Tools (F12)
   - Look for CORS errors in the Console tab
   - Check Network tab for failed requests

### ❌ "Connection Refused" or "Cannot Connect"

**Symptoms:**
- Network error when trying to connect
- Timeout errors
- "Connection refused" messages

**Solutions:**
1. **Verify tunnel is active**
   - Ask the developer to check if the tunnel is still running
   - VS Code should show the tunnel status

2. **Check firewall settings**
   - Your firewall might be blocking the connection
   - Try from a different network if possible

3. **Try different browsers**
   - Some browsers have stricter CORS policies
   - Try Chrome, Firefox, or Edge

### ❌ "401 Unauthorized" or "403 Forbidden"

**Symptoms:**
- API returns 401 or 403 status codes
- Authentication errors

**Solutions:**
1. **Use the health check endpoint first**
   - Test `https://YOUR_TUNNEL_URL/api/v1/auth/health/`
   - This endpoint doesn't require authentication

2. **Check credentials**
   - Make sure you have valid login credentials
   - Ask the developer for test credentials

3. **Check user permissions**
   - The user might not have proper permissions
   - Ask the developer to verify user roles

## 📱 Frontend Integration

### React/Angular/Vue Configuration
```javascript
// API Configuration
const API_BASE_URL = 'https://YOUR_TUNNEL_URL/api/v1/';

// Example API service
class ApiService {
  static async login(email, password) {
    const response = await fetch(`${API_BASE_URL}auth/login/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email, password })
    });
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    return response.json();
  }
  
  static async getProfile(token) {
    const response = await fetch(`${API_BASE_URL}auth/profile/`, {
      headers: {
        'Authorization': `Token ${token}`,
        'Content-Type': 'application/json',
      }
    });
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    return response.json();
  }
}
```

### Environment Variables
```bash
# .env file
REACT_APP_API_URL=https://YOUR_TUNNEL_URL/api/v1/
# or
VITE_API_URL=https://YOUR_TUNNEL_URL/api/v1/
```

## 🚨 Common Issues and Solutions

### Issue: GitHub Login Page Appears
**Problem:** You see a GitHub login page instead of your API
**Solution:** The tunnel is not properly forwarding to Django. Ask the developer to:
1. Check if Django server is running on port 8000
2. Verify the tunnel is configured for port 8000
3. Restart the tunnel if needed

### Issue: CORS Errors in Browser
**Problem:** Browser blocks requests due to CORS policy
**Solution:** The API should handle CORS automatically. If not:
1. Check if you're using the correct tunnel URL
2. Try using a different browser
3. Ask the developer to check CORS settings

### Issue: Authentication Fails
**Problem:** Login returns 401 or 400 errors
**Solution:**
1. Verify you have correct credentials
2. Check if the user exists in the database
3. Ask the developer for test credentials

## 📞 Getting Help

If you're still having issues:

1. **Check the tunnel URL** - Make sure it's current
2. **Test the health endpoint** - This should work without authentication
3. **Check browser console** - Look for specific error messages
4. **Contact the developer** - Provide the specific error messages you're seeing

### Information to Provide:
- The tunnel URL you're trying to access
- The specific error message you're seeing
- Your browser and operating system
- The exact steps you're taking when the error occurs

## ✅ Success Indicators

You know it's working when:
- ✅ Health check endpoint returns JSON response
- ✅ API root endpoint is accessible
- ✅ Login endpoint accepts requests (even if credentials are wrong)
- ✅ No CORS errors in browser console
- ✅ Network requests show 200, 401, or 403 status codes (not connection errors) 