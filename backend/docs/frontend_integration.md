# 🔗 Frontend Integration Guide

## Complete Guide for Frontend Developers

This guide provides everything frontend developers need to integrate with the PRS Backend API.

---

## 🎯 **QUICK START**

### **API Base Configuration**
```javascript
// Configuration
const API_CONFIG = {
    baseURL: 'http://localhost:8000/api/v1',  // Development
    // baseURL: 'https://your-domain.com/api/v1',  // Production
    timeout: 10000,
    headers: {
        'Content-Type': 'application/json',
    }
};

// API Client Setup
class PRS_API {
    constructor() {
        this.baseURL = API_CONFIG.baseURL;
        this.token = localStorage.getItem('prs_token');
    }

    // Set authentication token
    setToken(token) {
        this.token = token;
        localStorage.setItem('prs_token', token);
    }

    // Remove token
    clearToken() {
        this.token = null;
        localStorage.removeItem('prs_token');
    }

    // Make authenticated request
    async request(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;
        const config = {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...(this.token && { 'Authorization': `Token ${this.token}` }),
                ...options.headers,
            },
        };

        try {
            const response = await fetch(url, config);
            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || `HTTP ${response.status}`);
            }

            return data;
        } catch (error) {
            console.error('API Request failed:', error);
            throw error;
        }
    }
}

// Initialize API client
const api = new PRS_API();
```

---

## 🔑 **AUTHENTICATION FLOW**

### **1. Regular User Login**
```javascript
// Regular user login
async function loginUser(email, password) {
    try {
        const response = await api.request('/auth/login/', {
            method: 'POST',
            body: JSON.stringify({
                email: email,
                password: password
            })
        });

        // Store token and user info
        api.setToken(response.token);
        localStorage.setItem('user_info', JSON.stringify(response.user));
        
        return {
            success: true,
            user: response.user,
            token: response.token
        };
    } catch (error) {
        return {
            success: false,
            error: error.message
        };
    }
}

// Usage example
const loginResult = await loginUser('user@example.com', 'password123');
if (loginResult.success) {
    console.log('Login successful:', loginResult.user);
    // Redirect to dashboard
} else {
    console.error('Login failed:', loginResult.error);
    // Show error message
}
```

### **2. Super Admin Login (Two-Step Process)**
```javascript
// Step 1: Request OTP
async function requestSuperAdminOTP(email, password) {
    try {
        const response = await api.request('/auth/super-admin/login/', {
            method: 'POST',
            body: JSON.stringify({
                email: email,
                password: password
            })
        });

        return {
            success: true,
            message: response.message
        };
    } catch (error) {
        return {
            success: false,
            error: error.message
        };
    }
}

// Step 2: Verify OTP
async function verifySuperAdminOTP(email, otp) {
    try {
        const response = await api.request('/auth/super-admin/verify/', {
            method: 'POST',
            body: JSON.stringify({
                email: email,
                otp: otp
            })
        });

        // Store token and user info
        api.setToken(response.token);
        localStorage.setItem('user_info', JSON.stringify({
            id: response.user_id,
            email: response.email,
            role: response.role
        }));

        return {
            success: true,
            user: {
                id: response.user_id,
                email: response.email,
                role: response.role
            },
            token: response.token
        };
    } catch (error) {
        return {
            success: false,
            error: error.message
        };
    }
}

// Complete Super Admin Login Flow
async function superAdminLogin(email, password, otpCallback) {
    // Step 1: Request OTP
    const otpRequest = await requestSuperAdminOTP(email, password);
    
    if (!otpRequest.success) {
        return otpRequest;
    }

    // Show OTP input to user
    const otp = await otpCallback(otpRequest.message);
    
    // Step 2: Verify OTP
    return await verifySuperAdminOTP(email, otp);
}

// Usage example
const result = await superAdminLogin(
    'admin@example.com',
    'admin_password',
    async (message) => {
        // Show OTP input modal/form
        return prompt(`${message}\nEnter OTP:`);
    }
);
```

### **3. Logout**
```javascript
async function logout() {
    try {
        await api.request('/auth/logout/', {
            method: 'POST'
        });
    } catch (error) {
        console.error('Logout error:', error);
    } finally {
        // Clear local storage regardless of API response
        api.clearToken();
        localStorage.removeItem('user_info');
        // Redirect to login page
        window.location.href = '/login';
    }
}
```

---

## 📊 **API ENDPOINTS REFERENCE**

### **Authentication Endpoints**
```javascript
// Authentication API calls
const authAPI = {
    // Regular login
    login: (email, password) => api.request('/auth/login/', {
        method: 'POST',
        body: JSON.stringify({ email, password })
    }),

    // Super admin login (step 1)
    superAdminLogin: (email, password) => api.request('/auth/super-admin/login/', {
        method: 'POST',
        body: JSON.stringify({ email, password })
    }),

    // Super admin OTP verification (step 2)
    verifyOTP: (email, otp) => api.request('/auth/super-admin/verify/', {
        method: 'POST',
        body: JSON.stringify({ email, otp })
    }),

    // Logout
    logout: () => api.request('/auth/logout/', { method: 'POST' }),

    // Get user sessions
    getSessions: () => api.request('/auth/sessions/', { method: 'GET' }),

    // Delete session
    deleteSession: (sessionId) => api.request(`/auth/sessions/${sessionId}/`, {
        method: 'DELETE'
    })
};
```

### **Organization Management**
```javascript
const organizationAPI = {
    // Register new organization
    register: (orgData) => api.request('/register/', {
        method: 'POST',
        body: JSON.stringify(orgData)
    }),

    // Get organizations (super admin only)
    list: () => api.request('/organizations/', { method: 'GET' }),

    // Get organization details
    get: (id) => api.request(`/organizations/${id}/`, { method: 'GET' }),

    // Update organization
    update: (id, data) => api.request(`/organizations/${id}/`, {
        method: 'PUT',
        body: JSON.stringify(data)
    })
};

// Organization registration example
const newOrg = {
    name: "Tech Corp Ltd",
    business_type: "technology",
    address: "123 Tech Street",
    phone: "+1234567890",
    admin_email: "admin@techcorp.com",
    admin_password: "SecurePass123!"
};

const result = await organizationAPI.register(newOrg);
```

### **User Management**
```javascript
const userAPI = {
    // List users
    list: (filters = {}) => {
        const params = new URLSearchParams(filters);
        return api.request(`/auth/users/?${params}`, { method: 'GET' });
    },

    // Get user details
    get: (id) => api.request(`/auth/users/${id}/`, { method: 'GET' }),

    // Create user
    create: (userData) => api.request('/auth/users/', {
        method: 'POST',
        body: JSON.stringify(userData)
    }),

    // Update user
    update: (id, data) => api.request(`/auth/users/${id}/`, {
        method: 'PUT',
        body: JSON.stringify(data)
    }),

    // Delete user
    delete: (id) => api.request(`/auth/users/${id}/`, { method: 'DELETE' })
};
```

### **Client Management**
```javascript
const clientAPI = {
    // List clients
    list: (filters = {}) => {
        const params = new URLSearchParams(filters);
        return api.request(`/clients/?${params}`, { method: 'GET' });
    },

    // Get client details
    get: (id) => api.request(`/clients/${id}/`, { method: 'GET' }),

    // Create client
    create: (clientData) => api.request('/clients/', {
        method: 'POST',
        body: JSON.stringify(clientData)
    }),

    // Update client
    update: (id, data) => api.request(`/clients/${id}/`, {
        method: 'PUT',
        body: JSON.stringify(data)
    }),

    // Delete client
    delete: (id) => api.request(`/clients/${id}/`, { method: 'DELETE' })
};

// Client creation example
const newClient = {
    name: "John Smith",
    email: "john@example.com",
    phone: "+1234567890",
    address: "456 Client Street",
    organization: 1  // Organization ID
};
```

---

## 🔒 **ERROR HANDLING**

### **Standard Error Response Format**
```javascript
// All API errors follow this format
{
    "error": "Error message",
    "details": {
        "field_name": ["Field-specific error message"]
    }
}
```

### **Comprehensive Error Handler**
```javascript
class APIErrorHandler {
    static handle(error, context = '') {
        console.error(`API Error in ${context}:`, error);

        // Handle different error types
        if (error.message.includes('401')) {
            // Unauthorized - redirect to login
            this.handleUnauthorized();
        } else if (error.message.includes('403')) {
            // Forbidden - show permission error
            this.showError('You do not have permission to perform this action.');
        } else if (error.message.includes('429')) {
            // Rate limited
            this.showError('Too many requests. Please wait and try again.');
        } else if (error.message.includes('500')) {
            // Server error
            this.showError('Server error. Please try again later.');
        } else {
            // General error
            this.showError(error.message);
        }
    }

    static handleUnauthorized() {
        api.clearToken();
        localStorage.removeItem('user_info');
        window.location.href = '/login';
    }

    static showError(message) {
        // Implement your error display logic
        console.error('Error:', message);
        // Show toast/modal/alert with the error message
    }
}

// Usage in API calls
try {
    const data = await userAPI.list();
    // Handle success
} catch (error) {
    APIErrorHandler.handle(error, 'User List');
}
```

---

## 🔄 **REAL-TIME FEATURES**

### **Notification Polling**
```javascript
class NotificationManager {
    constructor() {
        this.pollingInterval = null;
        this.lastCheck = null;
    }

    startPolling(intervalMs = 30000) { // 30 seconds
        this.pollingInterval = setInterval(() => {
            this.fetchNotifications();
        }, intervalMs);
    }

    stopPolling() {
        if (this.pollingInterval) {
            clearInterval(this.pollingInterval);
            this.pollingInterval = null;
        }
    }

    async fetchNotifications() {
        try {
            const notifications = await api.request('/notifications/', {
                method: 'GET'
            });
            
            // Filter new notifications
            const newNotifications = this.lastCheck ? 
                notifications.filter(n => new Date(n.created_at) > this.lastCheck) :
                notifications;

            if (newNotifications.length > 0) {
                this.handleNewNotifications(newNotifications);
            }

            this.lastCheck = new Date();
        } catch (error) {
            console.error('Failed to fetch notifications:', error);
        }
    }

    handleNewNotifications(notifications) {
        notifications.forEach(notification => {
            this.showNotification(notification);
        });
    }

    showNotification(notification) {
        // Implement your notification display logic
        console.log('New notification:', notification);
    }
}

// Usage
const notificationManager = new NotificationManager();
notificationManager.startPolling();
```

---

## 📱 **REACT INTEGRATION EXAMPLE**

### **React Authentication Hook**
```javascript
// useAuth.js
import { useState, useEffect, createContext, useContext } from 'react';

const AuthContext = createContext();

export const useAuth = () => {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
};

export const AuthProvider = ({ children }) => {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        // Check for existing token on app start
        const token = localStorage.getItem('prs_token');
        const userInfo = localStorage.getItem('user_info');
        
        if (token && userInfo) {
            api.setToken(token);
            setUser(JSON.parse(userInfo));
        }
        setLoading(false);
    }, []);

    const login = async (email, password, isAdmin = false) => {
        try {
            let result;
            if (isAdmin) {
                // Super admin login flow
                result = await superAdminLogin(email, password, async (message) => {
                    // Return OTP from your OTP input component
                    return prompt(message + '\nEnter OTP:');
                });
            } else {
                // Regular user login
                result = await loginUser(email, password);
            }

            if (result.success) {
                setUser(result.user);
                return { success: true };
            } else {
                return { success: false, error: result.error };
            }
        } catch (error) {
            return { success: false, error: error.message };
        }
    };

    const logout = async () => {
        try {
            await api.request('/auth/logout/', { method: 'POST' });
        } catch (error) {
            console.error('Logout error:', error);
        } finally {
            api.clearToken();
            setUser(null);
            localStorage.removeItem('user_info');
        }
    };

    const value = {
        user,
        login,
        logout,
        loading,
        isAuthenticated: !!user
    };

    return (
        <AuthContext.Provider value={value}>
            {children}
        </AuthContext.Provider>
    );
};
```

### **React Login Component**
```javascript
// LoginForm.js
import React, { useState } from 'react';
import { useAuth } from './useAuth';

const LoginForm = () => {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [isAdmin, setIsAdmin] = useState(false);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    const { login } = useAuth();

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');

        const result = await login(email, password, isAdmin);
        
        if (!result.success) {
            setError(result.error);
        }
        
        setLoading(false);
    };

    return (
        <form onSubmit={handleSubmit}>
            <div>
                <label>Email:</label>
                <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                />
            </div>
            
            <div>
                <label>Password:</label>
                <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                />
            </div>
            
            <div>
                <label>
                    <input
                        type="checkbox"
                        checked={isAdmin}
                        onChange={(e) => setIsAdmin(e.target.checked)}
                    />
                    Super Admin Login
                </label>
            </div>
            
            {error && <div className="error">{error}</div>}
            
            <button type="submit" disabled={loading}>
                {loading ? 'Logging in...' : 'Login'}
            </button>
        </form>
    );
};
```

---

## 🧪 **TESTING YOUR INTEGRATION**

### **API Testing Checklist**
```javascript
// Test authentication
const testAuth = async () => {
    console.log('Testing authentication...');
    
    // Test regular login
    const loginResult = await loginUser('test@example.com', 'password');
    console.log('Login result:', loginResult);
    
    // Test logout
    if (loginResult.success) {
        await logout();
        console.log('Logout successful');
    }
};

// Test API endpoints
const testAPI = async () => {
    console.log('Testing API endpoints...');
    
    // Test user list
    try {
        const users = await userAPI.list();
        console.log('Users:', users);
    } catch (error) {
        console.error('User list error:', error);
    }
    
    // Test client list
    try {
        const clients = await clientAPI.list();
        console.log('Clients:', clients);
    } catch (error) {
        console.error('Client list error:', error);
    }
};

// Run tests
testAuth();
testAPI();
```

---

## 📝 **COMMON PATTERNS**

### **Form Data Handler**
```javascript
class FormHandler {
    static async submitForm(apiCall, formData, onSuccess, onError) {
        try {
            const result = await apiCall(formData);
            onSuccess(result);
        } catch (error) {
            const errorMessage = this.extractErrorMessage(error);
            onError(errorMessage);
        }
    }

    static extractErrorMessage(error) {
        if (typeof error === 'string') return error;
        if (error.details) {
            // Extract field errors
            const fieldErrors = Object.values(error.details).flat();
            return fieldErrors.join(', ');
        }
        return error.message || 'An error occurred';
    }
}
```

### **Data Caching**
```javascript
class DataCache {
    constructor() {
        this.cache = new Map();
        this.ttl = 5 * 60 * 1000; // 5 minutes
    }

    set(key, data) {
        this.cache.set(key, {
            data,
            timestamp: Date.now()
        });
    }

    get(key) {
        const item = this.cache.get(key);
        if (!item) return null;

        if (Date.now() - item.timestamp > this.ttl) {
            this.cache.delete(key);
            return null;
        }

        return item.data;
    }

    async getOrFetch(key, fetchFunction) {
        let data = this.get(key);
        if (!data) {
            data = await fetchFunction();
            this.set(key, data);
        }
        return data;
    }
}

// Usage
const cache = new DataCache();
const users = await cache.getOrFetch('users', () => userAPI.list());
```

---

## 🔍 **DEBUGGING TIPS**

### **Enable Debug Mode**
```javascript
// Add to your API client
const DEBUG = process.env.NODE_ENV === 'development';

class PRS_API {
    async request(endpoint, options = {}) {
        if (DEBUG) {
            console.log(`🔍 API Request: ${options.method || 'GET'} ${endpoint}`);
            console.log('📤 Request options:', options);
        }

        // ... existing request code ...

        if (DEBUG) {
            console.log(`📥 API Response: ${response.status}`, data);
        }

        return data;
    }
}
```

### **Network Monitoring**
```javascript
// Monitor API performance
class APIMonitor {
    static logRequest(endpoint, startTime, success, error = null) {
        const duration = Date.now() - startTime;
        
        console.log(`📊 API ${success ? '✅' : '❌'} ${endpoint} (${duration}ms)`);
        
        if (!success && error) {
            console.error('❌ Error:', error);
        }
    }
}
```

---

For more detailed API documentation, check the [Complete API Reference](./api_reference.md).

**Happy integrating! 🚀** 