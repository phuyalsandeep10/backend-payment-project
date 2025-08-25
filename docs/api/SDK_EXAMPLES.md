# PRS API SDK Examples and Integration Patterns

## Overview

This guide provides comprehensive SDK examples and integration patterns for the Payment Receiving System (PRS) API across different programming languages and frameworks.

---

## 📱 Mobile Integration

### React Native SDK

```javascript
// PRSMobileSDK.js
import AsyncStorage from '@react-native-async-storage/async-storage';

class PRSMobileSDK {
    constructor(baseUrl, options = {}) {
        this.baseUrl = baseUrl;
        this.timeout = options.timeout || 30000;
        this.retries = options.retries || 3;
        this.token = null;
    }
    
    async initialize() {
        // Load saved token
        try {
            this.token = await AsyncStorage.getItem('prs_auth_token');
        } catch (error) {
            console.warn('Failed to load saved token:', error);
        }
    }
    
    async request(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers
        };
        
        if (this.token) {
            headers['Authorization'] = `Token ${this.token}`;
        }
        
        try {
            const response = await fetch(url, {
                timeout: this.timeout,
                ...options,
                headers
            });
            
            if (!response.ok) {
                throw new PRSAPIError(response.status, await response.json());
            }
            
            return await response.json();
        } catch (error) {
            if (error.status === 401) {
                await this.clearToken();
            }
            throw error;
        }
    }
    
    async login(email, password) {
        try {
            const data = await this.request('/auth/login/', {
                method: 'POST',
                body: JSON.stringify({ email, password })
            });
            
            this.token = data.token;
            await AsyncStorage.setItem('prs_auth_token', this.token);
            return data.user;
        } catch (error) {
            throw new PRSAPIError('LOGIN_FAILED', 'Login failed', error);
        }
    }
    
    async logout() {
        try {
            if (this.token) {
                await this.request('/auth/logout/', { method: 'POST' });
            }
        } finally {
            await this.clearToken();
        }
    }
    
    async clearToken() {
        this.token = null;
        try {
            await AsyncStorage.removeItem('prs_auth_token');
        } catch (error) {
            console.warn('Failed to clear token:', error);
        }
    }
    
    // Deal management
    async getDeals(filters = {}) {
        const params = new URLSearchParams(filters).toString();
        return await this.request(`/deals/?${params}`);
    }
    
    async getDeal(dealId) {
        return await this.request(`/deals/${dealId}/`);
    }
    
    async createDeal(dealData) {
        return await this.request('/deals/', {
            method: 'POST',
            body: JSON.stringify(dealData)
        });
    }
    
    async updateDeal(dealId, dealData) {
        return await this.request(`/deals/${dealId}/`, {
            method: 'PATCH',
            body: JSON.stringify(dealData)
        });
    }
    
    // Commission tracking
    async getCommissions(filters = {}) {
        const params = new URLSearchParams(filters).toString();
        return await this.request(`/commission/?${params}`);
    }
    
    async getUserCommissionSummary(userId) {
        return await this.request(`/commission/user-summary/${userId}/`);
    }
}

// Usage in React Native component
import React, { useEffect, useState } from 'react';
import { View, Text, FlatList, Alert } from 'react-native';

const DealsList = () => {
    const [deals, setDeals] = useState([]);
    const [loading, setLoading] = useState(true);
    const [sdk] = useState(() => new PRSMobileSDK('https://api.prs.com/api'));
    
    useEffect(() => {
        loadDeals();
    }, []);
    
    const loadDeals = async () => {
        try {
            await sdk.initialize();
            const dealsData = await sdk.getDeals({ status: 'in_progress' });
            setDeals(dealsData.results);
        } catch (error) {
            Alert.alert('Error', 'Failed to load deals');
            console.error(error);
        } finally {
            setLoading(false);
        }
    };
    
    const renderDeal = ({ item }) => (
        <View style={styles.dealItem}>
            <Text style={styles.dealTitle}>{item.title}</Text>
            <Text style={styles.dealValue}>${item.deal_value}</Text>
            <Text style={styles.dealStatus}>{item.status}</Text>
        </View>
    );
    
    if (loading) {
        return <Text>Loading deals...</Text>;
    }
    
    return (
        <FlatList
            data={deals}
            renderItem={renderDeal}
            keyExtractor={item => item.id.toString()}
            onRefresh={loadDeals}
            refreshing={loading}
        />
    );
};
```

### iOS Swift SDK

```swift
import Foundation

class PRSSDK {
    private let baseURL: URL
    private var token: String?
    private let session: URLSession
    
    init(baseURL: String) {
        self.baseURL = URL(string: baseURL)!
        
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 60
        self.session = URLSession(configuration: config)
        
        // Load saved token
        self.token = UserDefaults.standard.string(forKey: "prs_auth_token")
    }
    
    // MARK: - Authentication
    
    func login(email: String, password: String, completion: @escaping (Result<User, PRSError>) -> Void) {
        let credentials = ["email": email, "password": password]
        
        request(endpoint: "/auth/login/", method: "POST", body: credentials) { (result: Result<LoginResponse, PRSError>) in
            switch result {
            case .success(let response):
                self.token = response.token
                UserDefaults.standard.set(response.token, forKey: "prs_auth_token")
                completion(.success(response.user))
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
    
    func logout(completion: @escaping (Result<Void, PRSError>) -> Void) {
        request(endpoint: "/auth/logout/", method: "POST", body: nil as String?) { (result: Result<MessageResponse, PRSError>) in
            self.token = nil
            UserDefaults.standard.removeObject(forKey: "prs_auth_token")
            
            switch result {
            case .success:
                completion(.success(()))
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
    
    // MARK: - Deal Management
    
    func getDeals(filters: [String: Any] = [:], completion: @escaping (Result<DealListResponse, PRSError>) -> Void) {
        var components = URLComponents(url: baseURL.appendingPathComponent("/deals/"), resolvingAgainstBaseURL: false)!
        
        if !filters.isEmpty {
            components.queryItems = filters.map { URLQueryItem(name: $0.key, value: "\($0.value)") }
        }
        
        request(url: components.url!, method: "GET", completion: completion)
    }
    
    func createDeal(_ deal: CreateDealRequest, completion: @escaping (Result<Deal, PRSError>) -> Void) {
        request(endpoint: "/deals/", method: "POST", body: deal, completion: completion)
    }
    
    func updateDeal(id: Int, data: UpdateDealRequest, completion: @escaping (Result<Deal, PRSError>) -> Void) {
        request(endpoint: "/deals/\(id)/", method: "PATCH", body: data, completion: completion)
    }
    
    // MARK: - Private Methods
    
    private func request<T: Codable, U: Codable>(
        endpoint: String? = nil,
        url: URL? = nil,
        method: String,
        body: U? = nil,
        completion: @escaping (Result<T, PRSError>) -> Void
    ) {
        let requestURL = url ?? baseURL.appendingPathComponent(endpoint!)
        var request = URLRequest(url: requestURL)
        request.httpMethod = method
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        // Add authorization header if token exists
        if let token = token {
            request.setValue("Token \(token)", forHTTPHeaderField: "Authorization")
        }
        
        // Add request body if provided
        if let body = body {
            do {
                request.httpBody = try JSONEncoder().encode(body)
            } catch {
                completion(.failure(.encodingError(error)))
                return
            }
        }
        
        session.dataTask(with: request) { data, response, error in
            DispatchQueue.main.async {
                if let error = error {
                    completion(.failure(.networkError(error)))
                    return
                }
                
                guard let httpResponse = response as? HTTPURLResponse else {
                    completion(.failure(.invalidResponse))
                    return
                }
                
                guard let data = data else {
                    completion(.failure(.noData))
                    return
                }
                
                if httpResponse.statusCode >= 400 {
                    do {
                        let errorResponse = try JSONDecoder().decode(APIErrorResponse.self, from: data)
                        completion(.failure(.apiError(errorResponse)))
                    } catch {
                        completion(.failure(.decodingError(error)))
                    }
                    return
                }
                
                do {
                    let result = try JSONDecoder().decode(T.self, from: data)
                    completion(.success(result))
                } catch {
                    completion(.failure(.decodingError(error)))
                }
            }
        }.resume()
    }
}

// Models
struct User: Codable {
    let id: Int
    let email: String
    let firstName: String
    let lastName: String
    let role: String
    
    enum CodingKeys: String, CodingKey {
        case id, email, role
        case firstName = "first_name"
        case lastName = "last_name"
    }
}

struct LoginResponse: Codable {
    let token: String
    let user: User
}

struct Deal: Codable {
    let id: Int
    let title: String
    let client: Int
    let dealValue: String
    let status: String
    let createdAt: String
    
    enum CodingKeys: String, CodingKey {
        case id, title, client, status
        case dealValue = "deal_value"
        case createdAt = "created_at"
    }
}

// Error types
enum PRSError: Error, LocalizedError {
    case networkError(Error)
    case invalidResponse
    case noData
    case encodingError(Error)
    case decodingError(Error)
    case apiError(APIErrorResponse)
    
    var errorDescription: String? {
        switch self {
        case .networkError(let error):
            return "Network error: \(error.localizedDescription)"
        case .invalidResponse:
            return "Invalid response received"
        case .noData:
            return "No data received"
        case .encodingError(let error):
            return "Encoding error: \(error.localizedDescription)"
        case .decodingError(let error):
            return "Decoding error: \(error.localizedDescription)"
        case .apiError(let response):
            return response.error.message
        }
    }
}

struct APIErrorResponse: Codable {
    let error: APIError
    
    struct APIError: Codable {
        let code: String
        let message: String
        let details: [String: [String]]?
    }
}
```

---

## 🌐 Web Framework Integration

### React Hooks SDK

```javascript
// hooks/usePRSAPI.js
import { useState, useCallback, useContext, createContext } from 'react';

const PRSContext = createContext();

export const PRSProvider = ({ children, baseUrl }) => {
    const [token, setToken] = useState(localStorage.getItem('prs_token'));
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(false);
    
    const api = useCallback(async (endpoint, options = {}) => {
        const url = `${baseUrl}${endpoint}`;
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers
        };
        
        if (token) {
            headers['Authorization'] = `Token ${token}`;
        }
        
        try {
            const response = await fetch(url, { ...options, headers });
            const data = await response.json();
            
            if (!response.ok) {
                throw new PRSAPIError(data);
            }
            
            return data;
        } catch (error) {
            if (error.status === 401) {
                setToken(null);
                setUser(null);
                localStorage.removeItem('prs_token');
            }
            throw error;
        }
    }, [baseUrl, token]);
    
    const login = useCallback(async (email, password) => {
        setLoading(true);
        try {
            const data = await api('/auth/login/', {
                method: 'POST',
                body: JSON.stringify({ email, password })
            });
            
            setToken(data.token);
            setUser(data.user);
            localStorage.setItem('prs_token', data.token);
            return data.user;
        } finally {
            setLoading(false);
        }
    }, [api]);
    
    const logout = useCallback(async () => {
        try {
            if (token) {
                await api('/auth/logout/', { method: 'POST' });
            }
        } finally {
            setToken(null);
            setUser(null);
            localStorage.removeItem('prs_token');
        }
    }, [api, token]);
    
    const value = {
        token,
        user,
        loading,
        api,
        login,
        logout
    };
    
    return <PRSContext.Provider value={value}>{children}</PRSContext.Provider>;
};

export const usePRSAPI = () => {
    const context = useContext(PRSContext);
    if (!context) {
        throw new Error('usePRSAPI must be used within PRSProvider');
    }
    return context;
};

// Custom hooks for specific resources
export const useDeals = () => {
    const { api } = usePRSAPI();
    const [deals, setDeals] = useState([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);
    
    const fetchDeals = useCallback(async (filters = {}) => {
        setLoading(true);
        setError(null);
        try {
            const params = new URLSearchParams(filters).toString();
            const data = await api(`/deals/?${params}`);
            setDeals(data.results);
            return data;
        } catch (err) {
            setError(err);
            throw err;
        } finally {
            setLoading(false);
        }
    }, [api]);
    
    const createDeal = useCallback(async (dealData) => {
        try {
            const newDeal = await api('/deals/', {
                method: 'POST',
                body: JSON.stringify(dealData)
            });
            setDeals(prev => [newDeal, ...prev]);
            return newDeal;
        } catch (err) {
            setError(err);
            throw err;
        }
    }, [api]);
    
    const updateDeal = useCallback(async (dealId, dealData) => {
        try {
            const updatedDeal = await api(`/deals/${dealId}/`, {
                method: 'PATCH',
                body: JSON.stringify(dealData)
            });
            setDeals(prev => prev.map(deal => 
                deal.id === dealId ? updatedDeal : deal
            ));
            return updatedDeal;
        } catch (err) {
            setError(err);
            throw err;
        }
    }, [api]);
    
    return {
        deals,
        loading,
        error,
        fetchDeals,
        createDeal,
        updateDeal
    };
};

// Usage in React component
import React, { useEffect } from 'react';
import { usePRSAPI, useDeals } from './hooks/usePRSAPI';

const DealsPage = () => {
    const { user } = usePRSAPI();
    const { deals, loading, error, fetchDeals, createDeal } = useDeals();
    
    useEffect(() => {
        fetchDeals({ status: 'in_progress' });
    }, [fetchDeals]);
    
    const handleCreateDeal = async (dealData) => {
        try {
            await createDeal(dealData);
            alert('Deal created successfully!');
        } catch (error) {
            alert(`Error creating deal: ${error.message}`);
        }
    };
    
    if (loading) return <div>Loading deals...</div>;
    if (error) return <div>Error: {error.message}</div>;
    
    return (
        <div>
            <h1>Deals for {user?.first_name}</h1>
            <div className="deals-list">
                {deals.map(deal => (
                    <div key={deal.id} className="deal-card">
                        <h3>{deal.title}</h3>
                        <p>Value: ${deal.deal_value}</p>
                        <p>Status: {deal.status}</p>
                    </div>
                ))}
            </div>
        </div>
    );
};
```

### Vue.js Composition API SDK

```javascript
// composables/usePRS.js
import { ref, reactive, computed } from 'vue';

const state = reactive({
    token: localStorage.getItem('prs_token'),
    user: null,
    loading: false,
    error: null
});

const baseURL = process.env.VUE_APP_PRS_API_URL || 'http://localhost:8000/api';

const api = async (endpoint, options = {}) => {
    const url = `${baseURL}${endpoint}`;
    const headers = {
        'Content-Type': 'application/json',
        ...options.headers
    };
    
    if (state.token) {
        headers['Authorization'] = `Token ${state.token}`;
    }
    
    try {
        const response = await fetch(url, { ...options, headers });
        const data = await response.json();
        
        if (!response.ok) {
            throw new PRSAPIError(data);
        }
        
        return data;
    } catch (error) {
        if (error.status === 401) {
            state.token = null;
            state.user = null;
            localStorage.removeItem('prs_token');
        }
        throw error;
    }
};

export const usePRSAuth = () => {
    const login = async (email, password) => {
        state.loading = true;
        state.error = null;
        
        try {
            const data = await api('/auth/login/', {
                method: 'POST',
                body: JSON.stringify({ email, password })
            });
            
            state.token = data.token;
            state.user = data.user;
            localStorage.setItem('prs_token', data.token);
            return data.user;
        } catch (error) {
            state.error = error;
            throw error;
        } finally {
            state.loading = false;
        }
    };
    
    const logout = async () => {
        try {
            if (state.token) {
                await api('/auth/logout/', { method: 'POST' });
            }
        } finally {
            state.token = null;
            state.user = null;
            localStorage.removeItem('prs_token');
        }
    };
    
    return {
        user: computed(() => state.user),
        token: computed(() => state.token),
        loading: computed(() => state.loading),
        error: computed(() => state.error),
        isAuthenticated: computed(() => !!state.token),
        login,
        logout
    };
};

export const usePRSDeals = () => {
    const deals = ref([]);
    const loading = ref(false);
    const error = ref(null);
    
    const fetchDeals = async (filters = {}) => {
        loading.value = true;
        error.value = null;
        
        try {
            const params = new URLSearchParams(filters).toString();
            const data = await api(`/deals/?${params}`);
            deals.value = data.results;
            return data;
        } catch (err) {
            error.value = err;
            throw err;
        } finally {
            loading.value = false;
        }
    };
    
    const createDeal = async (dealData) => {
        try {
            const newDeal = await api('/deals/', {
                method: 'POST',
                body: JSON.stringify(dealData)
            });
            deals.value.unshift(newDeal);
            return newDeal;
        } catch (err) {
            error.value = err;
            throw err;
        }
    };
    
    return {
        deals: computed(() => deals.value),
        loading: computed(() => loading.value),
        error: computed(() => error.value),
        fetchDeals,
        createDeal
    };
};

// Usage in Vue component
// Deals.vue
<template>
  <div class="deals-page">
    <h1>Deals</h1>
    
    <div v-if="loading" class="loading">
      Loading deals...
    </div>
    
    <div v-else-if="error" class="error">
      Error: {{ error.message }}
    </div>
    
    <div v-else class="deals-grid">
      <div 
        v-for="deal in deals" 
        :key="deal.id" 
        class="deal-card"
      >
        <h3>{{ deal.title }}</h3>
        <p>Value: ${{ deal.deal_value }}</p>
        <p>Status: {{ deal.status }}</p>
      </div>
    </div>
  </div>
</template>

<script setup>
import { onMounted } from 'vue';
import { usePRSDeals } from '@/composables/usePRS';

const { deals, loading, error, fetchDeals } = usePRSDeals();

onMounted(() => {
  fetchDeals({ status: 'in_progress' });
});
</script>
```

---

## 🖥️ Desktop Application Integration

### Electron Integration

```javascript
// main.js (Electron main process)
const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');

class PRSElectronApp {
    constructor() {
        this.mainWindow = null;
        this.prsConfig = {
            baseUrl: process.env.PRS_API_URL || 'http://localhost:8000/api',
            appName: 'PRS Desktop',
            version: app.getVersion()
        };
    }
    
    createWindow() {
        this.mainWindow = new BrowserWindow({
            width: 1200,
            height: 800,
            webPreferences: {
                nodeIntegration: false,
                contextIsolation: true,
                preload: path.join(__dirname, 'preload.js')
            }
        });
        
        this.mainWindow.loadFile('dist/index.html');
        
        // Handle external links
        this.mainWindow.webContents.setWindowOpenHandler(({ url }) => {
            shell.openExternal(url);
            return { action: 'deny' };
        });
    }
    
    setupIPC() {
        // PRS API bridge
        ipcMain.handle('prs-api-request', async (event, { endpoint, options }) => {
            try {
                const response = await this.makeAPIRequest(endpoint, options);
                return { success: true, data: response };
            } catch (error) {
                return { success: false, error: error.message };
            }
        });
        
        // Secure storage for tokens
        ipcMain.handle('secure-storage-get', async (event, key) => {
            // Implement secure storage (e.g., keytar)
            return await this.getSecureValue(key);
        });
        
        ipcMain.handle('secure-storage-set', async (event, key, value) => {
            await this.setSecureValue(key, value);
        });
    }
    
    async makeAPIRequest(endpoint, options = {}) {
        const fetch = require('node-fetch');
        const url = `${this.prsConfig.baseUrl}${endpoint}`;
        
        const response = await fetch(url, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                'User-Agent': `${this.prsConfig.appName}/${this.prsConfig.version}`,
                ...options.headers
            }
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error?.message || data.detail || 'API request failed');
        }
        
        return data;
    }
}

const prsApp = new PRSElectronApp();

app.whenReady().then(() => {
    prsApp.createWindow();
    prsApp.setupIPC();
});

// preload.js (Electron preload script)
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('prsAPI', {
    request: (endpoint, options) => 
        ipcRenderer.invoke('prs-api-request', { endpoint, options }),
    
    secureStorage: {
        get: (key) => ipcRenderer.invoke('secure-storage-get', key),
        set: (key, value) => ipcRenderer.invoke('secure-storage-set', key, value)
    }
});

// renderer.js (Frontend code)
class PRSDesktopClient {
    constructor() {
        this.token = null;
        this.initialize();
    }
    
    async initialize() {
        this.token = await window.prsAPI.secureStorage.get('auth_token');
    }
    
    async login(email, password) {
        try {
            const response = await window.prsAPI.request('/auth/login/', {
                method: 'POST',
                body: JSON.stringify({ email, password })
            });
            
            if (response.success) {
                this.token = response.data.token;
                await window.prsAPI.secureStorage.set('auth_token', this.token);
                return response.data.user;
            } else {
                throw new Error(response.error);
            }
        } catch (error) {
            throw new Error(`Login failed: ${error.message}`);
        }
    }
    
    async getDeals(filters = {}) {
        const params = new URLSearchParams(filters).toString();
        const response = await window.prsAPI.request(`/deals/?${params}`, {
            headers: { 'Authorization': `Token ${this.token}` }
        });
        
        if (response.success) {
            return response.data;
        } else {
            throw new Error(response.error);
        }
    }
}
```

---

## 🐍 Python SDK (Advanced)

```python
# prs_sdk/client.py
import asyncio
import aiohttp
import json
from typing import Dict, List, Optional, Any, AsyncGenerator
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

@dataclass
class PRSConfig:
    base_url: str
    timeout: int = 30
    max_retries: int = 3
    user_agent: str = "PRS-Python-SDK/1.0"

class PRSAsyncClient:
    """Asynchronous PRS API client with advanced features"""
    
    def __init__(self, config: PRSConfig):
        self.config = config
        self.token: Optional[str] = None
        self.session: Optional[aiohttp.ClientSession] = None
        self._rate_limit_remaining = 1000
        self._rate_limit_reset = datetime.now()
    
    async def __aenter__(self):
        await self.start_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close_session()
    
    async def start_session(self):
        """Start aiohttp session"""
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            headers={'User-Agent': self.config.user_agent}
        )
    
    async def close_session(self):
        """Close aiohttp session"""
        if self.session:
            await self.session.close()
    
    async def request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make HTTP request with rate limiting and retry logic"""
        if not self.session:
            await self.start_session()
        
        url = f"{self.config.base_url}{endpoint}"
        headers = kwargs.pop('headers', {})
        
        if self.token:
            headers['Authorization'] = f'Token {self.token}'
        
        # Rate limiting
        await self._handle_rate_limiting()
        
        # Retry logic
        for attempt in range(self.config.max_retries + 1):
            try:
                async with self.session.request(method, url, headers=headers, **kwargs) as response:
                    # Update rate limit info
                    self._update_rate_limit_info(response.headers)
                    
                    data = await response.json()
                    
                    if response.status >= 400:
                        self._handle_error_response(response.status, data)
                    
                    return data
            
            except aiohttp.ClientError as e:
                if attempt == self.config.max_retries:
                    raise PRSAPIError('NETWORK_ERROR', str(e))
                
                await asyncio.sleep(2 ** attempt)
        
        raise PRSAPIError('MAX_RETRIES_EXCEEDED', 'Maximum retry attempts exceeded')
    
    async def _handle_rate_limiting(self):
        """Handle API rate limiting"""
        if (self._rate_limit_remaining <= 10 and 
            datetime.now() < self._rate_limit_reset):
            
            wait_time = (self._rate_limit_reset - datetime.now()).total_seconds()
            logger.info(f"Rate limit nearly exceeded, waiting {wait_time} seconds")
            await asyncio.sleep(wait_time)
    
    def _update_rate_limit_info(self, headers: Dict[str, str]):
        """Update rate limit information from response headers"""
        if 'X-RateLimit-Remaining' in headers:
            self._rate_limit_remaining = int(headers['X-RateLimit-Remaining'])
        
        if 'X-RateLimit-Reset' in headers:
            reset_timestamp = int(headers['X-RateLimit-Reset'])
            self._rate_limit_reset = datetime.fromtimestamp(reset_timestamp)
    
    def _handle_error_response(self, status_code: int, data: Dict[str, Any]):
        """Handle error responses"""
        if 'error' in data:
            error_info = data['error']
            raise PRSAPIError(
                error_info.get('code', 'UNKNOWN_ERROR'),
                error_info.get('message', 'An error occurred'),
                details=error_info.get('details', {}),
                status_code=status_code
            )
        elif 'detail' in data:
            raise PRSAPIError(
                self._get_error_code_from_status(status_code),
                data['detail'],
                status_code=status_code
            )
        else:
            raise PRSAPIError(
                'UNKNOWN_ERROR',
                f'HTTP {status_code} error',
                status_code=status_code
            )
    
    # Authentication methods
    async def login(self, email: str, password: str) -> Dict[str, Any]:
        """Login user"""
        data = await self.request('POST', '/auth/login/', json={
            'email': email,
            'password': password
        })
        self.token = data['token']
        return data['user']
    
    async def admin_login(self, email: str, password: str, otp: str = None) -> Dict[str, Any]:
        """Admin login with OTP"""
        if otp is None:
            # Step 1: Initiate login
            return await self.request('POST', '/auth/login/super-admin/', json={
                'email': email,
                'password': password
            })
        else:
            # Step 2: Verify OTP
            data = await self.request('POST', '/auth/login/super-admin/verify/', json={
                'email': email,
                'otp': otp
            })
            self.token = data['token']
            return data['user']
    
    # Deal management
    async def get_deals(self, **filters) -> Dict[str, Any]:
        """Get deals with filtering"""
        params = '&'.join(f"{k}={v}" for k, v in filters.items() if v is not None)
        endpoint = f"/deals/?{params}" if params else "/deals/"
        return await self.request('GET', endpoint)
    
    async def stream_deals(self, **filters) -> AsyncGenerator[Dict[str, Any], None]:
        """Stream deals with pagination"""
        page = 1
        while True:
            data = await self.get_deals(page=page, **filters)
            
            for deal in data['results']:
                yield deal
            
            if not data.get('next'):
                break
            
            page += 1
    
    async def create_deal(self, deal_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new deal"""
        return await self.request('POST', '/deals/', json=deal_data)
    
    async def update_deal(self, deal_id: int, deal_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update existing deal"""
        return await self.request('PATCH', f'/deals/{deal_id}/', json=deal_data)
    
    async def delete_deal(self, deal_id: int) -> None:
        """Delete deal"""
        await self.request('DELETE', f'/deals/{deal_id}/')
    
    # Bulk operations
    async def bulk_create_deals(self, deals_data: List[Dict[str, Any]], batch_size: int = 10) -> List[Dict[str, Any]]:
        """Create multiple deals in batches"""
        results = []
        
        for i in range(0, len(deals_data), batch_size):
            batch = deals_data[i:i + batch_size]
            batch_results = await asyncio.gather(
                *[self.create_deal(deal_data) for deal_data in batch],
                return_exceptions=True
            )
            
            for result in batch_results:
                if isinstance(result, Exception):
                    logger.error(f"Failed to create deal: {result}")
                else:
                    results.append(result)
        
        return results
    
    # Commission tracking
    async def get_commissions(self, **filters) -> Dict[str, Any]:
        """Get commission data"""
        params = '&'.join(f"{k}={v}" for k, v in filters.items() if v is not None)
        endpoint = f"/commission/?{params}" if params else "/commission/"
        return await self.request('GET', endpoint)
    
    async def get_commission_summary(self, user_id: int, period: str = 'this_month') -> Dict[str, Any]:
        """Get commission summary for user"""
        return await self.request('GET', f'/commission/user-summary/{user_id}/', params={'period': period})

# Usage example
async def main():
    config = PRSConfig(base_url='https://api.prs.com/api')
    
    async with PRSAsyncClient(config) as client:
        # Login
        user = await client.login('user@example.com', 'password123')
        print(f"Logged in as: {user['first_name']} {user['last_name']}")
        
        # Stream all active deals
        active_deals = []
        async for deal in client.stream_deals(status='in_progress'):
            active_deals.append(deal)
            print(f"Deal: {deal['title']} - ${deal['deal_value']}")
        
        # Bulk create deals
        new_deals = [
            {'title': f'Deal {i}', 'client': 1, 'deal_value': f'{(i+1)*10000}.00'}
            for i in range(5)
        ]
        created_deals = await client.bulk_create_deals(new_deals)
        print(f"Created {len(created_deals)} deals")
        
        # Get commission summary
        commission_summary = await client.get_commission_summary(user['id'])
        print(f"Total commission: ${commission_summary['total_commission']}")

if __name__ == '__main__':
    asyncio.run(main())
```

---

## 🔧 Integration Best Practices

### Configuration Management

```python
# config.py
import os
from dataclasses import dataclass
from typing import Optional

@dataclass
class PRSClientConfig:
    """PRS API client configuration"""
    
    # API Settings
    base_url: str = os.getenv('PRS_API_URL', 'http://localhost:8000/api')
    timeout: int = int(os.getenv('PRS_API_TIMEOUT', '30'))
    max_retries: int = int(os.getenv('PRS_API_MAX_RETRIES', '3'))
    
    # Authentication
    token: Optional[str] = os.getenv('PRS_API_TOKEN')
    
    # Rate Limiting
    rate_limit_enabled: bool = os.getenv('PRS_RATE_LIMIT_ENABLED', 'true').lower() == 'true'
    rate_limit_per_hour: int = int(os.getenv('PRS_RATE_LIMIT_PER_HOUR', '1000'))
    
    # Logging
    log_level: str = os.getenv('PRS_LOG_LEVEL', 'INFO')
    log_requests: bool = os.getenv('PRS_LOG_REQUESTS', 'false').lower() == 'true'
    
    # Development
    debug: bool = os.getenv('PRS_DEBUG', 'false').lower() == 'true'
    verify_ssl: bool = os.getenv('PRS_VERIFY_SSL', 'true').lower() == 'true'
    
    @classmethod
    def from_env(cls) -> 'PRSClientConfig':
        """Create configuration from environment variables"""
        return cls()
    
    @classmethod
    def from_file(cls, config_file: str) -> 'PRSClientConfig':
        """Create configuration from file"""
        import json
        with open(config_file) as f:
            data = json.load(f)
        return cls(**data)
```

### Error Handling Middleware

```javascript
// middleware/errorHandling.js
class PRSErrorMiddleware {
    constructor(options = {}) {
        this.retryableErrors = options.retryableErrors || [
            'RATE_LIMIT_EXCEEDED',
            'INTERNAL_ERROR',
            'TIMEOUT_ERROR',
            'NETWORK_ERROR'
        ];
        
        this.maxRetries = options.maxRetries || 3;
        this.baseDelay = options.baseDelay || 1000;
        this.onError = options.onError || console.error;
    }
    
    async handle(apiCall, context = {}) {
        let lastError = null;
        
        for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
            try {
                return await apiCall();
            } catch (error) {
                lastError = error;
                
                // Don't retry non-retryable errors
                if (!this.retryableErrors.includes(error.errorCode)) {
                    break;
                }
                
                // Don't retry on last attempt
                if (attempt === this.maxRetries) {
                    break;
                }
                
                // Calculate delay with exponential backoff
                const delay = this.baseDelay * Math.pow(2, attempt);
                await this.sleep(delay);
                
                // Log retry attempt
                console.log(`Retrying API call (attempt ${attempt + 2}/${this.maxRetries + 1}) after ${delay}ms`);
            }
        }
        
        // Call error handler
        this.onError(lastError, context);
        throw lastError;
    }
    
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// Usage
const errorMiddleware = new PRSErrorMiddleware({
    onError: (error, context) => {
        console.error('PRS API Error:', error);
        // Send to monitoring service
        analytics.track('api_error', {
            error_code: error.errorCode,
            context: context
        });
    }
});

// In API client
async createDeal(dealData) {
    return errorMiddleware.handle(
        () => this.api('/deals/', { method: 'POST', body: JSON.stringify(dealData) }),
        { action: 'create_deal', deal_data: dealData }
    );
}
```

---

## 📊 Monitoring and Analytics Integration

### Analytics Tracking

```javascript
// analytics/prsAnalytics.js
class PRSAnalytics {
    constructor(analyticsProvider) {
        this.provider = analyticsProvider;
    }
    
    trackAPICall(endpoint, method, duration, success) {
        this.provider.track('api_call', {
            endpoint,
            method,
            duration,
            success,
            timestamp: new Date().toISOString()
        });
    }
    
    trackAuthentication(method, success, errorCode = null) {
        this.provider.track('authentication', {
            method, // 'login', 'admin_login', 'logout'
            success,
            error_code: errorCode,
            timestamp: new Date().toISOString()
        });
    }
    
    trackBusinessAction(action, entityType, entityId, metadata = {}) {
        this.provider.track('business_action', {
            action, // 'create', 'update', 'delete', 'view'
            entity_type: entityType, // 'deal', 'client', 'commission'
            entity_id: entityId,
            metadata,
            timestamp: new Date().toISOString()
        });
    }
    
    trackError(error, context = {}) {
        this.provider.track('api_error', {
            error_code: error.errorCode,
            error_message: error.message,
            status_code: error.statusCode,
            context,
            timestamp: new Date().toISOString()
        });
    }
}

// Integration with PRS client
class AnalyticsEnabledPRSClient extends PRSAPIClient {
    constructor(baseUrl, analytics) {
        super(baseUrl);
        this.analytics = analytics;
    }
    
    async request(endpoint, options = {}) {
        const startTime = Date.now();
        const method = options.method || 'GET';
        
        try {
            const result = await super.request(endpoint, options);
            const duration = Date.now() - startTime;
            
            this.analytics.trackAPICall(endpoint, method, duration, true);
            return result;
        } catch (error) {
            const duration = Date.now() - startTime;
            
            this.analytics.trackAPICall(endpoint, method, duration, false);
            this.analytics.trackError(error, { endpoint, method });
            throw error;
        }
    }
    
    async createDeal(dealData) {
        const deal = await super.createDeal(dealData);
        this.analytics.trackBusinessAction('create', 'deal', deal.id, {
            deal_value: deal.deal_value,
            client: deal.client
        });
        return deal;
    }
}
```

---

## 📚 Documentation and Support

### SDK Documentation Generator

```python
# Generate SDK documentation from code
def generate_sdk_docs():
    """Generate comprehensive SDK documentation"""
    
    docs = {
        'title': 'PRS API SDK Documentation',
        'version': '1.0.0',
        'languages': {
            'python': {
                'installation': 'pip install prs-python-sdk',
                'quickstart': python_quickstart_example(),
                'examples': python_examples()
            },
            'javascript': {
                'installation': 'npm install prs-js-sdk',
                'quickstart': javascript_quickstart_example(),
                'examples': javascript_examples()
            },
            'swift': {
                'installation': 'Swift Package Manager integration',
                'quickstart': swift_quickstart_example(),
                'examples': swift_examples()
            }
        },
        'common_patterns': {
            'authentication': auth_patterns(),
            'error_handling': error_handling_patterns(),
            'pagination': pagination_patterns(),
            'bulk_operations': bulk_operation_patterns()
        }
    }
    
    return docs
```

This comprehensive SDK guide provides production-ready integration examples across multiple platforms and frameworks, with advanced features like error handling, retry logic, rate limiting, and analytics integration.
