# Backend_PRS - Comprehensive Documentation

## Table of Contents
1. [Project Overview](#project-overview)
2. [System Architecture](#system-architecture)
3. [API Reference](#api-reference)
4. [Database Schema](#database-schema)
5. [Authentication & Authorization](#authentication--authorization)
6. [Installation & Setup](#installation--setup)
7. [Environment Configuration](#environment-configuration)
8. [Deployment Guide](#deployment-guide)
9. [Security Features](#security-features)
10. [Management Commands](#management-commands)
11. [Testing](#testing)
12. [Troubleshooting](#troubleshooting)

---

## Project Overview

**Backend_PRS** is a comprehensive Django REST Framework-based backend system for a Payment Receiving System (PRS). It provides a complete multi-tenant SaaS solution for managing sales operations, client relationships, payment processing, and commission tracking with role-based access control.

### Key Features
- 🏢 **Multi-tenant Architecture** - Organization-based data isolation
- 🔐 **Role-Based Access Control** - Granular permissions system
- 💰 **Payment Processing** - Complete payment workflow management
- 📊 **Analytics Dashboard** - Real-time sales and performance metrics
- 🔄 **Real-time Notifications** - WebSocket-based instant updates
- 🛡️ **Security First** - Comprehensive security measures
- 📈 **Commission Tracking** - Automated commission calculations
- 🎯 **Gamification** - Sales streaks and performance tracking

### Technology Stack
- **Framework:** Django 5.2.2 + Django REST Framework 3.15.2
- **Database:** PostgreSQL (Primary), SQLite (Development)
- **Cache/Queuing:** Redis
- **Real-time:** Django Channels + WebSockets
- **Media Storage:** Cloudinary
- **Authentication:** JWT + Multi-factor Authentication
- **Documentation:** Swagger/OpenAPI

---

## System Architecture

### Multi-Tenant Architecture

The system implements a sophisticated multi-tenant architecture:

```mermaid
graph TB
    A[Super Admin] --> B[Organization 1]
    A --> C[Organization 2]
    A --> D[Organization N]
    
    B --> B1[Org Admin 1]
    B --> B2[Users]
    B --> B3[Teams]
    B --> B4[Data]
    
    C --> C1[Org Admin 2] 
    C --> C2[Users]
    C --> C3[Teams]
    C --> C4[Data]
```

### Core Components

1. **Authentication System** - User management, roles, permissions
2. **Organization Management** - Multi-tenant isolation
3. **Business Logic** - Clients, deals, payments, commission
4. **Dashboard Systems** - Sales and verifier dashboards
5. **Notification System** - Real-time notifications
6. **Team Management** - Team organization and assignments

### Django Apps Structure

```
backend/
├── authentication/          # User management & auth
├── organization/           # Multi-tenant organization management
├── permissions/            # Role-based access control
├── clients/               # Client relationship management
├── deals/                 # Core business logic (deals & payments)
├── commission/            # Commission calculations
├── team/                  # Team management
├── project/               # Project management
├── notifications/         # Real-time notification system
├── Sales_dashboard/       # Sales analytics & performance
├── Verifier_dashboard/    # Payment verification workflows
└── core_config/          # Project configuration
```

---

## API Reference

### Base URL Structure
```
https://your-domain.com/api/
```

### Authentication Endpoints (`/api/auth/`)

#### User Authentication
```http
POST /api/auth/login/
Content-Type: application/json

{
    "email": "user@example.com",
    "password": "password123"
}
```

**Response:**
```json
{
    "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "user": {
        "id": "uuid-here",
        "email": "user@example.com",
        "role": "salesperson",
        "organization": "org-uuid"
    }
}
```

#### User Registration
```http
POST /api/auth/register/
Content-Type: application/json

{
    "email": "newuser@example.com",
    "password": "securepassword",
    "first_name": "John",
    "last_name": "Doe",
    "role": "salesperson",
    "organization": "org-uuid"
}
```

#### Password Change
```http
POST /api/auth/change-password/
Authorization: Bearer <access_token>
Content-Type: application/json

{
    "old_password": "oldpassword",
    "new_password": "newpassword"
}
```

### Business Logic Endpoints

#### Clients Management (`/api/clients/`)

**List Clients**
```http
GET /api/clients/
Authorization: Bearer <access_token>

Query Parameters:
- page: Page number (default: 1)
- page_size: Items per page (default: 20)
- search: Search by name or email
- status: Filter by client status
```

**Create Client**
```http
POST /api/clients/
Authorization: Bearer <access_token>
Content-Type: application/json

{
    "client_name": "ABC Company",
    "email": "contact@abc.com",
    "contact_number": "+1234567890",
    "nationality": "US",
    "client_satisfaction": 5,
    "address": "123 Main St, City, State"
}
```

**Get Client Details**
```http
GET /api/clients/{client_id}/
Authorization: Bearer <access_token>
```

**Update Client**
```http
PUT /api/clients/{client_id}/
Authorization: Bearer <access_token>
Content-Type: application/json

{
    "client_name": "Updated Company Name",
    "email": "newemail@abc.com"
}
```

#### Deals Management (`/api/deals/`)

**List Deals**
```http
GET /api/deals/
Authorization: Bearer <access_token>

Query Parameters:
- client: Filter by client ID
- status: Filter by verification status
- payment_status: Filter by payment status
- date_from: Start date filter (YYYY-MM-DD)
- date_to: End date filter (YYYY-MM-DD)
```

**Create Deal**
```http
POST /api/deals/
Authorization: Bearer <access_token>
Content-Type: application/json

{
    "client": "client-uuid",
    "project": "project-uuid",
    "deal_name": "Website Development",
    "deal_value": "5000.00",
    "currency": "USD",
    "payment_method": "bank",
    "payment_status": "initial payment",
    "source_type": "linkedin",
    "due_date": "2024-12-31",
    "deal_remarks": "Initial payment received"
}
```

**Get Deal Details**
```http
GET /api/deals/{deal_id}/
Authorization: Bearer <access_token>
```

**Update Deal**
```http
PUT /api/deals/{deal_id}/
Authorization: Bearer <access_token>
Content-Type: application/json

{
    "verification_status": "verified",
    "deal_remarks": "Updated remarks"
}
```

#### Payments (`/api/deals/{deal_id}/payments/`)

**Add Payment**
```http
POST /api/deals/{deal_id}/payments/
Authorization: Bearer <access_token>
Content-Type: multipart/form-data

payment_amount: 2500.00
payment_method: bank
payment_date: 2024-01-15
payment_receipt: <file>
payment_remarks: Partial payment received
```

**List Payments**
```http
GET /api/deals/{deal_id}/payments/
Authorization: Bearer <access_token>
```

#### Commission (`/api/commission/`)

**Get Commission Summary**
```http
GET /api/commission/summary/
Authorization: Bearer <access_token>

Query Parameters:
- period: daily, weekly, monthly, yearly
- start_date: YYYY-MM-DD
- end_date: YYYY-MM-DD
```

**Get User Commissions**
```http
GET /api/commission/user/{user_id}/
Authorization: Bearer <access_token>
```

### Dashboard Endpoints

#### Sales Dashboard (`/api/dashboard/`)

**Get Dashboard Overview**
```http
GET /api/dashboard/overview/
Authorization: Bearer <access_token>
```

**Response:**
```json
{
    "total_deals": 150,
    "total_revenue": "75000.00",
    "pending_deals": 25,
    "verified_deals": 125,
    "monthly_target": "100000.00",
    "monthly_achieved": "75000.00",
    "streak_count": 15,
    "recent_deals": [...],
    "performance_chart": {...}
}
```

**Get Sales Performance**
```http
GET /api/dashboard/performance/
Authorization: Bearer <access_token>

Query Parameters:
- period: daily, weekly, monthly
- user_id: Specific user (admin only)
```

#### Verifier Dashboard (`/api/verifier/`)

**Get Verification Queue**
```http
GET /api/verifier/queue/
Authorization: Bearer <access_token>

Query Parameters:
- status: pending, verified, rejected
- priority: high, medium, low
```

**Verify Payment**
```http
POST /api/verifier/verify/{payment_id}/
Authorization: Bearer <access_token>
Content-Type: application/json

{
    "verification_status": "verified",
    "verifier_remarks": "Payment confirmed",
    "verified_amount": "2500.00"
}
```

### Team Management (`/api/team/`)

**List Teams**
```http
GET /api/team/
Authorization: Bearer <access_token>
```

**Create Team**
```http
POST /api/team/
Authorization: Bearer <access_token>
Content-Type: application/json

{
    "team_name": "Sales Team Alpha",
    "team_lead": "user-uuid",
    "description": "Primary sales team"
}
```

### Notifications (`/api/notifications/`)

**Get User Notifications**
```http
GET /api/notifications/
Authorization: Bearer <access_token>

Query Parameters:
- read: true/false
- notification_type: payment, deal, system
```

**Mark as Read**
```http
POST /api/notifications/{notification_id}/mark-read/
Authorization: Bearer <access_token>
```

### Organizations (`/api/organizations/`)

**Get Organization Details**
```http
GET /api/organizations/{org_id}/
Authorization: Bearer <access_token>
```

**Update Organization**
```http
PUT /api/organizations/{org_id}/
Authorization: Bearer <access_token>
Content-Type: application/json

{
    "organization_name": "Updated Org Name",
    "contact_email": "admin@updated.com",
    "organization_address": "New Address"
}
```

---

## Database Schema

### Core Models

#### User Model (`authentication.User`)
```sql
CREATE TABLE authentication_user (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(254) UNIQUE NOT NULL,
    username VARCHAR(150),
    first_name VARCHAR(150),
    last_name VARCHAR(150),
    organization_id UUID REFERENCES organization_organization(id),
    role_id UUID REFERENCES permissions_role(id),
    team_id UUID REFERENCES team_team(id),
    contact_number VARCHAR(30),
    address TEXT,
    status VARCHAR(20) DEFAULT 'active',
    must_change_password BOOLEAN DEFAULT FALSE,
    login_count INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    is_staff BOOLEAN DEFAULT FALSE,
    is_superuser BOOLEAN DEFAULT FALSE,
    date_joined TIMESTAMP DEFAULT NOW(),
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

#### Organization Model (`organization.Organization`)
```sql
CREATE TABLE organization_organization (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_name VARCHAR(255) NOT NULL,
    organization_description TEXT,
    contact_email VARCHAR(254),
    contact_number VARCHAR(30),
    organization_address TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

#### Client Model (`clients.Client`)
```sql
CREATE TABLE clients_client (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organization_organization(id) ON DELETE CASCADE,
    created_by_id UUID REFERENCES authentication_user(id) ON DELETE PROTECT,
    client_name VARCHAR(255) NOT NULL,
    email VARCHAR(254),
    contact_number VARCHAR(30),
    nationality VARCHAR(100),
    client_satisfaction INTEGER CHECK (client_satisfaction BETWEEN 1 AND 5),
    address TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

#### Deal Model (`deals.Deal`)
```sql
CREATE TABLE deals_deal (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    deal_id VARCHAR(50) UNIQUE,
    organization_id UUID REFERENCES organization_organization(id) ON DELETE CASCADE,
    client_id UUID REFERENCES clients_client(id) ON DELETE CASCADE,
    project_id UUID REFERENCES project_project(id) ON DELETE CASCADE,
    created_by_id UUID REFERENCES authentication_user(id) ON DELETE PROTECT,
    updated_by_id UUID REFERENCES authentication_user(id) ON DELETE SET NULL,
    deal_name VARCHAR(255) NOT NULL,
    deal_value DECIMAL(10,2) NOT NULL,
    currency VARCHAR(3) DEFAULT 'USD',
    payment_status VARCHAR(50) NOT NULL,
    payment_method VARCHAR(100) NOT NULL,
    source_type VARCHAR(50) NOT NULL,
    verification_status VARCHAR(100) DEFAULT 'pending',
    client_status VARCHAR(100) DEFAULT 'pending',
    version VARCHAR(10) DEFAULT 'original',
    deal_date DATE DEFAULT CURRENT_DATE,
    due_date DATE,
    deal_remarks TEXT,
    payment_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

#### Payment Model (`deals.Payment`)
```sql
CREATE TABLE deals_payment (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id VARCHAR(50) UNIQUE,
    deal_id UUID REFERENCES deals_deal(id) ON DELETE CASCADE,
    payment_amount DECIMAL(10,2) NOT NULL,
    payment_method VARCHAR(100) NOT NULL,
    payment_date DATE NOT NULL,
    payment_receipt VARCHAR(255),
    payment_remarks TEXT,
    verification_status VARCHAR(100) DEFAULT 'pending',
    verified_by_id UUID REFERENCES authentication_user(id) ON DELETE SET NULL,
    verified_at TIMESTAMP,
    verifier_remarks TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

### Relationships

```mermaid
erDiagram
    Organization ||--o{ User : "has many"
    Organization ||--o{ Client : "has many"
    Organization ||--o{ Deal : "has many"
    Organization ||--o{ Team : "has many"
    
    User ||--o{ Deal : "creates"
    User ||--o{ Payment : "verifies"
    User }o--|| Role : "has"
    User }o--o| Team : "belongs to"
    
    Client ||--o{ Deal : "has many"
    Deal ||--o{ Payment : "has many"
    Deal }o--|| Project : "belongs to"
    
    Team ||--o{ User : "has members"
    Role ||--o{ Permission : "has many"
```

### Indexes and Performance

Key database indexes for optimal performance:

```sql
-- User indexes
CREATE INDEX idx_user_organization ON authentication_user(organization_id);
CREATE INDEX idx_user_role ON authentication_user(role_id);
CREATE INDEX idx_user_email ON authentication_user(email);

-- Deal indexes
CREATE INDEX idx_deal_client_created ON deals_deal(client_id, created_at);
CREATE INDEX idx_deal_organization ON deals_deal(organization_id);
CREATE INDEX idx_deal_verification_status ON deals_deal(verification_status);
CREATE INDEX idx_deal_payment_status ON deals_deal(payment_status);
CREATE INDEX idx_deal_created_by ON deals_deal(created_by_id);

-- Payment indexes
CREATE INDEX idx_payment_deal ON deals_payment(deal_id);
CREATE INDEX idx_payment_verification ON deals_payment(verification_status);
CREATE INDEX idx_payment_date ON deals_payment(payment_date);

-- Client indexes
CREATE INDEX idx_client_organization ON clients_client(organization_id);
CREATE INDEX idx_client_created_by ON clients_client(created_by_id);
```

---

## Authentication & Authorization

### Authentication Methods

1. **Email-based Authentication**
   - Primary login method using email and password
   - JWT token-based authentication for API access

2. **Multi-Factor Authentication (MFA)**
   - Available for admin users
   - TOTP-based second factor
   - Backup codes for recovery

3. **Session Management**
   - Secure session handling
   - Session timeout configuration
   - Active session tracking

### Role-Based Access Control (RBAC)

#### User Roles

1. **Super Admin**
   - System-wide administration
   - Organization management
   - User role assignments
   - System configuration

2. **Organization Admin**
   - Organization-specific administration
   - User management within organization
   - Team and project management
   - Commission and payment oversight

3. **Salesperson**
   - Client management
   - Deal creation and management
   - Payment recording
   - Commission tracking

4. **Verifier**
   - Payment verification
   - Invoice approval
   - Audit trail management
   - Verification queue management

5. **Team Lead**
   - Team member oversight
   - Performance monitoring
   - Team goal setting
   - Member guidance

### Permission System

Permissions are organized into categories:

#### Authentication Permissions
- `auth.view_user`
- `auth.add_user`
- `auth.change_user`
- `auth.delete_user`

#### Client Permissions
- `clients.view_client`
- `clients.add_client`
- `clients.change_client`
- `clients.delete_client`

#### Deal Permissions
- `deals.view_deal`
- `deals.add_deal`
- `deals.change_deal`
- `deals.delete_deal`
- `deals.verify_deal`
- `deals.view_all_deals` (admin only)

#### Payment Permissions
- `deals.view_payment`
- `deals.add_payment`
- `deals.verify_payment`
- `deals.approve_payment`

#### Commission Permissions
- `commission.view_commission`
- `commission.view_all_commissions` (admin only)
- `commission.calculate_commission`

### Authentication Flow

```mermaid
sequenceDiagram
    participant C as Client
    participant A as API
    participant D as Database
    participant R as Redis
    
    C->>A: POST /api/auth/login/
    A->>D: Validate credentials
    D-->>A: User data
    A->>R: Store session
    A-->>C: JWT tokens + user data
    
    C->>A: API request with Bearer token
    A->>R: Validate token
    R-->>A: Token valid
    A->>D: Process request
    D-->>A: Response data
    A-->>C: API response
```

### Security Middleware

1. **Token Validation Middleware**
   - Validates JWT tokens on each request
   - Handles token refresh automatically
   - Rate limiting for authentication attempts

2. **Organization Isolation Middleware**
   - Ensures data access within organization boundaries
   - Prevents cross-organization data leakage

3. **Permission Check Middleware**
   - Validates user permissions for each endpoint
   - Logs unauthorized access attempts

---

## Installation & Setup

### System Requirements

- **Python**: 3.8+
- **Database**: PostgreSQL 12+ (SQLite for development)
- **Cache/Queue**: Redis 6+
- **OS**: Linux/macOS/Windows
- **Memory**: 2GB+ RAM recommended
- **Storage**: 10GB+ available space

### Development Setup

#### 1. Clone Repository
```bash
git clone https://github.com/your-org/backend-prs.git
cd backend-prs
```

#### 2. Create Virtual Environment
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Linux/macOS:
source venv/bin/activate
# On Windows:
venv\Scripts\activate
```

#### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

#### 4. Environment Configuration
```bash
# Copy environment template
cp .env.example .env

# Edit environment variables
nano .env
```

#### 5. Database Setup
```bash
# Run migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Load initial data (optional)
python manage.py loaddata fixtures/initial_data.json
```

#### 6. Static Files
```bash
python manage.py collectstatic --noinput
```

#### 7. Run Development Server
```bash
python manage.py runserver
```

### Production Setup

#### 1. Server Preparation
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y python3 python3-pip python3-venv postgresql redis-server nginx
```

#### 2. PostgreSQL Setup
```bash
# Create database and user
sudo -u postgres psql

CREATE DATABASE prs_production;
CREATE USER prs_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE prs_production TO prs_user;
ALTER USER prs_user CREATEDB;
\q
```

#### 3. Redis Configuration
```bash
# Configure Redis
sudo nano /etc/redis/redis.conf

# Set password
requirepass your_redis_password

# Restart Redis
sudo systemctl restart redis-server
```

#### 4. Application Deployment
```bash
# Clone and setup application
git clone https://github.com/your-org/backend-prs.git /var/www/backend-prs
cd /var/www/backend-prs

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install gunicorn

# Configure environment
nano .env.production
```

#### 5. Gunicorn Configuration
Create `/var/www/backend-prs/gunicorn_config.py`:
```python
bind = "127.0.0.1:8000"
workers = 3
worker_class = "gevent"
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 50
timeout = 30
keepalive = 2
user = "www-data"
group = "www-data"
```

#### 6. Systemd Service
Create `/etc/systemd/system/backend-prs.service`:
```ini
[Unit]
Description=Backend PRS Gunicorn daemon
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/backend-prs
Environment="PATH=/var/www/backend-prs/venv/bin"
ExecStart=/var/www/backend-prs/venv/bin/gunicorn --config gunicorn_config.py core_config.wsgi:application
ExecReload=/bin/kill -s HUP $MAINPID
Restart=always

[Install]
WantedBy=multi-user.target
```

#### 7. Nginx Configuration
Create `/etc/nginx/sites-available/backend-prs`:
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location = /favicon.ico { access_log off; log_not_found off; }
    
    location /static/ {
        root /var/www/backend-prs;
        expires 1M;
        access_log off;
        add_header Cache-Control "public, immutable";
    }

    location /media/ {
        root /var/www/backend-prs;
        expires 1M;
        access_log off;
        add_header Cache-Control "public, immutable";
    }

    location / {
        include proxy_params;
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

#### 8. Enable Services
```bash
# Enable and start services
sudo systemctl enable backend-prs
sudo systemctl start backend-prs

# Enable and configure Nginx
sudo ln -s /etc/nginx/sites-available/backend-prs /etc/nginx/sites-enabled
sudo systemctl enable nginx
sudo systemctl restart nginx

# Configure SSL with Let's Encrypt
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

### Docker Setup

#### Dockerfile
```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python manage.py collectstatic --noinput

EXPOSE 8000

CMD ["gunicorn", "--config", "gunicorn_config.py", "core_config.wsgi:application"]
```

#### docker-compose.yml
```yaml
version: '3.8'

services:
  web:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://postgres:password@db:5432/prs_db
      - REDIS_URL=redis://redis:6379
    depends_on:
      - db
      - redis
    volumes:
      - static_volume:/app/staticfiles
      - media_volume:/app/media

  db:
    image: postgres:15
    environment:
      POSTGRES_DB: prs_db
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: password
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass password

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - static_volume:/app/staticfiles
      - media_volume:/app/media
    depends_on:
      - web

volumes:
  postgres_data:
  static_volume:
  media_volume:
```

---

## Environment Configuration

### Environment Variables

#### Database Configuration
```env
# Primary Database (PostgreSQL)
DATABASE_URL=postgresql://username:password@localhost:5432/database_name

# Development Database (SQLite) - Optional
USE_SQLITE=false
SQLITE_DB_PATH=db.sqlite3
```

#### Django Settings
```env
# Django Secret Key (Generate new for production)
SECRET_KEY=your-very-secure-secret-key-here

# Debug Mode (Never set to True in production)
DEBUG=false

# Allowed Hosts (Comma-separated)
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com,localhost

# CORS Settings
CORS_ALLOW_ALL_ORIGINS=false
CORS_ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
```

#### Cache Configuration
```env
# Redis Cache
REDIS_URL=redis://username:password@localhost:6379/0

# Alternative Redis configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your-redis-password
REDIS_DB=0
```

#### Email Configuration
```env
# Email Backend
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend

# SMTP Settings
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=true
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password

# From Email
DEFAULT_FROM_EMAIL=noreply@yourdomain.com
SERVER_EMAIL=admin@yourdomain.com
```

#### Media Storage (Cloudinary)
```env
# Cloudinary Configuration
CLOUDINARY_CLOUD_NAME=your-cloud-name
CLOUDINARY_API_KEY=your-api-key
CLOUDINARY_API_SECRET=your-api-secret

# Alternative: Use local storage
USE_CLOUDINARY=false
MEDIA_ROOT=/path/to/media/files
```

#### Security Settings
```env
# CSRF Settings
CSRF_COOKIE_SECURE=true
CSRF_COOKIE_HTTPONLY=true
CSRF_TRUSTED_ORIGINS=https://yourdomain.com

# Session Security
SESSION_COOKIE_SECURE=true
SESSION_COOKIE_HTTPONLY=true
SESSION_COOKIE_AGE=3600
SESSION_EXPIRE_AT_BROWSER_CLOSE=true

# HTTPS Settings
SECURE_SSL_REDIRECT=true
SECURE_HSTS_SECONDS=31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS=true
SECURE_HSTS_PRELOAD=true
```

#### JWT Configuration
```env
# JWT Settings
JWT_SECRET_KEY=your-jwt-secret-key
JWT_ACCESS_TOKEN_LIFETIME=5  # minutes
JWT_REFRESH_TOKEN_LIFETIME=1440  # minutes (24 hours)
JWT_ALGORITHM=HS256
```

#### API Settings
```env
# API Rate Limiting
API_THROTTLE_RATE_ANON=100/hour
API_THROTTLE_RATE_USER=1000/hour

# Pagination
API_PAGE_SIZE=20
API_MAX_PAGE_SIZE=100
```

#### Monitoring and Logging
```env
# Logging Level
LOG_LEVEL=INFO

# Sentry (Error Tracking)
SENTRY_DSN=https://your-sentry-dsn.ingest.sentry.io/project-id

# New Relic (Performance Monitoring)
NEW_RELIC_LICENSE_KEY=your-new-relic-key
NEW_RELIC_APP_NAME=Backend-PRS
```

### Configuration Files

#### settings.py Structure
```python
# backend/core_config/settings.py
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Build paths
BASE_DIR = Path(__file__).resolve().parent.parent

# Security
SECRET_KEY = os.getenv('SECRET_KEY')
DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', '').split(',')

# Application definition
DJANGO_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]

THIRD_PARTY_APPS = [
    'rest_framework',
    'rest_framework_simplejwt',
    'corsheaders',
    'drf_yasg',
    'channels',
    'cloudinary',
    'cloudinary_storage',
]

LOCAL_APPS = [
    'authentication',
    'organization',
    'permissions',
    'clients',
    'deals',
    'commission',
    'team',
    'project',
    'notifications',
    'Sales_dashboard',
    'Verifier_dashboard',
]

INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

# Middleware
MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'core_config.middleware.OrganizationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# Database configuration
if os.getenv('USE_SQLITE', 'False').lower() == 'true':
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': os.getenv('DB_NAME'),
            'USER': os.getenv('DB_USER'),
            'PASSWORD': os.getenv('DB_PASSWORD'),
            'HOST': os.getenv('DB_HOST', 'localhost'),
            'PORT': os.getenv('DB_PORT', '5432'),
        }
    }
```

### Environment-Specific Settings

#### Development (.env.development)
```env
DEBUG=true
ALLOWED_HOSTS=localhost,127.0.0.1,0.0.0.0
USE_SQLITE=true
EMAIL_BACKEND=django.core.mail.backends.console.EmailBackend
CORS_ALLOW_ALL_ORIGINS=true
```

#### Staging (.env.staging)
```env
DEBUG=false
ALLOWED_HOSTS=staging.yourdomain.com
DATABASE_URL=postgresql://user:pass@staging-db:5432/prs_staging
CORS_ALLOW_ALL_ORIGINS=false
CORS_ALLOWED_ORIGINS=https://staging-frontend.yourdomain.com
```

#### Production (.env.production)
```env
DEBUG=false
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com
DATABASE_URL=postgresql://user:pass@prod-db:5432/prs_production
SECURE_SSL_REDIRECT=true
SESSION_COOKIE_SECURE=true
CSRF_COOKIE_SECURE=true
USE_CLOUDINARY=true
SENTRY_DSN=https://your-sentry-dsn.ingest.sentry.io/project-id
```

---

## Deployment Guide

### Render.com Deployment

#### 1. Preparation

**Create deployment scripts:**

`render.sh`:
```bash
#!/usr/bin/env bash
set -o errexit

pip install -r requirements.txt
python manage.py collectstatic --noinput
python manage.py migrate
```

`render-start-safe.sh`:
```bash
#!/usr/bin/env bash
python manage.py migrate --check
gunicorn --config gunicorn_config.py core_config.wsgi:application
```

#### 2. Render Configuration

**render.yaml**:
```yaml
services:
  - type: web
    name: backend-prs
    env: python
    region: oregon
    plan: starter
    buildCommand: "./render.sh"
    startCommand: "./render-start-safe.sh"
    envVars:
      - key: SECRET_KEY
        generateValue: true
      - key: DEBUG
        value: false
      - key: DATABASE_URL
        fromDatabase:
          name: prs-database
          property: connectionString
      - key: REDIS_URL
        fromService:
          type: redis
          name: prs-redis
          property: connectionString

databases:
  - name: prs-database
    databaseName: prs_production
    plan: starter

services:
  - type: redis
    name: prs-redis
    plan: starter
    maxmemoryPolicy: allkeys-lru
```

#### 3. Environment Variables in Render
```
SECRET_KEY=<auto-generated>
DEBUG=false
DATABASE_URL=<from-database>
REDIS_URL=<from-redis>
ALLOWED_HOSTS=your-app-name.onrender.com
CORS_ALLOWED_ORIGINS=https://your-frontend.com
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password
CLOUDINARY_CLOUD_NAME=your-cloud-name
CLOUDINARY_API_KEY=your-api-key
CLOUDINARY_API_SECRET=your-api-secret
```

### AWS Deployment

#### 1. EC2 Setup

**Launch EC2 Instance:**
```bash
# Connect to EC2
ssh -i your-key.pem ubuntu@your-ec2-ip

# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y python3 python3-pip python3-venv postgresql-client nginx redis-tools git
```

#### 2. RDS Database Setup

**Create PostgreSQL RDS Instance:**
- Engine: PostgreSQL 15
- Instance class: db.t3.micro (for testing)
- Storage: 20 GB GP2
- Multi-AZ: No (for cost optimization)
- Public access: No
- Security group: Allow 5432 from EC2 security group

#### 3. ElastiCache Redis Setup

**Create Redis Cluster:**
- Engine: Redis 7
- Node type: cache.t3.micro
- Number of replicas: 0 (for cost optimization)
- Subnet group: Private subnets
- Security group: Allow 6379 from EC2 security group

#### 4. Application Deployment

```bash
# Clone application
git clone https://github.com/your-org/backend-prs.git /opt/backend-prs
cd /opt/backend-prs

# Create virtual environment
sudo python3 -m venv /opt/venv
source /opt/venv/bin/activate

# Install dependencies
pip install -r requirements.txt gunicorn

# Configure environment
sudo nano /opt/backend-prs/.env
```

#### 5. Systemd Service

`/etc/systemd/system/backend-prs.service`:
```ini
[Unit]
Description=Backend PRS
After=network.target

[Service]
Type=notify
User=www-data
Group=www-data
WorkingDirectory=/opt/backend-prs
Environment=PATH=/opt/venv/bin
ExecStart=/opt/venv/bin/gunicorn --config gunicorn_config.py core_config.wsgi:application
ExecReload=/bin/kill -s HUP $MAINPID
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

#### 6. Load Balancer Setup

**Application Load Balancer:**
- Scheme: Internet-facing
- Listeners: HTTP (80) → HTTPS (443)
- Target group: EC2 instances on port 8000
- Health check: /api/health/

#### 7. SSL Certificate

```bash
# Install certbot
sudo apt install certbot

# Get certificate
sudo certbot certonly --webroot -w /var/www/html -d yourdomain.com

# Configure auto-renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

### Docker Deployment

#### 1. Multi-stage Dockerfile

```dockerfile
# Build stage
FROM python:3.11-slim as builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim

# Create non-root user
RUN groupadd -r django && useradd --no-log-init -r -g django django

WORKDIR /app

# Copy dependencies
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application
COPY . .
RUN chown -R django:django /app

# Collect static files
RUN python manage.py collectstatic --noinput

USER django

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/health/ || exit 1

CMD ["gunicorn", "--config", "gunicorn_config.py", "core_config.wsgi:application"]
```

#### 2. Production docker-compose.yml

```yaml
version: '3.8'

services:
  web:
    build: 
      context: .
      dockerfile: Dockerfile
    restart: unless-stopped
    environment:
      - DATABASE_URL=postgresql://postgres:${POSTGRES_PASSWORD}@db:5432/${POSTGRES_DB}
      - REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379/0
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_healthy
    volumes:
      - static_volume:/app/staticfiles
      - media_volume:/app/media
    networks:
      - backend

  db:
    image: postgres:15-alpine
    restart: unless-stopped
    environment:
      POSTGRES_DB: ${POSTGRES_DB}
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER} -d ${POSTGRES_DB}"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - backend

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    command: redis-server --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "--raw", "incr", "ping"]
      interval: 10s
      timeout: 3s
      retries: 5
    networks:
      - backend

  nginx:
    image: nginx:alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/ssl:/etc/nginx/ssl:ro
      - static_volume:/app/staticfiles:ro
      - media_volume:/app/media:ro
    depends_on:
      - web
    networks:
      - backend

volumes:
  postgres_data:
  redis_data:
  static_volume:
  media_volume:

networks:
  backend:
    driver: bridge
```

#### 3. Nginx Configuration

`nginx/nginx.conf`:
```nginx
upstream backend {
    server web:8000;
}

server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com www.yourdomain.com;

    ssl_certificate /etc/nginx/ssl/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    ssl_prefer_server_ciphers off;

    client_max_body_size 100M;

    location /static/ {
        alias /app/staticfiles/;
        expires 1M;
        access_log off;
        add_header Cache-Control "public, immutable";
    }

    location /media/ {
        alias /app/media/;
        expires 1M;
        access_log off;
        add_header Cache-Control "public, immutable";
    }

    location / {
        proxy_pass http://backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

### Monitoring and Health Checks

#### 1. Health Check Endpoint

```python
# core_config/urls.py
def health(request):
    """Health check endpoint for load balancers"""
    try:
        # Check database connection
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            
        # Check Redis connection
        from django.core.cache import cache
        cache.set('health_check', 'ok', 10)
        
        return JsonResponse({
            "status": "healthy",
            "timestamp": timezone.now().isoformat(),
            "version": "1.0.0"
        })
    except Exception as e:
        return JsonResponse({
            "status": "unhealthy",
            "error": str(e),
            "timestamp": timezone.now().isoformat()
        }, status=503)
```

#### 2. Application Monitoring

**Sentry Integration:**
```python
# settings.py
import sentry_sdk
from sentry_sdk.integrations.django import DjangoIntegration

if not DEBUG and os.getenv('SENTRY_DSN'):
    sentry_sdk.init(
        dsn=os.getenv('SENTRY_DSN'),
        integrations=[DjangoIntegration()],
        traces_sample_rate=1.0,
        send_default_pii=True
    )
```

**Prometheus Metrics:**
```python
# monitoring/middleware.py
from prometheus_client import Counter, Histogram
import time

request_count = Counter('django_http_requests_total', 'Total HTTP requests', ['method', 'endpoint'])
request_duration = Histogram('django_http_request_duration_seconds', 'HTTP request duration')

class PrometheusMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        start_time = time.time()
        
        response = self.get_response(request)
        
        duration = time.time() - start_time
        request_count.labels(method=request.method, endpoint=request.path).inc()
        request_duration.observe(duration)
        
        return response
```

---

## Security Features

### Authentication Security

#### 1. Password Policy
```python
# settings.py
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 12,
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
    {
        'NAME': 'authentication.validators.CustomPasswordValidator',
    },
]

# Custom password validator
class CustomPasswordValidator:
    def validate(self, password, user=None):
        if not any(char.isdigit() for char in password):
            raise ValidationError("Password must contain at least one digit.")
        if not any(char.isupper() for char in password):
            raise ValidationError("Password must contain at least one uppercase letter.")
        if not any(char.islower() for char in password):
            raise ValidationError("Password must contain at least one lowercase letter.")
        if not any(char in "!@#$%^&*()_+-=[]{}|;:,.<>?" for char in password):
            raise ValidationError("Password must contain at least one special character.")
```

#### 2. Multi-Factor Authentication (MFA)
```python
# authentication/mfa.py
import pyotp
import qrcode
from io import BytesIO
import base64

class MFAManager:
    @staticmethod
    def generate_secret_key():
        return pyotp.random_base32()
    
    @staticmethod
    def generate_qr_code(user, secret_key):
        totp_uri = pyotp.totp.TOTP(secret_key).provisioning_uri(
            name=user.email,
            issuer_name="Backend PRS"
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        
        return base64.b64encode(buffer.getvalue()).decode()
    
    @staticmethod
    def verify_token(secret_key, token):
        totp = pyotp.TOTP(secret_key)
        return totp.verify(token, valid_window=1)
```

#### 3. Rate Limiting
```python
# core_config/middleware.py
from django.core.cache import cache
from django.http import HttpResponse
from django.utils import timezone
import json

class RateLimitMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        # Rate limit login attempts
        if request.path == '/api/auth/login/' and request.method == 'POST':
            client_ip = self.get_client_ip(request)
            cache_key = f"login_attempts_{client_ip}"
            
            attempts = cache.get(cache_key, 0)
            if attempts >= 5:  # Max 5 attempts per hour
                return HttpResponse(
                    json.dumps({"error": "Too many login attempts. Try again later."}),
                    status=429,
                    content_type="application/json"
                )
            
            cache.set(cache_key, attempts + 1, 3600)  # 1 hour timeout
        
        return self.get_response(request)
    
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
```

### Data Protection

#### 1. Organization Isolation
```python
# core_config/middleware.py
class OrganizationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated and hasattr(request.user, 'organization'):
            request.organization = request.user.organization
        else:
            request.organization = None
            
        return self.get_response(request)

# Custom model manager for organization isolation
class OrganizationQuerySet(models.QuerySet):
    def for_organization(self, organization):
        return self.filter(organization=organization)

class OrganizationManager(models.Manager):
    def get_queryset(self):
        return OrganizationQuerySet(self.model, using=self._db)
    
    def for_organization(self, organization):
        return self.get_queryset().for_organization(organization)
```

#### 2. File Upload Security
```python
# deals/validators.py
import mimetypes
import magic
from django.core.exceptions import ValidationError
from django.conf import settings

ALLOWED_EXTENSIONS = {'.pdf', '.jpg', '.jpeg', '.png', '.gif', '.doc', '.docx'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

def validate_file_security(file):
    # Check file size
    if file.size > MAX_FILE_SIZE:
        raise ValidationError(f'File too large. Maximum size is {MAX_FILE_SIZE/1024/1024}MB')
    
    # Check file extension
    file_extension = os.path.splitext(file.name)[1].lower()
    if file_extension not in ALLOWED_EXTENSIONS:
        raise ValidationError('File type not allowed')
    
    # Check MIME type
    file.seek(0)
    file_content = file.read(1024)
    file.seek(0)
    
    mime_type = magic.from_buffer(file_content, mime=True)
    expected_mime_types = {
        '.pdf': 'application/pdf',
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg', 
        '.png': 'image/png',
        '.gif': 'image/gif'
    }
    
    expected_mime = expected_mime_types.get(file_extension)
    if expected_mime and mime_type != expected_mime:
        raise ValidationError('File content does not match extension')
    
    # Scan for malicious content (basic check)
    file.seek(0)
    content = file.read().decode('utf-8', errors='ignore')
    malicious_patterns = ['<script', 'javascript:', 'vbscript:', 'onload=']
    
    for pattern in malicious_patterns:
        if pattern.lower() in content.lower():
            raise ValidationError('File contains potentially malicious content')
    
    file.seek(0)
```

#### 3. SQL Injection Prevention
```python
# Always use Django ORM or parameterized queries
from django.db import connection

# Good - Using ORM
deals = Deal.objects.filter(organization=request.organization, client__email=email)

# Good - Parameterized raw query if needed
with connection.cursor() as cursor:
    cursor.execute(
        "SELECT * FROM deals_deal WHERE organization_id = %s AND deal_value > %s",
        [org_id, min_value]
    )

# Bad - String concatenation (vulnerable)
# cursor.execute(f"SELECT * FROM deals_deal WHERE email = '{email}'")
```

### API Security

#### 1. CORS Configuration
```python
# settings.py
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOWED_ORIGINS = [
    "https://yourdomain.com",
    "https://www.yourdomain.com",
    "https://app.yourdomain.com"
]

CORS_ALLOW_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
]

# Only allow specific methods
CORS_ALLOWED_METHODS = [
    'DELETE',
    'GET',
    'OPTIONS',
    'PATCH',
    'POST',
    'PUT',
]
```

#### 2. Content Security Policy
```python
# settings.py
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Custom middleware for CSP
class CSPMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        
        csp_policy = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https://res.cloudinary.com; "
            "connect-src 'self' https://api.yourdomain.com; "
            "frame-ancestors 'none';"
        )
        
        response['Content-Security-Policy'] = csp_policy
        response['X-Frame-Options'] = 'DENY'
        response['X-Content-Type-Options'] = 'nosniff'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        return response
```

#### 3. API Request Validation
```python
# permissions/decorators.py
from functools import wraps
from django.http import JsonResponse
import logging

logger = logging.getLogger('security')

def organization_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not hasattr(request, 'organization') or not request.organization:
            logger.warning(f"Unauthorized access attempt from {request.user}: No organization")
            return JsonResponse({'error': 'Organization required'}, status=403)
        return view_func(request, *args, **kwargs)
    return _wrapped_view

def permission_required(permission):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.has_perm(permission):
                logger.warning(f"Permission denied for {request.user}: {permission}")
                return JsonResponse({'error': 'Permission denied'}, status=403)
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator
```

### Audit Logging

#### 1. Security Event Logging
```python
# authentication/signals.py
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver
import logging

security_logger = logging.getLogger('security')

@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    client_ip = get_client_ip(request)
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    
    security_logger.info(
        f"User login successful - User: {user.email}, IP: {client_ip}, "
        f"User-Agent: {user_agent}, Organization: {getattr(user, 'organization', 'None')}"
    )

@receiver(user_login_failed)
def log_failed_login(sender, credentials, request, **kwargs):
    client_ip = get_client_ip(request)
    email = credentials.get('username', 'Unknown')
    
    security_logger.warning(
        f"Login failed - Email: {email}, IP: {client_ip}"
    )

@receiver(user_logged_out)
def log_user_logout(sender, request, user, **kwargs):
    client_ip = get_client_ip(request)
    
    security_logger.info(
        f"User logout - User: {user.email}, IP: {client_ip}"
    )

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip
```

#### 2. Activity Audit Trail
```python
# deals/models.py
class ActivityLog(models.Model):
    ACTION_CHOICES = [
        ('create', 'Create'),
        ('update', 'Update'),
        ('delete', 'Delete'),
        ('view', 'View'),
        ('verify', 'Verify'),
        ('approve', 'Approve'),
        ('reject', 'Reject'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.UUIDField()
    content_object = GenericForeignKey('content_type', 'object_id')
    
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    description = models.TextField()
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    
    # Store changes for audit purposes
    old_values = models.JSONField(null=True, blank=True)
    new_values = models.JSONField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'activity_logs'
        indexes = [
            models.Index(fields=['organization', 'created_at']),
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['content_type', 'object_id']),
        ]
```

---

## Management Commands

Django management commands for system administration and maintenance.

### User Management Commands

#### 1. Create Super Admin
```python
# authentication/management/commands/create_super_admin.py
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

User = get_user_model()

class Command(BaseCommand):
    help = 'Create a super admin user'

    def add_arguments(self, parser):
        parser.add_argument('--email', type=str, required=True)
        parser.add_argument('--password', type=str)
        parser.add_argument('--first-name', type=str)
        parser.add_argument('--last-name', type=str)

    def handle(self, *args, **options):
        email = options['email']
        password = options.get('password')
        
        if User.objects.filter(email=email).exists():
            self.stdout.write(
                self.style.ERROR(f'User with email {email} already exists')
            )
            return
        
        if not password:
            password = self.get_password()
        
        try:
            user = User.objects.create_superuser(
                email=email,
                password=password,
                first_name=options.get('first_name', ''),
                last_name=options.get('last_name', '')
            )
            
            self.stdout.write(
                self.style.SUCCESS(f'Super admin created successfully: {user.email}')
            )
            
        except ValidationError as e:
            self.stdout.write(
                self.style.ERROR(f'Error creating user: {e}')
            )

    def get_password(self):
        import getpass
        while True:
            password = getpass.getpass('Enter password: ')
            password2 = getpass.getpass('Confirm password: ')
            
            if password == password2:
                return password
            else:
                self.stdout.write(self.style.ERROR('Passwords do not match'))
```

**Usage:**
```bash
python manage.py create_super_admin --email admin@example.com --first-name John --last-name Doe
```

#### 2. Setup Permissions
```python
# permissions/management/commands/setup_permissions.py
from django.core.management.base import BaseCommand
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.models import Permission
from permissions.models import Role

class Command(BaseCommand):
    help = 'Setup default roles and permissions'

    def handle(self, *args, **options):
        self.create_default_permissions()
        self.create_default_roles()
        
        self.stdout.write(
            self.style.SUCCESS('Permissions and roles setup completed')
        )

    def create_default_permissions(self):
        """Create custom permissions"""
        custom_permissions = [
            ('view_all_deals', 'Can view all deals'),
            ('verify_payment', 'Can verify payments'),
            ('approve_payment', 'Can approve payments'),
            ('view_commission', 'Can view commission'),
            ('calculate_commission', 'Can calculate commission'),
            ('manage_organization', 'Can manage organization'),
            ('view_analytics', 'Can view analytics'),
            ('export_data', 'Can export data'),
        ]
        
        deal_content_type = ContentType.objects.get_for_model(Deal)
        
        for codename, name in custom_permissions:
            permission, created = Permission.objects.get_or_create(
                codename=codename,
                name=name,
                content_type=deal_content_type
            )
            
            if created:
                self.stdout.write(f'Created permission: {name}')

    def create_default_roles(self):
        """Create default roles with permissions"""
        roles_config = {
            'super_admin': {
                'name': 'Super Admin',
                'permissions': 'all'
            },
            'org_admin': {
                'name': 'Organization Admin', 
                'permissions': [
                    'view_all_deals', 'verify_payment', 'approve_payment',
                    'view_commission', 'calculate_commission', 'manage_organization',
                    'view_analytics', 'export_data'
                ]
            },
            'salesperson': {
                'name': 'Salesperson',
                'permissions': [
                    'add_deal', 'change_deal', 'view_deal',
                    'add_client', 'change_client', 'view_client',
                    'add_payment', 'view_payment', 'view_commission'
                ]
            },
            'verifier': {
                'name': 'Verifier',
                'permissions': [
                    'view_deal', 'verify_payment', 'view_payment',
                    'view_analytics'
                ]
            }
        }
        
        for role_code, config in roles_config.items():
            role, created = Role.objects.get_or_create(
                role_name=role_code,
                defaults={'display_name': config['name']}
            )
            
            if config['permissions'] == 'all':
                role.permissions.set(Permission.objects.all())
            else:
                permissions = Permission.objects.filter(
                    codename__in=config['permissions']
                )
                role.permissions.set(permissions)
            
            if created:
                self.stdout.write(f'Created role: {config["name"]}')
```

**Usage:**
```bash
python manage.py setup_permissions
```

### Data Management Commands

#### 1. Seed Demo Data
```python
# authentication/management/commands/seed_demo_data.py
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from faker import Faker
import random
from decimal import Decimal

User = get_user_model()
fake = Faker()

class Command(BaseCommand):
    help = 'Seed database with demo data'

    def add_arguments(self, parser):
        parser.add_argument('--users', type=int, default=20, help='Number of users to create')
        parser.add_argument('--clients', type=int, default=50, help='Number of clients to create')
        parser.add_argument('--deals', type=int, default=100, help='Number of deals to create')

    def handle(self, *args, **options):
        self.create_demo_organization()
        self.create_demo_users(options['users'])
        self.create_demo_clients(options['clients'])
        self.create_demo_deals(options['deals'])
        
        self.stdout.write(
            self.style.SUCCESS('Demo data created successfully')
        )

    def create_demo_organization(self):
        from organization.models import Organization
        
        self.organization, created = Organization.objects.get_or_create(
            organization_name='Demo Organization',
            defaults={
                'organization_description': 'Demo organization for testing',
                'contact_email': 'demo@example.com',
                'contact_number': '+1234567890',
                'organization_address': fake.address()
            }
        )
        
        if created:
            self.stdout.write('Created demo organization')

    def create_demo_users(self, count):
        from permissions.models import Role
        
        roles = list(Role.objects.all())
        
        for i in range(count):
            email = fake.email()
            if not User.objects.filter(email=email).exists():
                user = User.objects.create_user(
                    email=email,
                    password='demo123',
                    first_name=fake.first_name(),
                    last_name=fake.last_name(),
                    organization=self.organization,
                    role=random.choice(roles) if roles else None,
                    contact_number=fake.phone_number()[:20],
                    address=fake.address()
                )
                
                if i % 10 == 0:
                    self.stdout.write(f'Created {i + 1} demo users')

    def create_demo_clients(self, count):
        from clients.models import Client
        
        users = list(User.objects.filter(organization=self.organization))
        
        for i in range(count):
            Client.objects.create(
                organization=self.organization,
                created_by=random.choice(users),
                client_name=fake.company(),
                email=fake.email(),
                contact_number=fake.phone_number()[:20],
                nationality=fake.country_code(),
                client_satisfaction=random.randint(1, 5),
                address=fake.address()
            )
            
            if i % 20 == 0:
                self.stdout.write(f'Created {i + 1} demo clients')

    def create_demo_deals(self, count):
        from deals.models import Deal
        from clients.models import Client
        
        clients = list(Client.objects.filter(organization=self.organization))
        users = list(User.objects.filter(organization=self.organization))
        
        payment_methods = ['wallet', 'bank', 'cheque', 'cash']
        payment_statuses = ['initial payment', 'partial_payment', 'full_payment']
        source_types = ['linkedin', 'instagram', 'google', 'referral', 'others']
        
        for i in range(count):
            Deal.objects.create(
                organization=self.organization,
                client=random.choice(clients),
                created_by=random.choice(users),
                deal_name=f"Deal {fake.bs()}",
                deal_value=Decimal(random.uniform(1000, 50000)).quantize(Decimal('0.01')),
                payment_status=random.choice(payment_statuses),
                payment_method=random.choice(payment_methods),
                source_type=random.choice(source_types),
                deal_remarks=fake.text(max_nb_chars=200),
                deal_date=fake.date_between(start_date='-1y', end_date='today')
            )
            
            if i % 25 == 0:
                self.stdout.write(f'Created {i + 1} demo deals')
```

**Usage:**
```bash
python manage.py seed_demo_data --users 50 --clients 100 --deals 200
```

#### 2. Calculate Streaks
```python
# Sales_dashboard/management/commands/calculate_streaks.py
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.db.models import Count
from deals.models import Deal
from datetime import datetime, timedelta

User = get_user_model()

class Command(BaseCommand):
    help = 'Calculate and update sales streaks for all users'

    def handle(self, *args, **options):
        users = User.objects.filter(role__role_name='salesperson')
        
        for user in users:
            streak = self.calculate_user_streak(user)
            
            # Update user profile with streak
            if hasattr(user, 'userprofile'):
                user.userprofile.current_streak = streak
                user.userprofile.save()
            
            self.stdout.write(f'Updated streak for {user.email}: {streak} days')
        
        self.stdout.write(
            self.style.SUCCESS(f'Updated streaks for {users.count()} users')
        )

    def calculate_user_streak(self, user):
        """Calculate consecutive days with verified deals"""
        today = datetime.now().date()
        current_date = today
        streak_days = 0
        
        while True:
            deals_count = Deal.objects.filter(
                created_by=user,
                verification_status='verified',
                deal_date=current_date
            ).count()
            
            if deals_count > 0:
                streak_days += 1
                current_date -= timedelta(days=1)
            else:
                break
            
            # Limit to reasonable timeframe
            if streak_days > 365:
                break
        
        return streak_days
```

**Usage:**
```bash
python manage.py calculate_streaks
```

### Database Management Commands

#### 1. Reset Database for Deployment
```python
# authentication/management/commands/reset_db_for_deployment.py
from django.core.management.base import BaseCommand
from django.core.management import call_command
from django.contrib.auth import get_user_model
import os

User = get_user_model()

class Command(BaseCommand):
    help = 'Reset database for deployment (DANGEROUS - USE WITH CAUTION)'

    def add_arguments(self, parser):
        parser.add_argument(
            '--confirm',
            action='store_true',
            help='Confirm that you want to reset the database'
        )

    def handle(self, *args, **options):
        if not options['confirm']:
            self.stdout.write(
                self.style.ERROR(
                    'This command will delete all data. '
                    'Use --confirm to proceed.'
                )
            )
            return
        
        if not self.confirm_action():
            self.stdout.write(self.style.ERROR('Operation cancelled'))
            return
        
        self.stdout.write(self.style.WARNING('Resetting database...'))
        
        # Delete migration files (except __init__.py)
        self.delete_migrations()
        
        # Reset database
        call_command('flush', '--noinput')
        
        # Recreate migrations
        call_command('makemigrations')
        
        # Apply migrations
        call_command('migrate')
        
        # Setup permissions
        call_command('setup_permissions')
        
        # Create default superuser if email provided
        admin_email = os.getenv('ADMIN_EMAIL')
        admin_password = os.getenv('ADMIN_PASSWORD')
        
        if admin_email and admin_password:
            User.objects.create_superuser(
                email=admin_email,
                password=admin_password,
                first_name='Admin',
                last_name='User'
            )
            self.stdout.write(f'Created superuser: {admin_email}')
        
        self.stdout.write(
            self.style.SUCCESS('Database reset completed successfully')
        )

    def confirm_action(self):
        response = input(
            'Are you sure you want to reset the database? '
            'This will delete all data. Type "yes" to confirm: '
        )
        return response.lower() == 'yes'

    def delete_migrations(self):
        """Delete migration files except __init__.py"""
        apps = [
            'authentication', 'organization', 'permissions',
            'clients', 'deals', 'commission', 'team', 'project',
            'notifications', 'Sales_dashboard', 'Verifier_dashboard'
        ]
        
        for app in apps:
            migrations_dir = f'{app}/migrations'
            if os.path.exists(migrations_dir):
                for filename in os.listdir(migrations_dir):
                    if filename.endswith('.py') and filename != '__init__.py':
                        file_path = os.path.join(migrations_dir, filename)
                        os.remove(file_path)
                        self.stdout.write(f'Deleted {file_path}')
```

**Usage:**
```bash
python manage.py reset_db_for_deployment --confirm
```

#### 2. Cleanup Permissions
```python
# permissions/management/commands/cleanup_permissions.py
from django.core.management.base import BaseCommand
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType

class Command(BaseCommand):
    help = 'Clean up orphaned permissions and fix permission issues'

    def handle(self, *args, **options):
        self.remove_orphaned_permissions()
        self.fix_duplicate_permissions()
        self.verify_role_permissions()
        
        self.stdout.write(
            self.style.SUCCESS('Permission cleanup completed')
        )

    def remove_orphaned_permissions(self):
        """Remove permissions for non-existent content types"""
        orphaned_count = 0
        
        for permission in Permission.objects.all():
            try:
                # Try to access the content type
                _ = permission.content_type.model_class()
            except:
                permission.delete()
                orphaned_count += 1
        
        if orphaned_count > 0:
            self.stdout.write(f'Removed {orphaned_count} orphaned permissions')

    def fix_duplicate_permissions(self):
        """Remove duplicate permissions"""
        seen_permissions = set()
        duplicates = []
        
        for permission in Permission.objects.all():
            key = (permission.content_type_id, permission.codename)
            if key in seen_permissions:
                duplicates.append(permission.id)
            else:
                seen_permissions.add(key)
        
        if duplicates:
            Permission.objects.filter(id__in=duplicates).delete()
            self.stdout.write(f'Removed {len(duplicates)} duplicate permissions')

    def verify_role_permissions(self):
        """Verify that all roles have valid permissions"""
        from permissions.models import Role
        
        for role in Role.objects.all():
            invalid_perms = []
            
            for permission in role.permissions.all():
                try:
                    # Verify permission is valid
                    _ = permission.content_type.model_class()
                except:
                    invalid_perms.append(permission)
            
            if invalid_perms:
                role.permissions.remove(*invalid_perms)
                self.stdout.write(
                    f'Removed {len(invalid_perms)} invalid permissions from role {role.display_name}'
                )
```

**Usage:**
```bash
python manage.py cleanup_permissions
```

### Maintenance Commands

#### 1. Health Check
```python
# core_config/management/commands/health_check.py
from django.core.management.base import BaseCommand
from django.db import connection
from django.core.cache import cache
import redis
import os

class Command(BaseCommand):
    help = 'Perform system health check'

    def handle(self, *args, **options):
        self.check_database()
        self.check_cache()
        self.check_media_storage()
        self.check_environment()
        
        self.stdout.write(
            self.style.SUCCESS('Health check completed')
        )

    def check_database(self):
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                result = cursor.fetchone()
                
            if result[0] == 1:
                self.stdout.write(
                    self.style.SUCCESS('✓ Database connection: OK')
                )
            else:
                self.stdout.write(
                    self.style.ERROR('✗ Database connection: FAILED')
                )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'✗ Database connection: ERROR - {e}')
            )

    def check_cache(self):
        try:
            cache.set('health_check', 'ok', 10)
            result = cache.get('health_check')
            
            if result == 'ok':
                self.stdout.write(
                    self.style.SUCCESS('✓ Cache (Redis): OK')
                )
            else:
                self.stdout.write(
                    self.style.ERROR('✗ Cache (Redis): FAILED')
                )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'✗ Cache (Redis): ERROR - {e}')
            )

    def check_media_storage(self):
        from django.conf import settings
        
        if hasattr(settings, 'CLOUDINARY_CLOUD_NAME'):
            try:
                import cloudinary
                # Basic cloudinary connectivity test
                self.stdout.write(
                    self.style.SUCCESS('✓ Media storage (Cloudinary): Configured')
                )
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'✗ Media storage: ERROR - {e}')
                )
        else:
            media_root = getattr(settings, 'MEDIA_ROOT', '')
            if os.path.exists(media_root) and os.access(media_root, os.W_OK):
                self.stdout.write(
                    self.style.SUCCESS('✓ Media storage (Local): OK')
                )
            else:
                self.stdout.write(
                    self.style.WARNING('⚠ Media storage (Local): Check permissions')
                )

    def check_environment(self):
        required_vars = [
            'SECRET_KEY', 'DATABASE_URL', 'REDIS_URL'
        ]
        
        missing_vars = []
        for var in required_vars:
            if not os.getenv(var):
                missing_vars.append(var)
        
        if missing_vars:
            self.stdout.write(
                self.style.ERROR(
                    f'✗ Environment variables missing: {", ".join(missing_vars)}'
                )
            )
        else:
            self.stdout.write(
                self.style.SUCCESS('✓ Environment variables: OK')
            )
```

**Usage:**
```bash
python manage.py health_check
```

---

## Testing

### Test Structure

```
backend/
├── tests/
│   ├── __init__.py
│   ├── test_authentication.py
│   ├── test_clients.py
│   ├── test_deals.py
│   ├── test_permissions.py
│   └── test_api_endpoints.py
├── authentication/
│   └── tests/
│       ├── test_models.py
│       ├── test_views.py
│       └── test_permissions.py
└── deals/
    └── tests/
        ├── test_models.py
        ├── test_views.py
        └── test_validators.py
```

### Test Configuration

#### 1. Test Settings
```python
# backend/core_config/test_settings.py
from .settings import *

# Use SQLite for faster tests
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}

# Disable migrations for faster tests
class DisableMigrations:
    def __contains__(self, item):
        return True
    
    def __getitem__(self, item):
        return None

MIGRATION_MODULES = DisableMigrations()

# Use dummy cache
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.dummy.DummyCache',
    }
}

# Disable logging during tests
LOGGING_CONFIG = None

# Use test email backend
EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'

# Disable Cloudinary for tests
DEFAULT_FILE_STORAGE = 'django.core.files.storage.FileSystemStorage'

# Speed up password hashing
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.MD5PasswordHasher',
]
```

### Model Tests

#### 1. User Model Tests
```python
# authentication/tests/test_models.py
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from organization.models import Organization
from permissions.models import Role

User = get_user_model()

class UserModelTest(TestCase):
    def setUp(self):
        self.organization = Organization.objects.create(
            organization_name="Test Org",
            contact_email="test@org.com"
        )
        
        self.role = Role.objects.create(
            role_name="test_role",
            display_name="Test Role"
        )

    def test_create_user_with_email(self):
        """Test creating a user with email"""
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User',
            organization=self.organization,
            role=self.role
        )
        
        self.assertEqual(user.email, 'test@example.com')
        self.assertEqual(user.first_name, 'Test')
        self.assertEqual(user.organization, self.organization)
        self.assertTrue(user.check_password('testpass123'))
        self.assertTrue(user.is_active)
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)

    def test_create_superuser(self):
        """Test creating a superuser"""
        user = User.objects.create_superuser(
            email='admin@example.com',
            password='adminpass123'
        )
        
        self.assertEqual(user.email, 'admin@example.com')
        self.assertTrue(user.is_active)
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)

    def test_create_user_without_email_raises_error(self):
        """Test creating user without email raises ValueError"""
        with self.assertRaises(ValueError):
            User.objects.create_user(
                email='',
                password='testpass123'
            )

    def test_email_normalization(self):
        """Test email is normalized"""
        user = User.objects.create_user(
            email='Test@EXAMPLE.COM',
            password='testpass123'
        )
        
        self.assertEqual(user.email, 'Test@example.com')

    def test_user_string_representation(self):
        """Test string representation of user"""
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
        
        self.assertEqual(str(user), 'Test User')
```

#### 2. Deal Model Tests
```python
# deals/tests/test_models.py
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from decimal import Decimal
from deals.models import Deal
from clients.models import Client
from organization.models import Organization

User = get_user_model()

class DealModelTest(TestCase):
    def setUp(self):
        self.organization = Organization.objects.create(
            organization_name="Test Org"
        )
        
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            organization=self.organization
        )
        
        self.client = Client.objects.create(
            organization=self.organization,
            created_by=self.user,
            client_name="Test Client",
            email="client@test.com"
        )

    def test_create_deal(self):
        """Test creating a deal"""
        deal = Deal.objects.create(
            organization=self.organization,
            client=self.client,
            created_by=self.user,
            deal_name="Test Deal",
            deal_value=Decimal('1000.00'),
            payment_status='initial payment',
            payment_method='bank',
            source_type='linkedin'
        )
        
        self.assertEqual(deal.deal_name, "Test Deal")
        self.assertEqual(deal.deal_value, Decimal('1000.00'))
        self.assertEqual(deal.verification_status, 'pending')
        self.assertEqual(deal.payment_count, 0)
        self.assertTrue(deal.deal_id)  # Auto-generated

    def test_deal_string_representation(self):
        """Test string representation of deal"""
        deal = Deal.objects.create(
            organization=self.organization,
            client=self.client,
            created_by=self.user,
            deal_name="Test Deal",
            deal_value=Decimal('1000.00'),
            payment_status='initial payment',
            payment_method='bank',
            source_type='linkedin'
        )
        
        expected_str = f"{deal.deal_id} - {self.client.client_name}"
        self.assertEqual(str(deal), expected_str)

    def test_deal_value_validation(self):
        """Test deal value must be positive"""
        with self.assertRaises(ValidationError):
            deal = Deal(
                organization=self.organization,
                client=self.client,
                created_by=self.user,
                deal_name="Invalid Deal",
                deal_value=Decimal('-1000.00'),
                payment_status='initial payment',
                payment_method='bank',
                source_type='linkedin'
            )
            deal.full_clean()
```

### API Tests

#### 1. Authentication API Tests
```python
# tests/test_authentication_api.py
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from django.contrib.auth import get_user_model
from organization.models import Organization

User = get_user_model()

class AuthenticationAPITest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.organization = Organization.objects.create(
            organization_name="Test Org"
        )
        
        self.user_data = {
            'email': 'test@example.com',
            'password': 'testpass123',
            'first_name': 'Test',
            'last_name': 'User'
        }

    def test_register_user(self):
        """Test user registration"""
        url = reverse('authentication:register')
        response = self.client.post(url, self.user_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(User.objects.filter(email='test@example.com').exists())
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_login_user(self):
        """Test user login"""
        # Create user first
        User.objects.create_user(**self.user_data, organization=self.organization)
        
        login_data = {
            'email': 'test@example.com',
            'password': 'testpass123'
        }
        
        url = reverse('authentication:login')
        response = self.client.post(url, login_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)
        self.assertIn('user', response.data)

    def test_login_invalid_credentials(self):
        """Test login with invalid credentials"""
        login_data = {
            'email': 'test@example.com',
            'password': 'wrongpassword'
        }
        
        url = reverse('authentication:login')
        response = self.client.post(url, login_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_user_profile(self):
        """Test retrieving user profile"""
        user = User.objects.create_user(**self.user_data, organization=self.organization)
        self.client.force_authenticate(user=user)
        
        url = reverse('authentication:profile')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], user.email)
        self.assertEqual(response.data['first_name'], user.first_name)
```

#### 2. Deals API Tests
```python
# tests/test_deals_api.py
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from django.contrib.auth import get_user_model
from decimal import Decimal
from organization.models import Organization
from clients.models import Client
from deals.models import Deal

User = get_user_model()

class DealsAPITest(TestCase):
    def setUp(self):
        self.client = APIClient()
        
        self.organization = Organization.objects.create(
            organization_name="Test Org"
        )
        
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            organization=self.organization
        )
        
        self.test_client = Client.objects.create(
            organization=self.organization,
            created_by=self.user,
            client_name="Test Client",
            email="client@test.com"
        )
        
        self.client.force_authenticate(user=self.user)

    def test_create_deal(self):
        """Test creating a new deal"""
        deal_data = {
            'client': str(self.test_client.id),
            'deal_name': 'Test Deal',
            'deal_value': '1000.00',
            'payment_status': 'initial payment',
            'payment_method': 'bank',
            'source_type': 'linkedin',
            'deal_remarks': 'Test deal creation'
        }
        
        url = reverse('api:deals-list')
        response = self.client.post(url, deal_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Deal.objects.count(), 1)
        
        deal = Deal.objects.first()
        self.assertEqual(deal.deal_name, 'Test Deal')
        self.assertEqual(deal.created_by, self.user)
        self.assertEqual(deal.organization, self.organization)

    def test_list_deals(self):
        """Test listing deals"""
        Deal.objects.create(
            organization=self.organization,
            client=self.test_client,
            created_by=self.user,
            deal_name="Deal 1",
            deal_value=Decimal('1000.00'),
            payment_status='initial payment',
            payment_method='bank',
            source_type='linkedin'
        )
        
        Deal.objects.create(
            organization=self.organization,
            client=self.test_client,
            created_by=self.user,
            deal_name="Deal 2",
            deal_value=Decimal('2000.00'),
            payment_status='full_payment',
            payment_method='cash',
            source_type='referral'
        )
        
        url = reverse('api:deals-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 2)

    def test_filter_deals_by_client(self):
        """Test filtering deals by client"""
        other_client = Client.objects.create(
            organization=self.organization,
            created_by=self.user,
            client_name="Other Client",
            email="other@test.com"
        )
        
        Deal.objects.create(
            organization=self.organization,
            client=self.test_client,
            created_by=self.user,
            deal_name="Deal 1",
            deal_value=Decimal('1000.00'),
            payment_status='initial payment',
            payment_method='bank',
            source_type='linkedin'
        )
        
        Deal.objects.create(
            organization=self.organization,
            client=other_client,
            created_by=self.user,
            deal_name="Deal 2",
            deal_value=Decimal('2000.00'),
            payment_status='initial payment',
            payment_method='bank',
            source_type='linkedin'
        )
        
        url = reverse('api:deals-list')
        response = self.client.get(url, {'client': str(self.test_client.id)})
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['deal_name'], 'Deal 1')

    def test_unauthorized_access(self):
        """Test unauthorized access to deals"""
        self.client.force_authenticate(user=None)
        
        url = reverse('api:deals-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
```

### Integration Tests

#### 1. Full Workflow Test
```python
# tests/test_deal_workflow.py
from django.test import TestCase, TransactionTestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from decimal import Decimal
from organization.models import Organization
from clients.models import Client
from deals.models import Deal, Payment

User = get_user_model()

class DealWorkflowIntegrationTest(TransactionTestCase):
    def setUp(self):
        self.client = APIClient()
        
        # Create organization
        self.organization = Organization.objects.create(
            organization_name="Test Org"
        )
        
        # Create users with different roles
        self.salesperson = User.objects.create_user(
            email='sales@example.com',
            password='testpass123',
            organization=self.organization,
            first_name='Sales',
            last_name='Person'
        )
        
        self.verifier = User.objects.create_user(
            email='verifier@example.com',
            password='testpass123',
            organization=self.organization,
            first_name='Ver',
            last_name='Ifier'
        )
        
        # Create client
        self.test_client = Client.objects.create(
            organization=self.organization,
            created_by=self.salesperson,
            client_name="Test Client",
            email="client@test.com"
        )

    def test_complete_deal_workflow(self):
        """Test complete deal workflow from creation to verification"""
        
        # 1. Salesperson creates a deal
        self.client.force_authenticate(user=self.salesperson)
        
        deal_data = {
            'client': str(self.test_client.id),
            'deal_name': 'Complete Workflow Deal',
            'deal_value': '5000.00',
            'payment_status': 'initial payment',
            'payment_method': 'bank',
            'source_type': 'linkedin',
            'deal_remarks': 'Test complete workflow'
        }
        
        url = reverse('api:deals-list')
        response = self.client.post(url, deal_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        deal_id = response.data['id']
        
        # 2. Salesperson adds payment with receipt
        receipt_file = SimpleUploadedFile(
            "receipt.jpg",
            b"fake receipt content",
            content_type="image/jpeg"
        )
        
        payment_data = {
            'payment_amount': '2500.00',
            'payment_method': 'bank',
            'payment_date': '2024-01-15',
            'payment_receipt': receipt_file,
            'payment_remarks': 'First payment'
        }
        
        url = reverse('api:deals-payments-list', kwargs={'deal_pk': deal_id})
        response = self.client.post(url, payment_data, format='multipart')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        payment_id = response.data['id']
        
        # 3. Verify deal is in pending status
        deal = Deal.objects.get(id=deal_id)
        self.assertEqual(deal.verification_status, 'pending')
        
        payment = Payment.objects.get(id=payment_id)
        self.assertEqual(payment.verification_status, 'pending')
        
        # 4. Verifier verifies the payment
        self.client.force_authenticate(user=self.verifier)
        
        verify_data = {
            'verification_status': 'verified',
            'verifier_remarks': 'Payment verified successfully'
        }
        
        url = reverse('api:payments-verify', kwargs={'pk': payment_id})
        response = self.client.patch(url, verify_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # 5. Check final status
        payment.refresh_from_db()
        self.assertEqual(payment.verification_status, 'verified')
        self.assertEqual(payment.verified_by, self.verifier)
        self.assertIsNotNone(payment.verified_at)
        
        # 6. Check commission calculation (if implemented)
        # This would test the commission calculation logic
        
        # 7. Check notification sent (if implemented)
        # This would test the notification system

    def test_deal_rejection_workflow(self):
        """Test deal rejection workflow"""
        
        # Create deal and payment
        self.client.force_authenticate(user=self.salesperson)
        
        deal = Deal.objects.create(
            organization=self.organization,
            client=self.test_client,
            created_by=self.salesperson,
            deal_name="Rejection Test Deal",
            deal_value=Decimal('3000.00'),
            payment_status='initial payment',
            payment_method='cash',
            source_type='referral'
        )
        
        payment = Payment.objects.create(
            deal=deal,
            payment_amount=Decimal('1500.00'),
            payment_method='cash',
            payment_date='2024-01-15',
            payment_remarks='Cash payment'
        )
        
        # Verifier rejects the payment
        self.client.force_authenticate(user=self.verifier)
        
        reject_data = {
            'verification_status': 'rejected',
            'verifier_remarks': 'Invalid receipt provided'
        }
        
        url = reverse('api:payments-verify', kwargs={'pk': payment.id})
        response = self.client.patch(url, reject_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Check rejection status
        payment.refresh_from_db()
        self.assertEqual(payment.verification_status, 'rejected')
        self.assertEqual(payment.verified_by, self.verifier)
```

### Test Running

#### 1. Run All Tests
```bash
# Run all tests
python manage.py test

# Run specific test file
python manage.py test tests.test_authentication_api

# Run specific test class
python manage.py test tests.test_authentication_api.AuthenticationAPITest

# Run specific test method
python manage.py test tests.test_authentication_api.AuthenticationAPITest.test_login_user
```

#### 2. Coverage Report
```bash
# Install coverage
pip install coverage

# Run tests with coverage
coverage run --source='.' manage.py test

# Generate coverage report
coverage report

# Generate HTML coverage report
coverage html
```

#### 3. Test Configuration in pytest
```python
# pytest.ini
[tool:pytest]
DJANGO_SETTINGS_MODULE = core_config.test_settings
python_files = tests.py test_*.py *_tests.py
addopts = --verbose --tb=short --strict-markers
markers =
    slow: marks tests as slow (deselect with '-m "not slow"')
    integration: marks tests as integration tests
    unit: marks tests as unit tests
```

```bash
# Run with pytest
pip install pytest-django
pytest

# Run specific markers
pytest -m unit
pytest -m "not slow"

# Run with coverage
pytest --cov=. --cov-report=html
```

---

## Troubleshooting

### Common Issues and Solutions

#### 1. Database Connection Issues

**Issue:** `django.db.utils.OperationalError: could not connect to server`

**Solutions:**
```bash
# Check PostgreSQL service status
sudo systemctl status postgresql

# Start PostgreSQL if stopped
sudo systemctl start postgresql

# Check database configuration
psql -h localhost -U username -d database_name

# Verify DATABASE_URL environment variable
echo $DATABASE_URL
```

**Django Settings Check:**
```python
# In Django shell
python manage.py shell

from django.conf import settings
print(settings.DATABASES)

# Test connection
from django.db import connection
with connection.cursor() as cursor:
    cursor.execute("SELECT 1")
    print(cursor.fetchone())
```

#### 2. Redis Connection Issues

**Issue:** `redis.exceptions.ConnectionError: Error 111 connecting to localhost:6379`

**Solutions:**
```bash
# Check Redis service
sudo systemctl status redis-server

# Start Redis
sudo systemctl start redis-server

# Test Redis connection
redis-cli ping

# Check Redis configuration
cat /etc/redis/redis.conf | grep -E "(bind|port|requirepass)"
```

**Django Cache Check:**
```python
from django.core.cache import cache
cache.set('test_key', 'test_value', 30)
print(cache.get('test_key'))
```

#### 3. Migration Issues

**Issue:** `django.db.migrations.exceptions.InconsistentMigrationHistory`

**Solutions:**
```bash
# Check migration status
python manage.py showmigrations

# Reset specific app migrations (CAUTION: Data loss)
python manage.py migrate app_name zero
python manage.py makemigrations app_name
python manage.py migrate app_name

# Fake apply migrations if already applied manually
python manage.py migrate --fake app_name migration_number

# Nuclear option: Reset all migrations (CAUTION: Complete data loss)
python manage.py reset_db_for_deployment --confirm
```

**Manual Migration Fix:**
```python
# Create custom migration to fix conflicts
from django.db import migrations

class Migration(migrations.Migration):
    dependencies = [
        ('app_name', 'previous_migration'),
    ]

    operations = [
        # Add your custom operations here
    ]
```

#### 4. Permission Denied Issues

**Issue:** `PermissionError: [Errno 13] Permission denied`

**Solutions:**
```bash
# Check file permissions
ls -la /path/to/file

# Fix ownership
sudo chown -R www-data:www-data /var/www/backend-prs/

# Fix permissions for media files
sudo chmod -R 755 /var/www/backend-prs/media/
sudo chmod -R 755 /var/www/backend-prs/staticfiles/

# Check Django user permissions
python manage.py shell
from django.contrib.auth import get_user_model
User = get_user_model()
user = User.objects.get(email='test@example.com')
print(user.get_all_permissions())
```

#### 5. Static Files Not Loading

**Issue:** Static files returning 404 in production

**Solutions:**
```bash
# Collect static files
python manage.py collectstatic --noinput

# Check static files configuration
python manage.py findstatic admin/css/base.css

# Verify nginx configuration
sudo nginx -t
sudo systemctl reload nginx
```

**Django Settings Check:**
```python
# settings.py
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static'),
]

# For WhiteNoise
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',  # Add this
    # ... other middleware
]
```

#### 6. CORS Issues

**Issue:** `Access to XMLHttpRequest has been blocked by CORS policy`

**Solutions:**
```python
# settings.py - Update CORS configuration
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",  # React dev server
    "https://yourdomain.com",
    "https://www.yourdomain.com",
]

# For development only (NOT for production)
CORS_ALLOW_ALL_ORIGINS = True  # DANGEROUS in production

# Check preflight requests
CORS_ALLOW_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
]
```

#### 7. JWT Token Issues

**Issue:** `Token is invalid or expired`

**Solutions:**
```python
# Check token configuration
from rest_framework_simplejwt.settings import api_settings
print(api_settings.ACCESS_TOKEN_LIFETIME)
print(api_settings.REFRESH_TOKEN_LIFETIME)

# Decode token for debugging
import jwt
from django.conf import settings

try:
    decoded = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
    print(decoded)
except jwt.ExpiredSignatureError:
    print("Token has expired")
except jwt.InvalidTokenError:
    print("Token is invalid")
```

**Token Refresh Implementation:**
```javascript
// Frontend token refresh logic
const refreshToken = async () => {
    const refresh = localStorage.getItem('refresh_token');
    
    try {
        const response = await fetch('/api/auth/token/refresh/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ refresh }),
        });
        
        if (response.ok) {
            const data = await response.json();
            localStorage.setItem('access_token', data.access);
            return data.access;
        }
    } catch (error) {
        console.error('Token refresh failed:', error);
        // Redirect to login
    }
};
```

#### 8. File Upload Issues

**Issue:** `413 Request Entity Too Large` or upload failures

**Solutions:**
```python
# Django settings
FILE_UPLOAD_MAX_MEMORY_SIZE = 10 * 1024 * 1024  # 10MB
DATA_UPLOAD_MAX_MEMORY_SIZE = 10 * 1024 * 1024  # 10MB

# Check file validator
from deals.validators import validate_file_security

def test_file_upload():
    # Test with a sample file
    pass
```

**Nginx Configuration:**
```nginx
server {
    # Increase client max body size
    client_max_body_size 100M;
    
    location / {
        proxy_pass http://backend;
        proxy_request_buffering off;  # For large file uploads
    }
}
```

#### 9. Memory Issues

**Issue:** `MemoryError` or high memory usage

**Solutions:**
```python
# Optimize database queries
from django.db import connection
from django.conf import settings

# Enable query logging in development
if settings.DEBUG:
    LOGGING = {
        'version': 1,
        'disable_existing_loggers': False,
        'handlers': {
            'console': {
                'level': 'DEBUG',
                'class': 'logging.StreamHandler',
            },
        },
        'loggers': {
            'django.db.backends': {
                'level': 'DEBUG',
                'handlers': ['console'],
            },
        },
    }

# Use select_related and prefetch_related
deals = Deal.objects.select_related('client', 'created_by').prefetch_related('payments')

# Use iterator for large querysets
for deal in Deal.objects.iterator(chunk_size=100):
    process_deal(deal)
```

**System Monitoring:**
```bash
# Monitor memory usage
free -m
htop

# Monitor Django processes
ps aux | grep python

# Check for memory leaks
pip install memory-profiler
python -m memory_profiler manage.py runserver
```

#### 10. Environment Variable Issues

**Issue:** Environment variables not loading or incorrect values

**Solutions:**
```bash
# Check environment variables
printenv | grep -E "(SECRET_KEY|DATABASE_URL|REDIS_URL)"

# Load .env file manually for testing
export $(cat .env | xargs)

# Check Django settings
python manage.py diffsettings
```

**Debug Environment Loading:**
```python
# In settings.py
import os
from dotenv import load_dotenv

# Debug environment loading
load_dotenv()
print(f"SECRET_KEY loaded: {bool(os.getenv('SECRET_KEY'))}")
print(f"DATABASE_URL loaded: {bool(os.getenv('DATABASE_URL'))}")

# Check for environment-specific files
env_file = f".env.{os.getenv('DJANGO_ENV', 'development')}"
if os.path.exists(env_file):
    load_dotenv(env_file, override=True)
    print(f"Loaded {env_file}")
```

### Debugging Tools

#### 1. Django Debug Toolbar
```python
# Install debug toolbar
pip install django-debug-toolbar

# settings.py
INSTALLED_APPS = [
    # ... other apps
    'debug_toolbar',
]

MIDDLEWARE = [
    # ... other middleware
    'debug_toolbar.middleware.DebugToolbarMiddleware',
]

# Show toolbar for internal IPs
INTERNAL_IPS = [
    '127.0.0.1',
    'localhost',
]

# urls.py
if settings.DEBUG:
    import debug_toolbar
    urlpatterns = [
        path('__debug__/', include(debug_toolbar.urls)),
    ] + urlpatterns
```

#### 2. Django Extensions
```python
# Install extensions
pip install django-extensions

# settings.py
INSTALLED_APPS = [
    # ... other apps
    'django_extensions',
]
```

**Useful Commands:**
```bash
# Enhanced shell with IPython
python manage.py shell_plus

# Show all URLs
python manage.py show_urls

# Generate model graphs
python manage.py graph_models -a -o models.png

# Check for issues
python manage.py check --deploy
```

#### 3. Logging Configuration
```python
# settings.py
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': 'logs/django.log',
            'formatter': 'verbose',
        },
        'security': {
            'level': 'WARNING',
            'class': 'logging.FileHandler',
            'filename': 'logs/security.log',
            'formatter': 'verbose',
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
        },
        'security': {
            'handlers': ['security'],
            'level': 'WARNING',
            'propagate': False,
        },
        'deals': {
            'handlers': ['file', 'console'],
            'level': 'DEBUG',
        },
    },
}
```

#### 4. Performance Monitoring
```python
# Install performance monitoring tools
pip install django-silk

# settings.py
MIDDLEWARE = [
    'silk.middleware.SilkyMiddleware',
    # ... other middleware
]

INSTALLED_APPS = [
    'silk',
    # ... other apps
]

# urls.py
urlpatterns += [path('silk/', include('silk.urls', namespace='silk'))]
```

### Performance Optimization

#### 1. Database Query Optimization
```python
# Use select_related for foreign keys
deals = Deal.objects.select_related('client', 'organization', 'created_by')

# Use prefetch_related for reverse foreign keys and many-to-many
deals = Deal.objects.prefetch_related('payments', 'activity_logs')

# Use only() to limit fields
deals = Deal.objects.only('deal_name', 'deal_value', 'client__client_name')

# Use values() for raw data
deal_data = Deal.objects.values('deal_name', 'deal_value', 'client__client_name')

# Use raw SQL for complex queries
deals = Deal.objects.raw(
    "SELECT * FROM deals_deal WHERE deal_value > %s",
    [1000]
)
```

#### 2. Caching Strategy
```python
# View-level caching
from django.views.decorators.cache import cache_page

@cache_page(60 * 15)  # Cache for 15 minutes
def dashboard_view(request):
    return render(request, 'dashboard.html', context)

# Template fragment caching
{% load cache %}
{% cache 500 sidebar %}
    <!-- Expensive sidebar content -->
{% endcache %}

# Low-level caching
from django.core.cache import cache

def get_user_deals(user_id):
    cache_key = f'user_deals_{user_id}'
    deals = cache.get(cache_key)
    
    if deals is None:
        deals = Deal.objects.filter(created_by_id=user_id).select_related('client')
        cache.set(cache_key, deals, 60 * 30)  # Cache for 30 minutes
    
    return deals
```

This concludes the comprehensive documentation for Backend_PRS. The system provides a robust, secure, and scalable solution for payment receiving system management with multi-tenant architecture, role-based access control, and comprehensive API endpoints.