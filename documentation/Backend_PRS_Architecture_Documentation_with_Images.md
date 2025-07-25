# Backend_PRS - System Architecture Documentation with Visual Diagrams

## Table of Contents
1. [System Overview](#system-overview)
2. [Technology Stack](#technology-stack)
3. [Overall Architecture](#overall-architecture)
4. [Application Architecture](#application-architecture)
5. [Database Architecture](#database-architecture)
6. [API Architecture](#api-architecture)
7. [Security Architecture](#security-architecture)
8. [Real-time Features](#real-time-features)
9. [Data Flow Diagrams](#data-flow-diagrams)
10. [Sequence Diagrams](#sequence-diagrams)
11. [Component Relationships](#component-relationships)
12. [Deployment Architecture](#deployment-architecture)
13. [Performance & Scalability](#performance--scalability)
14. [Diagram Generation Instructions](#diagram-generation-instructions)

---

## System Overview

Backend_PRS is a comprehensive **Multi-Tenant SaaS Platform** designed for Personal Revenue System management. It implements a sophisticated architecture supporting multiple organizations with complete data isolation, real-time notifications, payment processing, and advanced analytics.

### Key Features
- **Multi-tenant Architecture** with organization-based data isolation
- **Role-based Access Control** (RBAC) system
- **Real-time Notifications** via WebSocket
- **Payment Processing** with verification workflows
- **Sales Analytics** and performance tracking
- **Commission Management** with automatic calculations
- **Audit Logging** and compliance tracking

---

## Technology Stack

### Backend Framework
```
Django 5.2.2                    # Main web framework
Django REST Framework 3.15.2    # API framework
Django Channels 4.0.0           # WebSocket/async support
Daphne 4.0.0                    # ASGI server
```

### Database & Storage
```
PostgreSQL                      # Primary production database
SQLite                          # Development fallback
Redis                           # Caching, sessions, WebSocket layer
Cloudinary                      # Media storage and CDN
```

### Security & Authentication
```
JWT Token Authentication        # API authentication
Multi-factor Authentication     # Admin security
Role-based Access Control       # Permission system
Organization-based Multi-tenancy # Data isolation
```

### Deployment & Infrastructure
```
Render.com                      # Primary deployment platform
Gunicorn/Daphne                 # Production ASGI server
WhiteNoise                      # Static file serving
Docker                          # Containerization support
```

---

## Overall Architecture

### High-Level System Architecture

![High-Level System Architecture](diagrams/high-level-architecture.png)

**To generate this diagram, use the following Mermaid code:**

```mermaid
graph TB
    subgraph "Frontend Layer"
        WEB[Web Application]
        MOBILE[Mobile App]
        API_CLIENT[API Clients]
    end

    subgraph "Load Balancer/CDN"
        CDN[Cloudinary CDN]
        LB[Load Balancer]
    end

    subgraph "Backend Services"
        DJANGO[Django Application]
        DAPHNE[Daphne ASGI Server]
        GUNICORN[Gunicorn WSGI Server]
    end

    subgraph "Data Layer"
        POSTGRES[(PostgreSQL)]
        REDIS[(Redis Cache)]
        CLOUDINARY[Cloudinary Storage]
    end

    subgraph "External Services"
        EMAIL[Email Service]
        SMS[SMS Service]
        PAYMENT[Payment Gateway]
    end

    WEB --> LB
    MOBILE --> LB
    API_CLIENT --> LB
    
    LB --> DJANGO
    LB --> DAPHNE
    
    DJANGO --> GUNICORN
    DAPHNE --> DJANGO
    
    DJANGO --> POSTGRES
    DJANGO --> REDIS
    DJANGO --> CLOUDINARY
    
    CDN --> CLOUDINARY
    
    DJANGO --> EMAIL
    DJANGO --> SMS
    DJANGO --> PAYMENT
```

### Multi-Tenant Architecture Pattern

![Multi-Tenant Architecture](diagrams/multi-tenant-architecture.png)

**To generate this diagram, use the following Mermaid code:**

```mermaid
graph TB
    subgraph "Shared Infrastructure"
        APP[Django Application]
        DB[(Shared Database)]
        CACHE[(Shared Cache)]
    end

    subgraph "Organization A"
        UA[Users A]
        TA[Teams A]
        CA[Clients A]
        DA[Deals A]
    end

    subgraph "Organization B"
        UB[Users B]
        TB[Teams B]
        CB[Clients B]
        DB_ORG[Deals B]
    end

    subgraph "Organization C"
        UC[Users C]
        TC[Teams C]
        CC[Clients C]
        DC[Deals C]
    end

    APP --> DB
    APP --> CACHE
    
    DB --> UA
    DB --> TA
    DB --> CA
    DB --> DA
    
    DB --> UB
    DB --> TB
    DB --> CB
    DB --> DB_ORG
    
    DB --> UC
    DB --> TC
    DB --> CC
    DB --> DC
```

---

## Application Architecture

### Django Apps Structure

![Django Apps Structure](diagrams/django-apps-structure.png)

**To generate this diagram, use the following Mermaid code:**

```mermaid
graph TB
    subgraph "Core Apps"
        AUTH[Authentication]
        ORG[Organizations]
        PERMS[Permissions]
    end

    subgraph "Business Logic Apps"
        CLIENTS[Clients]
        DEALS[Deals]
        COMM[Commission]
        TEAM[Team]
        PROJ[Project]
    end

    subgraph "Feature Apps"
        NOTIF[Notifications]
        SALES_DASH[Sales Dashboard]
        VERIF_DASH[Verifier Dashboard]
    end

    subgraph "Supporting Apps"
        UTILS[Utils]
        MIDDLEWARE[Custom Middleware]
        MANAGEMENT[Management Commands]
    end

    AUTH --> ORG
    ORG --> PERMS
    PERMS --> CLIENTS
    PERMS --> DEALS
    PERMS --> COMM
    PERMS --> TEAM
    PERMS --> PROJ
    
    DEALS --> NOTIF
    DEALS --> SALES_DASH
    DEALS --> VERIF_DASH
    
    UTILS --> AUTH
    UTILS --> DEALS
    MIDDLEWARE --> AUTH
    MANAGEMENT --> ORG
```

### Application Layer Architecture

![Application Layer Architecture](diagrams/application-layer-architecture.png)

**To generate this diagram, use the following Mermaid code:**

```mermaid
graph TB
    subgraph "Presentation Layer"
        API[REST API Endpoints]
        WS[WebSocket Consumers]
        ADMIN[Django Admin]
    end

    subgraph "Business Logic Layer"
        MODELS[Django Models]
        VIEWS[API Views]
        SERIALIZERS[DRF Serializers]
        SERVICES[Business Services]
    end

    subgraph "Data Access Layer"
        ORM[Django ORM]
        MANAGERS[Custom Managers]
        QUERYSETS[Custom QuerySets]
    end

    subgraph "Infrastructure Layer"
        CACHE[Redis Cache]
        STORAGE[File Storage]
        EMAIL_SERVICE[Email Service]
        NOTIFICATIONS[Notification Service]
    end

    API --> VIEWS
    WS --> VIEWS
    ADMIN --> MODELS
    
    VIEWS --> SERIALIZERS
    VIEWS --> SERVICES
    SERIALIZERS --> MODELS
    SERVICES --> MODELS
    
    MODELS --> ORM
    MODELS --> MANAGERS
    MANAGERS --> QUERYSETS
    
    SERVICES --> CACHE
    SERVICES --> STORAGE
    SERVICES --> EMAIL_SERVICE
    SERVICES --> NOTIFICATIONS
```

---

## Database Architecture

### Entity Relationship Diagram

![Database Entity Relationship Diagram](diagrams/database-erd.png)

**To generate this diagram, use the following Mermaid code:**

```mermaid
erDiagram
    Organization ||--o{ User : "belongs_to"
    Organization ||--o{ Role : "has"
    Organization ||--o{ Team : "has"
    Organization ||--o{ Client : "has"
    Organization ||--o{ Deal : "has"
    
    User ||--o{ Deal : "created_by"
    User ||--o{ Commission : "earns"
    User ||--|| UserProfile : "has"
    User }o--|| Role : "assigned"
    User }o--o{ Team : "member_of"
    
    Client ||--o{ Deal : "has"
    Deal ||--o{ Payment : "has"
    Deal ||--o{ ActivityLog : "has"
    Deal ||--o{ PaymentInvoice : "generates"
    
    Payment ||--o{ PaymentApproval : "requires"
    Payment ||--o{ PaymentInvoice : "generates"
    
    Team ||--o{ Project : "works_on"
    Team }o--|| User : "led_by"
    
    Role ||--o{ Permission : "has"
    
    Organization {
        uuid id PK
        string name
        string email
        decimal sales_goal
        json settings
        datetime created_at
    }
    
    User {
        uuid id PK
        string email
        string first_name
        string last_name
        uuid organization_id FK
        uuid role_id FK
        boolean is_active
        datetime created_at
    }
    
    Deal {
        uuid id PK
        string deal_id
        uuid organization_id FK
        uuid client_id FK
        uuid created_by_id FK
        decimal amount
        string currency
        string status
        datetime created_at
    }
    
    Payment {
        uuid id PK
        string payment_id
        uuid deal_id FK
        decimal amount
        string currency
        string method
        string status
        datetime created_at
    }
    
    Client {
        uuid id PK
        string client_id
        uuid organization_id FK
        string name
        string email
        integer satisfaction_score
        datetime created_at
    }
```

### Database Schema Patterns

![Database Schema Patterns](diagrams/database-patterns.png)

**To generate this diagram, use the following Mermaid code:**

```mermaid
graph TB
    subgraph "Multi-tenancy Pattern"
        ORG_FILTER[Organization Filter]
        DATA_ISOLATION[Data Isolation]
        TENANT_AWARE[Tenant-Aware Queries]
    end

    subgraph "Audit Pattern"
        AUDIT_LOG[Activity Log]
        TIMESTAMP[Timestamps]
        USER_TRACKING[User Tracking]
    end

    subgraph "Security Pattern"
        UUID_PK[UUID Primary Keys]
        SOFT_DELETE[Soft Deletes]
        ENCRYPTION[Field Encryption]
    end

    subgraph "Performance Pattern"
        INDEXES[Strategic Indexes]
        QUERY_OPT[Query Optimization]
        CACHING[Database Caching]
    end

    ORG_FILTER --> DATA_ISOLATION
    DATA_ISOLATION --> TENANT_AWARE
    
    AUDIT_LOG --> TIMESTAMP
    TIMESTAMP --> USER_TRACKING
    
    UUID_PK --> SOFT_DELETE
    SOFT_DELETE --> ENCRYPTION
    
    INDEXES --> QUERY_OPT
    QUERY_OPT --> CACHING
```

---

## API Architecture

### RESTful API Structure

![RESTful API Structure](diagrams/api-structure.png)

**To generate this diagram, use the following Mermaid code:**

```mermaid
graph TB
    subgraph "API Gateway"
        NGINX[Nginx/Load Balancer]
        CORS[CORS Middleware]
        RATE_LIMIT[Rate Limiting]
    end

    subgraph "Authentication Layer"
        TOKEN_AUTH[Token Authentication]
        SESSION_AUTH[Session Authentication]
        MFA[Multi-Factor Auth]
    end

    subgraph "API Endpoints"
        AUTH_API[/api/auth/]
        BUSINESS_API[/api/business/]
        ANALYTICS_API[/api/analytics/]
        ADMIN_API[/api/admin/]
    end

    subgraph "Business Endpoints"
        CLIENTS_EP[/clients/]
        DEALS_EP[/deals/]
        PAYMENTS_EP[/payments/]
        TEAMS_EP[/teams/]
        PROJECTS_EP[/projects/]
    end

    subgraph "Response Layer"
        SERIALIZERS[DRF Serializers]
        PAGINATION[Pagination]
        FILTERING[Filtering]
        VALIDATION[Validation]
    end

    NGINX --> CORS
    CORS --> RATE_LIMIT
    RATE_LIMIT --> TOKEN_AUTH
    TOKEN_AUTH --> SESSION_AUTH
    SESSION_AUTH --> MFA
    
    MFA --> AUTH_API
    MFA --> BUSINESS_API
    MFA --> ANALYTICS_API
    MFA --> ADMIN_API
    
    BUSINESS_API --> CLIENTS_EP
    BUSINESS_API --> DEALS_EP
    BUSINESS_API --> PAYMENTS_EP
    BUSINESS_API --> TEAMS_EP
    BUSINESS_API --> PROJECTS_EP
    
    CLIENTS_EP --> SERIALIZERS
    DEALS_EP --> SERIALIZERS
    PAYMENTS_EP --> SERIALIZERS
    
    SERIALIZERS --> PAGINATION
    PAGINATION --> FILTERING
    FILTERING --> VALIDATION
```

---

## Security Architecture

### Security Layers

![Security Layers](diagrams/security-layers.png)

**To generate this diagram, use the following Mermaid code:**

```mermaid
graph TB
    subgraph "Network Security"
        HTTPS[HTTPS/TLS]
        CORS_SEC[CORS Protection]
        RATE_LIMITING[Rate Limiting]
    end

    subgraph "Application Security"
        AUTH_LAYER[Authentication Layer]
        AUTHZ_LAYER[Authorization Layer]
        INPUT_VAL[Input Validation]
    end

    subgraph "Data Security"
        ENCRYPTION[Data Encryption]
        DATA_ISOLATION[Data Isolation]
        AUDIT_TRAIL[Audit Trail]
    end

    subgraph "Infrastructure Security"
        ENV_VARS[Environment Variables]
        SECRET_MGMT[Secret Management]
        SECURITY_HEADERS[Security Headers]
    end

    HTTPS --> CORS_SEC
    CORS_SEC --> RATE_LIMITING
    RATE_LIMITING --> AUTH_LAYER
    
    AUTH_LAYER --> AUTHZ_LAYER
    AUTHZ_LAYER --> INPUT_VAL
    INPUT_VAL --> ENCRYPTION
    
    ENCRYPTION --> DATA_ISOLATION
    DATA_ISOLATION --> AUDIT_TRAIL
    AUDIT_TRAIL --> ENV_VARS
    
    ENV_VARS --> SECRET_MGMT
    SECRET_MGMT --> SECURITY_HEADERS
```

---

## Real-time Features

### WebSocket Architecture

![WebSocket Architecture](diagrams/websocket-architecture.png)

**To generate this diagram, use the following Mermaid code:**

```mermaid
graph TB
    subgraph "WebSocket Layer"
        WS_CONN[WebSocket Connections]
        CHANNELS[Django Channels]
        CONSUMERS[WebSocket Consumers]
    end

    subgraph "Message Routing"
        ROUTING[URL Routing]
        AUTH_WS[WebSocket Auth]
        CHANNEL_LAYER[Channel Layer]
    end

    subgraph "Business Logic"
        NOTIFICATION[Notification Service]
        REAL_TIME[Real-time Updates]
        BROADCAST[Message Broadcasting]
    end

    subgraph "Storage Layer"
        REDIS_CHANNELS[Redis Channel Layer]
        MESSAGE_QUEUE[Message Queue]
        PERSISTENCE[Message Persistence]
    end

    WS_CONN --> CHANNELS
    CHANNELS --> CONSUMERS
    CONSUMERS --> ROUTING
    
    ROUTING --> AUTH_WS
    AUTH_WS --> CHANNEL_LAYER
    CHANNEL_LAYER --> NOTIFICATION
    
    NOTIFICATION --> REAL_TIME
    REAL_TIME --> BROADCAST
    BROADCAST --> REDIS_CHANNELS
    
    REDIS_CHANNELS --> MESSAGE_QUEUE
    MESSAGE_QUEUE --> PERSISTENCE
```

---

## Data Flow Diagrams

### Deal Processing Flow

![Deal Processing Flow](diagrams/deal-processing-flow.png)

**To generate this diagram, use the following Mermaid code:**

```mermaid
graph TB
    subgraph "Deal Creation"
        START[Start Deal Creation]
        VALIDATE[Validate Deal Data]
        CREATE_DEAL[Create Deal Record]
        ASSIGN_ID[Generate Deal ID]
    end

    subgraph "Payment Processing"
        PAYMENT[Create Payment]
        VALIDATE_PAYMENT[Validate Payment Data]
        APPROVAL[Payment Approval Workflow]
        INVOICE[Generate Invoice]
    end

    subgraph "Commission Processing"
        CALC_COMMISSION[Calculate Commission]
        CREATE_COMMISSION[Create Commission Record]
        NOTIFY_USERS[Notify Stakeholders]
    end

    subgraph "Analytics Update"
        UPDATE_METRICS[Update Sales Metrics]
        UPDATE_STREAKS[Update Sales Streaks]
        UPDATE_DASHBOARD[Update Dashboard]
    end

    START --> VALIDATE
    VALIDATE --> CREATE_DEAL
    CREATE_DEAL --> ASSIGN_ID
    
    ASSIGN_ID --> PAYMENT
    PAYMENT --> VALIDATE_PAYMENT
    VALIDATE_PAYMENT --> APPROVAL
    APPROVAL --> INVOICE
    
    INVOICE --> CALC_COMMISSION
    CALC_COMMISSION --> CREATE_COMMISSION
    CREATE_COMMISSION --> NOTIFY_USERS
    
    NOTIFY_USERS --> UPDATE_METRICS
    UPDATE_METRICS --> UPDATE_STREAKS
    UPDATE_STREAKS --> UPDATE_DASHBOARD
```

### User Authentication Flow

![User Authentication Flow](diagrams/user-auth-flow.png)

**To generate this diagram, use the following Mermaid code:**

```mermaid
graph TB
    subgraph "Login Process"
        LOGIN[User Login Request]
        VALIDATE_CREDS[Validate Credentials]
        CHECK_MFA[Check MFA Required]
        MFA_VERIFY[MFA Verification]
    end

    subgraph "Session Management"
        CREATE_SESSION[Create Session]
        GENERATE_TOKEN[Generate JWT Token]
        STORE_SESSION[Store Session Data]
    end

    subgraph "Authorization"
        LOAD_ROLES[Load User Roles]
        LOAD_PERMISSIONS[Load Permissions]
        SET_CONTEXT[Set User Context]
    end

    LOGIN --> VALIDATE_CREDS
    VALIDATE_CREDS --> CHECK_MFA
    CHECK_MFA --> MFA_VERIFY
    MFA_VERIFY --> CREATE_SESSION
    
    CREATE_SESSION --> GENERATE_TOKEN
    GENERATE_TOKEN --> STORE_SESSION
    STORE_SESSION --> LOAD_ROLES
    
    LOAD_ROLES --> LOAD_PERMISSIONS
    LOAD_PERMISSIONS --> SET_CONTEXT
```

---

## Sequence Diagrams

### Deal Creation Sequence

![Deal Creation Sequence](diagrams/deal-creation-sequence.png)

**To generate this diagram, use the following Mermaid code:**

```mermaid
sequenceDiagram
    participant Salesperson
    participant Frontend
    participant API Gateway
    participant Deal Service
    participant Payment Service
    participant Notification Service
    participant Database

    Salesperson->>Frontend: Create New Deal
    Frontend->>API Gateway: POST /api/deals/
    API Gateway->>Deal Service: Validate & Create Deal
    Deal Service->>Database: Save Deal Record
    Database->>Deal Service: Deal Created
    Deal Service->>Payment Service: Create Payment Record
    Payment Service->>Database: Save Payment
    Database->>Payment Service: Payment Created
    Payment Service->>Notification Service: Trigger Notifications
    Notification Service->>Frontend: Real-time Updates
    Frontend->>Salesperson: Deal Created Successfully
```

### Payment Approval Sequence

![Payment Approval Sequence](diagrams/payment-approval-sequence.png)

**To generate this diagram, use the following Mermaid code:**

```mermaid
sequenceDiagram
    participant Verifier
    participant Frontend
    participant API Gateway
    participant Payment Service
    participant Commission Service
    participant Notification Service
    participant Database

    Verifier->>Frontend: Review Payment
    Frontend->>API Gateway: POST /api/payments/approve/
    API Gateway->>Payment Service: Approve Payment
    Payment Service->>Database: Update Payment Status
    Database->>Payment Service: Payment Approved
    Payment Service->>Commission Service: Calculate Commission
    Commission Service->>Database: Save Commission
    Database->>Commission Service: Commission Saved
    Commission Service->>Notification Service: Notify Stakeholders
    Notification Service->>Frontend: Real-time Notifications
    Frontend->>Verifier: Payment Approved
```

### Authentication & Authorization Sequence

![Authentication & Authorization Sequence](diagrams/auth-sequence.png)

**To generate this diagram, use the following Mermaid code:**

```mermaid
sequenceDiagram
    participant Client
    participant API Gateway
    participant Auth Service
    participant Permission Service
    participant Business Logic
    participant Database

    Client->>API Gateway: Request with Token
    API Gateway->>Auth Service: Validate Token
    Auth Service->>Auth Service: Verify Token
    Auth Service->>Permission Service: Check Permissions
    Permission Service->>Permission Service: Validate Role & Org
    Permission Service->>Business Logic: Authorized Request
    Business Logic->>Database: Query with Org Filter
    Database->>Business Logic: Filtered Results
    Business Logic->>Client: Response
```

---

## Component Relationships

### Core Component Interaction

![Core Component Interaction](diagrams/component-interaction.png)

**To generate this diagram, use the following Mermaid code:**

```mermaid
graph TB
    subgraph "User Interface Layer"
        WEB_UI[Web Interface]
        MOBILE_UI[Mobile Interface]
        API_DOCS[API Documentation]
    end

    subgraph "API Layer"
        REST_API[REST API]
        WS_API[WebSocket API]
        ADMIN_API[Admin API]
    end

    subgraph "Business Logic Layer"
        AUTH_SERVICE[Authentication Service]
        DEAL_SERVICE[Deal Service]
        PAYMENT_SERVICE[Payment Service]
        NOTIFICATION_SERVICE[Notification Service]
        COMMISSION_SERVICE[Commission Service]
    end

    subgraph "Data Layer"
        USER_MODEL[User Model]
        DEAL_MODEL[Deal Model]
        PAYMENT_MODEL[Payment Model]
        COMMISSION_MODEL[Commission Model]
    end

    subgraph "Infrastructure Layer"
        DATABASE[PostgreSQL]
        CACHE[Redis]
        STORAGE[Cloudinary]
        EMAIL[Email Service]
    end

    WEB_UI --> REST_API
    MOBILE_UI --> REST_API
    API_DOCS --> REST_API
    
    REST_API --> AUTH_SERVICE
    WS_API --> NOTIFICATION_SERVICE
    ADMIN_API --> AUTH_SERVICE
    
    AUTH_SERVICE --> USER_MODEL
    DEAL_SERVICE --> DEAL_MODEL
    PAYMENT_SERVICE --> PAYMENT_MODEL
    COMMISSION_SERVICE --> COMMISSION_MODEL
    
    USER_MODEL --> DATABASE
    DEAL_MODEL --> DATABASE
    PAYMENT_MODEL --> DATABASE
    COMMISSION_MODEL --> DATABASE
    
    AUTH_SERVICE --> CACHE
    NOTIFICATION_SERVICE --> CACHE
    PAYMENT_SERVICE --> STORAGE
    NOTIFICATION_SERVICE --> EMAIL
```

---

## Deployment Architecture

### Production Deployment

![Production Deployment](diagrams/production-deployment.png)

**To generate this diagram, use the following Mermaid code:**

```mermaid
graph TB
    subgraph "Render.com Infrastructure"
        LB[Load Balancer]
        WEB_SERVICE[Web Service]
        REDIS_SERVICE[Redis Service]
        DB_SERVICE[PostgreSQL Service]
    end

    subgraph "Application Stack"
        DAPHNE[Daphne ASGI Server]
        DJANGO[Django Application]
        CELERY[Background Tasks]
    end

    subgraph "Static Assets"
        WHITENOISE[WhiteNoise]
        CLOUDINARY[Cloudinary CDN]
        STATIC_FILES[Static Files]
    end

    subgraph "Monitoring & Logging"
        HEALTH_CHECK[Health Checks]
        LOG_AGGREGATION[Log Aggregation]
        METRICS[Application Metrics]
    end

    LB --> WEB_SERVICE
    WEB_SERVICE --> DAPHNE
    DAPHNE --> DJANGO
    DJANGO --> CELERY
    
    WEB_SERVICE --> REDIS_SERVICE
    WEB_SERVICE --> DB_SERVICE
    
    DJANGO --> WHITENOISE
    WHITENOISE --> STATIC_FILES
    DJANGO --> CLOUDINARY
    
    WEB_SERVICE --> HEALTH_CHECK
    DJANGO --> LOG_AGGREGATION
    DJANGO --> METRICS
```

---

## Performance & Scalability

### Performance Optimization Strategy

![Performance Optimization Strategy](diagrams/performance-optimization.png)

**To generate this diagram, use the following Mermaid code:**

```mermaid
graph TB
    subgraph "Database Optimization"
        INDEXES[Strategic Indexes]
        QUERY_OPT[Query Optimization]
        CONNECTION_POOL[Connection Pooling]
    end

    subgraph "Caching Strategy"
        REDIS_CACHE[Redis Caching]
        QUERY_CACHE[Query Caching]
        TEMPLATE_CACHE[Template Caching]
    end

    subgraph "Application Optimization"
        ASYNC_TASKS[Async Task Processing]
        LAZY_LOADING[Lazy Loading]
        BULK_OPERATIONS[Bulk Operations]
    end

    subgraph "Infrastructure Optimization"
        CDN[Content Delivery Network]
        LOAD_BALANCING[Load Balancing]
        AUTO_SCALING[Auto Scaling]
    end

    INDEXES --> QUERY_OPT
    QUERY_OPT --> CONNECTION_POOL
    CONNECTION_POOL --> REDIS_CACHE
    
    REDIS_CACHE --> QUERY_CACHE
    QUERY_CACHE --> TEMPLATE_CACHE
    TEMPLATE_CACHE --> ASYNC_TASKS
    
    ASYNC_TASKS --> LAZY_LOADING
    LAZY_LOADING --> BULK_OPERATIONS
    BULK_OPERATIONS --> CDN
    
    CDN --> LOAD_BALANCING
    LOAD_BALANCING --> AUTO_SCALING
```

---

## Diagram Generation Instructions

### How to Generate the Diagrams

1. **Visit [Mermaid Live Editor](https://mermaid.live)**
2. **Copy and paste each Mermaid code block** from the sections above
3. **Export as PNG or SVG** using the export button
4. **Save the images** in a `diagrams/` folder in your project
5. **Update the image paths** in this documentation

### Recommended Export Settings:
- **Format**: PNG or SVG
- **Resolution**: High (for documentation)
- **Background**: White or transparent
- **Size**: Large (for readability)

### Alternative Tools:
- **Mermaid Chart**: https://www.mermaidchart.com/play
- **Mermaid Viewer**: https://mermaidviewer.com/
- **Draw.io**: https://draw.io (with Mermaid plugin)
- **VS Code Extension**: Mermaid Preview

### Folder Structure for Diagrams:
```
project-root/
├── diagrams/
│   ├── high-level-architecture.png
│   ├── multi-tenant-architecture.png
│   ├── django-apps-structure.png
│   ├── database-erd.png
│   ├── api-structure.png
│   ├── security-layers.png
│   ├── websocket-architecture.png
│   ├── deal-processing-flow.png
│   ├── sequence-diagrams/
│   │   ├── deal-creation-sequence.png
│   │   ├── payment-approval-sequence.png
│   │   └── auth-sequence.png
│   └── component-interaction.png
└── Backend_PRS_Architecture_Documentation_with_Images.md
```

---

## Key Business Workflows

### Sales Process Workflow

![Sales Process Workflow](diagrams/sales-process-workflow.png)

**To generate this diagram, use the following Mermaid code:**

```mermaid
graph TB
    START[Start Sales Process]
    CLIENT_CONTACT[Client Contact]
    DEAL_NEGOTIATION[Deal Negotiation]
    DEAL_CREATION[Deal Creation]
    PAYMENT_PROCESSING[Payment Processing]
    VERIFICATION[Payment Verification]
    COMMISSION_CALC[Commission Calculation]
    ANALYTICS_UPDATE[Analytics Update]
    END[Process Complete]

    START --> CLIENT_CONTACT
    CLIENT_CONTACT --> DEAL_NEGOTIATION
    DEAL_NEGOTIATION --> DEAL_CREATION
    DEAL_CREATION --> PAYMENT_PROCESSING
    PAYMENT_PROCESSING --> VERIFICATION
    VERIFICATION --> COMMISSION_CALC
    COMMISSION_CALC --> ANALYTICS_UPDATE
    ANALYTICS_UPDATE --> END
```

### Commission Processing Workflow

![Commission Processing Workflow](diagrams/commission-processing-workflow.png)

**To generate this diagram, use the following Mermaid code:**

```mermaid
graph TB
    PAYMENT_APPROVED[Payment Approved]
    VALIDATE_DEAL[Validate Deal]
    CALCULATE_BASE[Calculate Base Commission]
    APPLY_BONUSES[Apply Performance Bonuses]
    DEDUCT_PENALTIES[Deduct Penalties]
    CREATE_COMMISSION[Create Commission Record]
    NOTIFY_SALESPERSON[Notify Salesperson]
    UPDATE_ANALYTICS[Update Analytics]

    PAYMENT_APPROVED --> VALIDATE_DEAL
    VALIDATE_DEAL --> CALCULATE_BASE
    CALCULATE_BASE --> APPLY_BONUSES
    APPLY_BONUSES --> DEDUCT_PENALTIES
    DEDUCT_PENALTIES --> CREATE_COMMISSION
    CREATE_COMMISSION --> NOTIFY_SALESPERSON
    NOTIFY_SALESPERSON --> UPDATE_ANALYTICS
```

---

## Detailed Component Specifications

### Core Models and Their Relationships

#### User Model
```python
class User(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=150)
    last_name = models.CharField(max_length=150)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
```

#### Deal Model
```python
class Deal(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    deal_id = models.CharField(max_length=50, unique=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=15, decimal_places=2)
    currency = models.CharField(max_length=3, default='USD')
    status = models.CharField(max_length=20, choices=DEAL_STATUS_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
```

#### Payment Model
```python
class Payment(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    payment_id = models.CharField(max_length=50, unique=True)
    deal = models.ForeignKey(Deal, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=15, decimal_places=2)
    currency = models.CharField(max_length=3, default='USD')
    method = models.CharField(max_length=20, choices=PAYMENT_METHOD_CHOICES)
    status = models.CharField(max_length=20, choices=PAYMENT_STATUS_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
```

### API Endpoints Overview

#### Authentication Endpoints
```
POST /api/auth/login/           # User login
POST /api/auth/logout/          # User logout
POST /api/auth/refresh/         # Refresh JWT token
GET  /api/auth/user/           # Get current user
PUT  /api/auth/user/           # Update user profile
POST /api/auth/change-password/ # Change password
```

#### Deal Management Endpoints
```
GET    /api/deals/              # List deals
POST   /api/deals/              # Create new deal
GET    /api/deals/{id}/         # Get deal details
PUT    /api/deals/{id}/         # Update deal
DELETE /api/deals/{id}/         # Delete deal
POST   /api/deals/{id}/approve/ # Approve deal
```

#### Payment Endpoints
```
GET    /api/payments/           # List payments
POST   /api/payments/           # Create payment
GET    /api/payments/{id}/      # Get payment details
PUT    /api/payments/{id}/      # Update payment
POST   /api/payments/{id}/approve/ # Approve payment
GET    /api/payments/{id}/invoice/ # Get payment invoice
```

#### Analytics Endpoints
```
GET /api/analytics/dashboard/   # Dashboard metrics
GET /api/analytics/sales/       # Sales analytics
GET /api/analytics/commission/  # Commission analytics
GET /api/analytics/performance/ # Performance metrics
```

---

## Security Implementation Details

### Authentication Middleware
```python
class TokenAuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        token = request.META.get('HTTP_AUTHORIZATION')
        if token:
            user = self.authenticate_token(token)
            if user:
                request.user = user
        
        response = self.get_response(request)
        return response
```

### Permission System
```python
class OrganizationPermission(BasePermission):
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        
        # Check organization-level permissions
        return request.user.organization.is_active
    
    def has_object_permission(self, request, view, obj):
        # Ensure user can only access their organization's data
        return obj.organization == request.user.organization
```

### Data Isolation
```python
class OrganizationQuerySet(models.QuerySet):
    def for_organization(self, organization):
        return self.filter(organization=organization)

class OrganizationManager(models.Manager):
    def get_queryset(self):
        return OrganizationQuerySet(self.model, using=self._db)
    
    def for_organization(self, organization):
        return self.get_queryset().for_organization(organization)
```

---

## Conclusion

This comprehensive architecture documentation provides a complete overview of the Backend_PRS system with visual diagrams that can be generated using the provided Mermaid code. The system is designed with:

- **Enterprise-grade security** with multi-layer protection
- **Scalable multi-tenant architecture** for SaaS deployment
- **Real-time capabilities** for enhanced user experience
- **Comprehensive business logic** for payment processing and commission management
- **Modern technology stack** with Django and related frameworks
- **Production-ready deployment** configuration

The visual diagrams help stakeholders understand the system architecture, data flow, and component relationships, making it easier to maintain, extend, and scale the application.

---

## Next Steps

1. **Generate all diagrams** using the Mermaid code provided
2. **Create a diagrams folder** in your project root
3. **Export images** from Mermaid Live Editor
4. **Update image paths** in this documentation
5. **Review and customize** diagrams based on your specific needs
6. **Keep documentation updated** as the system evolves

This documentation serves as a living document that should be updated as the system architecture evolves.