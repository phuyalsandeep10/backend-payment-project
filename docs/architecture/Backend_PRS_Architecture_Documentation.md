# Backend_PRS - System Architecture Documentation

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

### API Response Structure

```json
{
    "success": true,
    "data": {
        "results": [...],
        "pagination": {
            "count": 100,
            "next": "url",
            "previous": "url",
            "page_size": 20
        }
    },
    "meta": {
        "timestamp": "2024-01-01T00:00:00Z",
        "version": "1.0",
        "request_id": "uuid"
    }
}
```

---

## Security Architecture

### Security Layers

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

### Authentication & Authorization Flow

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

## Real-time Features

### WebSocket Architecture

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

### Real-time Notification Flow

```mermaid
sequenceDiagram
    participant User A
    participant WebSocket
    participant Notification Service
    participant Redis
    participant User B

    User A->>WebSocket: Connect with Token
    WebSocket->>Notification Service: Authenticate User
    Notification Service->>Redis: Store Connection
    
    Note over User A, User B: Business Action Occurs
    
    User A->>Notification Service: Trigger Notification
    Notification Service->>Redis: Broadcast Message
    Redis->>WebSocket: Send to Connected Users
    WebSocket->>User B: Real-time Notification
```

---

## Data Flow Diagrams

### Deal Processing Flow

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

### Real-time Notification Sequence

```mermaid
sequenceDiagram
    participant User A
    participant WebSocket A
    participant Notification Service
    participant Redis
    participant WebSocket B
    participant User B

    User A->>WebSocket A: Connect
    WebSocket A->>Notification Service: Authenticate
    Notification Service->>Redis: Store Connection
    
    User B->>WebSocket B: Connect
    WebSocket B->>Notification Service: Authenticate
    Notification Service->>Redis: Store Connection
    
    Note over User A, User B: Business Event Occurs
    
    Notification Service->>Redis: Broadcast Notification
    Redis->>WebSocket A: Send Notification
    Redis->>WebSocket B: Send Notification
    WebSocket A->>User A: Display Notification
    WebSocket B->>User B: Display Notification
```

---

## Component Relationships

### Core Component Interaction

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

### Inter-Service Communication

```mermaid
graph TB
    subgraph "Services Communication"
        DEAL_SVC[Deal Service]
        PAYMENT_SVC[Payment Service]
        COMM_SVC[Commission Service]
        NOTIF_SVC[Notification Service]
        ANALYTICS_SVC[Analytics Service]
    end

    subgraph "Communication Methods"
        DIRECT[Direct Method Calls]
        SIGNALS[Django Signals]
        EVENTS[Event Broadcasting]
        ASYNC[Async Tasks]
    end

    DEAL_SVC -->|Direct Call| PAYMENT_SVC
    PAYMENT_SVC -->|Django Signal| COMM_SVC
    COMM_SVC -->|Event Broadcast| NOTIF_SVC
    NOTIF_SVC -->|Async Task| ANALYTICS_SVC
    
    DEAL_SVC -->|Signal| ANALYTICS_SVC
    PAYMENT_SVC -->|Event| NOTIF_SVC
```

---

## Deployment Architecture

### Production Deployment

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

### Environment Configuration

```mermaid
graph TB
    subgraph "Environment Variables"
        DATABASE_URL[DATABASE_URL]
        REDIS_URL[REDIS_URL]
        SECRET_KEY[SECRET_KEY]
        CLOUDINARY_CONFIG[CLOUDINARY_CONFIG]
    end

    subgraph "Configuration Files"
        SETTINGS_PY[settings.py]
        ENV_FILES[.env files]
        RENDER_YAML[render.yaml]
    end

    subgraph "Deployment Scripts"
        BUILD_SCRIPT[render-build.sh]
        START_SCRIPT[render-start-safe.sh]
        MIGRATE_SCRIPT[migrate.sh]
    end

    DATABASE_URL --> SETTINGS_PY
    REDIS_URL --> SETTINGS_PY
    SECRET_KEY --> SETTINGS_PY
    CLOUDINARY_CONFIG --> SETTINGS_PY
    
    SETTINGS_PY --> ENV_FILES
    ENV_FILES --> RENDER_YAML
    
    BUILD_SCRIPT --> MIGRATE_SCRIPT
    MIGRATE_SCRIPT --> START_SCRIPT
```

---

## Performance & Scalability

### Performance Optimization Strategy

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

### Scalability Considerations

```mermaid
graph TB
    subgraph "Horizontal Scaling"
        MULTI_INSTANCE[Multiple App Instances]
        LOAD_BALANCER[Load Balancer]
        STATELESS_DESIGN[Stateless Design]
    end

    subgraph "Vertical Scaling"
        CPU_SCALING[CPU Scaling]
        MEMORY_SCALING[Memory Scaling]
        STORAGE_SCALING[Storage Scaling]
    end

    subgraph "Database Scaling"
        READ_REPLICAS[Read Replicas]
        PARTITIONING[Data Partitioning]
        SHARDING[Database Sharding]
    end

    subgraph "Caching Scaling"
        REDIS_CLUSTER[Redis Cluster]
        CACHE_LAYERS[Multiple Cache Layers]
        CACHE_WARMING[Cache Warming]
    end

    MULTI_INSTANCE --> LOAD_BALANCER
    LOAD_BALANCER --> STATELESS_DESIGN
    
    CPU_SCALING --> MEMORY_SCALING
    MEMORY_SCALING --> STORAGE_SCALING
    
    READ_REPLICAS --> PARTITIONING
    PARTITIONING --> SHARDING
    
    REDIS_CLUSTER --> CACHE_LAYERS
    CACHE_LAYERS --> CACHE_WARMING
```

---

## Key Business Workflows

### Sales Process Workflow

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

## Conclusion

The Backend_PRS system is built with a modern, scalable architecture that supports:

- **Multi-tenancy** with complete data isolation
- **Real-time features** for enhanced user experience
- **Comprehensive security** with multiple layers of protection
- **Flexible payment processing** with approval workflows
- **Advanced analytics** and reporting capabilities
- **Scalable infrastructure** ready for enterprise deployment

This architecture provides a solid foundation for a growing SaaS business while maintaining security, performance, and maintainability standards.

---

## Appendices

### A. Technology Versions
- Django: 5.2.2
- Django REST Framework: 3.15.2
- Django Channels: 4.0.0
- PostgreSQL: Latest
- Redis: Latest
- Python: 3.11+

### B. Key Environment Variables
```
DATABASE_URL=postgresql://...
REDIS_URL=redis://...
SECRET_KEY=...
CLOUDINARY_URL=...
DEBUG=False
ALLOWED_HOSTS=...
```

### C. Important Management Commands
```bash
python manage.py initialize_app          # Initialize application
python manage.py create_super_admin      # Create super admin
python manage.py setup_permissions       # Setup permissions
python manage.py calculate_streaks       # Calculate sales streaks
python manage.py collectstatic          # Collect static files
python manage.py migrate                # Run migrations
```