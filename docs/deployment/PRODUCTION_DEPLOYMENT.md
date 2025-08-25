# Production Deployment Guide

## Overview

This guide provides comprehensive instructions for deploying the Payment Receiving System (PRS) Backend to production environments. It covers deployment strategies, infrastructure requirements, security considerations, and operational procedures.

---

## 📋 Table of Contents

1. [Pre-Deployment Checklist](#pre-deployment-checklist)
2. [Infrastructure Requirements](#infrastructure-requirements)
3. [Environment Setup](#environment-setup)
4. [Database Setup and Migrations](#database-setup-and-migrations)
5. [Application Deployment](#application-deployment)
6. [Security Configuration](#security-configuration)
7. [Monitoring and Logging](#monitoring-and-logging)
8. [Post-Deployment Verification](#post-deployment-verification)
9. [Rollback Procedures](#rollback-procedures)
10. [Troubleshooting](#troubleshooting)

---

## ✅ Pre-Deployment Checklist

### Code Quality Verification
- [ ] All tests pass (unit, integration, security)
- [ ] Code quality gates pass (complexity < thresholds)
- [ ] Security scans completed with no critical issues
- [ ] Database migrations reviewed and tested
- [ ] Environment variables documented and secured
- [ ] Static files collected and optimized
- [ ] Documentation updated

### Infrastructure Readiness
- [ ] Production database provisioned and configured
- [ ] Redis cache cluster configured
- [ ] Load balancer configured
- [ ] SSL certificates installed and validated
- [ ] CDN configured for static/media files
- [ ] Monitoring systems configured
- [ ] Backup systems configured
- [ ] Log aggregation configured

### Security Checklist
- [ ] Secrets management system configured
- [ ] Database credentials rotated
- [ ] API keys secured
- [ ] HTTPS enforced
- [ ] Security headers configured
- [ ] Rate limiting configured
- [ ] WAF rules configured (if applicable)

---

## 🏗️ Infrastructure Requirements

### Minimum Production Requirements

#### Application Server
- **CPU**: 4 vCPUs (8 vCPUs recommended)
- **RAM**: 8 GB (16 GB recommended)
- **Storage**: 100 GB SSD (250 GB recommended)
- **OS**: Ubuntu 20.04 LTS or newer

#### Database Server (PostgreSQL)
- **CPU**: 4 vCPUs (8 vCPUs for high load)
- **RAM**: 8 GB (32 GB recommended)
- **Storage**: 200 GB SSD with backup
- **Version**: PostgreSQL 14+

#### Cache Server (Redis)
- **CPU**: 2 vCPUs
- **RAM**: 4 GB (8 GB recommended)
- **Storage**: 50 GB SSD
- **Version**: Redis 7+

#### Load Balancer
- **Application Load Balancer** with SSL termination
- **Health checks** configured
- **Auto-scaling** policies configured

### Recommended Cloud Architecture

#### AWS Deployment
```
Internet Gateway
    ↓
Application Load Balancer (ALB)
    ↓
Auto Scaling Group
    ↓ (Multiple AZs)
ECS/EC2 Instances (Django App)
    ↓
RDS PostgreSQL (Multi-AZ)
ElastiCache Redis (Cluster Mode)
S3 (Static/Media Files)
CloudWatch (Monitoring)
```

#### Azure Deployment
```
Azure Front Door
    ↓
Application Gateway
    ↓
App Service / Container Instances
    ↓
Azure Database for PostgreSQL
Azure Cache for Redis
Azure Blob Storage
Azure Monitor
```

---

## 🔧 Environment Setup

### 1. Create Production Environment File

Create `.env.production`:

```bash
# Django Core Settings
SECRET_KEY=your-256-bit-secret-key-here
DEBUG=False
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com,api.yourdomain.com
DJANGO_SETTINGS_MODULE=core_config.settings.production

# Database Configuration
DATABASE_URL=postgresql://username:password@db-host:5432/prs_production
DB_NAME=prs_production
DB_USER=prs_app_user
DB_PASSWORD=secure-database-password
DB_HOST=your-db-host.amazonaws.com
DB_PORT=5432
DB_SSL_REQUIRE=True

# Redis Configuration
REDIS_URL=redis://your-redis-cluster:6379/0
CELERY_BROKER_URL=redis://your-redis-cluster:6379/0
CELERY_RESULT_BACKEND=redis://your-redis-cluster:6379/0

# Email Configuration
EMAIL_HOST=smtp.gmail.com
EMAIL_HOST_USER=your-app@yourdomain.com
EMAIL_HOST_PASSWORD=your-app-password
EMAIL_PORT=587
EMAIL_USE_TLS=True
DEFAULT_FROM_EMAIL=noreply@yourdomain.com
SUPER_ADMIN_OTP_EMAIL=admin@yourdomain.com

# Media Storage (AWS S3)
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_STORAGE_BUCKET_NAME=prs-media-production
AWS_S3_REGION_NAME=us-east-1
AWS_S3_CUSTOM_DOMAIN=cdn.yourdomain.com
USE_S3=True

# Security Settings
SECURE_PROXY_SSL_HEADER_HTTP_X_FORWARDED_PROTO=https
SECURE_SSL_REDIRECT=True
SESSION_COOKIE_SECURE=True
CSRF_COOKIE_SECURE=True
SECURE_BROWSER_XSS_FILTER=True
SECURE_CONTENT_TYPE_NOSNIFF=True
X_FRAME_OPTIONS=DENY

# Monitoring & Logging
SENTRY_DSN=https://your-sentry-dsn@sentry.io/project-id
LOG_LEVEL=INFO
ENABLE_MONITORING=True

# Performance
GUNICORN_WORKERS=4
GUNICORN_THREADS=2
GUNICORN_TIMEOUT=120

# Application Settings
SITE_URL=https://yourdomain.com
API_BASE_URL=https://api.yourdomain.com
FRONTEND_URL=https://app.yourdomain.com
```

### 2. Secrets Management

#### Using AWS Secrets Manager

```bash
# Create secret for database
aws secretsmanager create-secret \
    --name "prs/production/database" \
    --description "PRS Production Database Credentials" \
    --secret-string '{
        "username": "prs_app_user",
        "password": "secure-database-password",
        "host": "prs-prod-db.cluster-xyz.us-east-1.rds.amazonaws.com",
        "port": 5432,
        "database": "prs_production"
    }'

# Create secret for Django
aws secretsmanager create-secret \
    --name "prs/production/django" \
    --description "PRS Production Django Settings" \
    --secret-string '{
        "SECRET_KEY": "your-256-bit-secret-key",
        "EMAIL_HOST_PASSWORD": "your-app-password",
        "AWS_SECRET_ACCESS_KEY": "your-secret-key"
    }'
```

#### Using HashiCorp Vault

```bash
# Enable KV secrets engine
vault secrets enable -path=prs kv-v2

# Store database credentials
vault kv put prs/production/database \
    username=prs_app_user \
    password=secure-database-password \
    host=prs-prod-db.cluster-xyz.us-east-1.rds.amazonaws.com \
    port=5432 \
    database=prs_production

# Store application secrets
vault kv put prs/production/django \
    SECRET_KEY=your-256-bit-secret-key \
    EMAIL_HOST_PASSWORD=your-app-password \
    AWS_SECRET_ACCESS_KEY=your-secret-key
```

---

## 🗄️ Database Setup and Migrations

### 1. Database Provisioning

#### AWS RDS Setup

```bash
# Create DB subnet group
aws rds create-db-subnet-group \
    --db-subnet-group-name prs-prod-subnet-group \
    --db-subnet-group-description "PRS Production DB Subnet Group" \
    --subnet-ids subnet-12345678 subnet-87654321

# Create parameter group
aws rds create-db-parameter-group \
    --db-parameter-group-name prs-prod-params \
    --db-parameter-group-family postgres14 \
    --description "PRS Production PostgreSQL Parameters"

# Create RDS instance
aws rds create-db-instance \
    --db-instance-identifier prs-production \
    --db-instance-class db.t3.large \
    --engine postgres \
    --engine-version 14.9 \
    --master-username prs_admin \
    --master-user-password your-admin-password \
    --allocated-storage 200 \
    --storage-type gp2 \
    --storage-encrypted \
    --vpc-security-group-ids sg-12345678 \
    --db-subnet-group-name prs-prod-subnet-group \
    --db-parameter-group-name prs-prod-params \
    --backup-retention-period 7 \
    --multi-az \
    --auto-minor-version-upgrade \
    --deletion-protection
```

#### Database Configuration

```sql
-- Connect as master user and create application database
CREATE DATABASE prs_production;
CREATE USER prs_app_user WITH PASSWORD 'secure-database-password';

-- Grant necessary permissions
GRANT ALL PRIVILEGES ON DATABASE prs_production TO prs_app_user;

-- Connect to prs_production database
\c prs_production;

-- Create necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "btree_gin";

-- Grant usage on extensions
GRANT USAGE ON SCHEMA public TO prs_app_user;
GRANT CREATE ON SCHEMA public TO prs_app_user;
```

### 2. Migration Procedures

#### Pre-Migration Backup

```bash
#!/bin/bash
# backup-database.sh

DB_HOST=${DB_HOST:-localhost}
DB_NAME=${DB_NAME:-prs_production}
DB_USER=${DB_USER:-prs_app_user}
BACKUP_DIR="/var/backups/postgresql"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p $BACKUP_DIR

# Create database backup
pg_dump -h $DB_HOST -U $DB_USER -d $DB_NAME \
    --clean --create --if-exists \
    --format=custom \
    --compress=9 \
    --file=$BACKUP_DIR/prs_production_$TIMESTAMP.backup

# Create schema-only backup
pg_dump -h $DB_HOST -U $DB_USER -d $DB_NAME \
    --schema-only \
    --file=$BACKUP_DIR/prs_production_schema_$TIMESTAMP.sql

# Verify backup
if [ -f "$BACKUP_DIR/prs_production_$TIMESTAMP.backup" ]; then
    echo "✅ Backup completed: $BACKUP_DIR/prs_production_$TIMESTAMP.backup"
    
    # Upload to S3 (optional)
    aws s3 cp $BACKUP_DIR/prs_production_$TIMESTAMP.backup \
        s3://prs-backups/database/prs_production_$TIMESTAMP.backup
else
    echo "❌ Backup failed"
    exit 1
fi
```

#### Migration Execution

```bash
#!/bin/bash
# run-migrations.sh

set -e  # Exit on any error

echo "🔄 Starting database migrations..."

# Load environment variables
source .env.production

# Change to application directory
cd /app

# Check database connection
python manage.py dbshell --command="SELECT version();" || {
    echo "❌ Database connection failed"
    exit 1
}

# Show migration plan
echo "📋 Migration plan:"
python manage.py showmigrations

# Run migrations
echo "🔄 Applying migrations..."
python manage.py migrate --noinput

# Verify migrations
echo "✅ Verifying migrations..."
python manage.py showmigrations | grep "\[ \]" && {
    echo "❌ Some migrations are still pending"
    exit 1
} || echo "✅ All migrations applied successfully"

# Create superuser if doesn't exist
echo "👤 Ensuring superuser exists..."
python manage.py shell << EOF
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(is_superuser=True).exists():
    User.objects.create_superuser(
        email='admin@yourdomain.com',
        password='temp-password-change-immediately',
        first_name='System',
        last_name='Administrator'
    )
    print("✅ Superuser created")
else:
    print("✅ Superuser already exists")
EOF

# Collect static files
echo "📦 Collecting static files..."
python manage.py collectstatic --noinput --clear

# Warm up cache if needed
echo "🔄 Warming up application cache..."
python manage.py shell << EOF
from django.core.cache import cache
cache.set('deployment_timestamp', '$(date -u +%Y-%m-%dT%H:%M:%SZ)', 3600)
print("✅ Cache warmed up")
EOF

echo "✅ Migration and setup completed successfully"
```

#### Migration Rollback Procedure

```bash
#!/bin/bash
# rollback-migrations.sh

set -e

ROLLBACK_TO=${1:-"previous"}

echo "🔄 Rolling back migrations to: $ROLLBACK_TO"

# Show current migration status
python manage.py showmigrations

if [ "$ROLLBACK_TO" = "previous" ]; then
    # Rollback to previous migration for each app
    for app in authentication deals commission clients notifications permissions organization; do
        echo "Rolling back $app..."
        python manage.py migrate $app --fake-initial || true
    done
else
    # Rollback to specific migration
    python manage.py migrate $ROLLBACK_TO
fi

# Verify rollback
python manage.py showmigrations
echo "✅ Rollback completed"
```

---

## 🚀 Application Deployment

### 1. Docker Deployment

#### Build Production Image

```bash
#!/bin/bash
# build-production-image.sh

set -e

REGISTRY=${1:-"your-registry.com"}
IMAGE_NAME="prs-backend"
VERSION=${2:-$(git rev-parse --short HEAD)}
TAG="$REGISTRY/$IMAGE_NAME:$VERSION"

echo "🔨 Building production Docker image: $TAG"

# Build multi-stage production image
docker build \
    --target production \
    --tag $TAG \
    --tag $REGISTRY/$IMAGE_NAME:latest \
    --build-arg VERSION=$VERSION \
    --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
    --file docker/Dockerfile.production \
    .

# Security scan
echo "🔍 Running security scan..."
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
    aquasec/trivy image --exit-code 1 --severity HIGH,CRITICAL $TAG

# Push to registry
echo "📤 Pushing to registry..."
docker push $TAG
docker push $REGISTRY/$IMAGE_NAME:latest

echo "✅ Image built and pushed: $TAG"
```

#### Production Dockerfile

```dockerfile
# docker/Dockerfile.production
FROM python:3.11-slim as base

# Build arguments
ARG VERSION=unknown
ARG BUILD_DATE=unknown

# Labels
LABEL maintainer="PRS Team <dev@yourdomain.com>"
LABEL version=$VERSION
LABEL build-date=$BUILD_DATE
LABEL description="PRS Backend Production Image"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DEBIAN_FRONTEND=noninteractive

# Create app user
RUN groupadd --gid 1000 app && \
    useradd --uid 1000 --gid app --shell /bin/bash --create-home app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    postgresql-client \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Set work directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements/production.txt ./requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install gunicorn

# Copy project files
COPY . .

# Create necessary directories
RUN mkdir -p /app/staticfiles /app/media /app/logs /app/temp

# Collect static files
RUN python manage.py collectstatic --noinput --settings=core_config.settings.production

# Set proper permissions
RUN chown -R app:app /app && \
    chmod +x docker/entrypoint.sh

USER app

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/health/ || exit 1

# Expose port
EXPOSE 8000

# Entrypoint
ENTRYPOINT ["./docker/entrypoint.sh"]
CMD ["gunicorn"]
```

#### Docker Compose for Production

```yaml
# docker-compose.production.yml
version: '3.8'

services:
  app:
    image: your-registry.com/prs-backend:latest
    restart: unless-stopped
    environment:
      - DJANGO_SETTINGS_MODULE=core_config.settings.production
    env_file:
      - .env.production
    volumes:
      - static_volume:/app/staticfiles
      - media_volume:/app/media
      - logs_volume:/app/logs
    ports:
      - "8000:8000"
    depends_on:
      - redis
    networks:
      - prs_network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/api/health/"]
      interval: 30s
      timeout: 10s
      retries: 3

  celery_worker:
    image: your-registry.com/prs-backend:latest
    restart: unless-stopped
    command: celery -A core_config worker -l info
    environment:
      - DJANGO_SETTINGS_MODULE=core_config.settings.production
    env_file:
      - .env.production
    volumes:
      - media_volume:/app/media
      - logs_volume:/app/logs
    depends_on:
      - redis
    networks:
      - prs_network

  celery_beat:
    image: your-registry.com/prs-backend:latest
    restart: unless-stopped
    command: celery -A core_config beat -l info
    environment:
      - DJANGO_SETTINGS_MODULE=core_config.settings.production
    env_file:
      - .env.production
    volumes:
      - logs_volume:/app/logs
    depends_on:
      - redis
    networks:
      - prs_network

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    command: redis-server --appendonly yes --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_volume:/data
    networks:
      - prs_network

  nginx:
    image: nginx:alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - static_volume:/var/www/static:ro
      - media_volume:/var/www/media:ro
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - app
    networks:
      - prs_network

volumes:
  static_volume:
  media_volume:
  logs_volume:
  redis_volume:

networks:
  prs_network:
    driver: bridge
```

### 2. Kubernetes Deployment

#### Namespace and ConfigMap

```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: prs-production
  labels:
    name: prs-production
    environment: production

---
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: prs-config
  namespace: prs-production
data:
  DJANGO_SETTINGS_MODULE: "core_config.settings.production"
  DEBUG: "False"
  LOG_LEVEL: "INFO"
  GUNICORN_WORKERS: "4"
  GUNICORN_THREADS: "2"
  GUNICORN_TIMEOUT: "120"
```

#### Secrets

```yaml
# k8s/secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: prs-secrets
  namespace: prs-production
type: Opaque
stringData:
  SECRET_KEY: "your-secret-key"
  DATABASE_URL: "postgresql://user:pass@host:5432/db"
  REDIS_URL: "redis://host:6379/0"
  EMAIL_HOST_PASSWORD: "your-email-password"
  AWS_SECRET_ACCESS_KEY: "your-aws-secret"
  SENTRY_DSN: "https://your-sentry-dsn"
```

#### Application Deployment

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: prs-backend
  namespace: prs-production
  labels:
    app: prs-backend
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  selector:
    matchLabels:
      app: prs-backend
  template:
    metadata:
      labels:
        app: prs-backend
    spec:
      containers:
      - name: prs-backend
        image: your-registry.com/prs-backend:latest
        ports:
        - containerPort: 8000
        envFrom:
        - configMapRef:
            name: prs-config
        - secretRef:
            name: prs-secrets
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /api/health/
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 30
          timeoutSeconds: 10
        readinessProbe:
          httpGet:
            path: /api/health/
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 5
        volumeMounts:
        - name: static-storage
          mountPath: /app/staticfiles
        - name: media-storage
          mountPath: /app/media
      volumes:
      - name: static-storage
        persistentVolumeClaim:
          claimName: prs-static-pvc
      - name: media-storage
        persistentVolumeClaim:
          claimName: prs-media-pvc
      imagePullSecrets:
      - name: registry-secret

---
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: prs-backend-service
  namespace: prs-production
spec:
  selector:
    app: prs-backend
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8000
  type: ClusterIP

---
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: prs-backend-ingress
  namespace: prs-production
  annotations:
    kubernetes.io/ingress.class: "nginx"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
spec:
  tls:
  - hosts:
    - api.yourdomain.com
    secretName: prs-backend-tls
  rules:
  - host: api.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: prs-backend-service
            port:
              number: 80
```

### 3. Zero-Downtime Deployment Script

```bash
#!/bin/bash
# deploy-production.sh

set -e

# Configuration
REGISTRY="your-registry.com"
IMAGE_NAME="prs-backend"
NAMESPACE="prs-production"
DEPLOYMENT_NAME="prs-backend"
TIMEOUT=600

# Get version from git or parameter
VERSION=${1:-$(git rev-parse --short HEAD)}
NEW_IMAGE="$REGISTRY/$IMAGE_NAME:$VERSION"

echo "🚀 Starting zero-downtime deployment"
echo "📦 Deploying image: $NEW_IMAGE"
echo "🎯 Target: $NAMESPACE/$DEPLOYMENT_NAME"

# Verify image exists
echo "🔍 Verifying image exists..."
docker manifest inspect $NEW_IMAGE > /dev/null || {
    echo "❌ Image $NEW_IMAGE not found in registry"
    exit 1
}

# Check cluster connection
kubectl cluster-info > /dev/null || {
    echo "❌ Cannot connect to Kubernetes cluster"
    exit 1
}

# Backup current deployment
echo "💾 Backing up current deployment..."
kubectl get deployment $DEPLOYMENT_NAME -n $NAMESPACE -o yaml > \
    "backup-deployment-$(date +%Y%m%d_%H%M%S).yaml"

# Update deployment image
echo "📦 Updating deployment image..."
kubectl set image deployment/$DEPLOYMENT_NAME \
    prs-backend=$NEW_IMAGE \
    -n $NAMESPACE

# Wait for rollout to complete
echo "⏳ Waiting for rollout to complete..."
kubectl rollout status deployment/$DEPLOYMENT_NAME \
    -n $NAMESPACE \
    --timeout=${TIMEOUT}s

# Verify deployment
echo "✅ Verifying deployment health..."
kubectl get pods -n $NAMESPACE -l app=prs-backend

# Wait for all pods to be ready
kubectl wait --for=condition=ready pod \
    -l app=prs-backend \
    -n $NAMESPACE \
    --timeout=300s

# Test endpoint
echo "🧪 Testing deployed application..."
INGRESS_IP=$(kubectl get ingress prs-backend-ingress -n $NAMESPACE -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
curl -f https://api.yourdomain.com/api/health/ || {
    echo "❌ Health check failed"
    echo "🔄 Rolling back deployment..."
    kubectl rollout undo deployment/$DEPLOYMENT_NAME -n $NAMESPACE
    exit 1
}

echo "✅ Deployment completed successfully!"
echo "🎉 Version $VERSION is now live"

# Clean up old replica sets (keep last 3)
echo "🧹 Cleaning up old replica sets..."
kubectl get rs -n $NAMESPACE -o name | \
    grep prs-backend | \
    tail -n +4 | \
    xargs kubectl delete -n $NAMESPACE || true

echo "✅ Deployment and cleanup completed"
```

---

## 🛡️ Security Configuration

### 1. SSL/TLS Configuration

#### Nginx SSL Configuration

```nginx
# nginx/nginx.conf
upstream prs_backend {
    server app:8000;
}

server {
    listen 80;
    server_name api.yourdomain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;

    # SSL Configuration
    ssl_certificate /etc/nginx/ssl/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy "strict-origin-when-cross-origin";

    # Rate Limiting
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
    limit_req_zone $binary_remote_addr zone=api:10m rate=100r/m;

    # Client settings
    client_max_body_size 10M;
    client_body_timeout 60s;
    client_header_timeout 60s;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml;

    # API endpoints
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        
        proxy_pass http://prs_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Buffer settings
        proxy_buffering on;
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;
    }

    # Authentication endpoints (stricter rate limiting)
    location /api/auth/login/ {
        limit_req zone=login burst=5 nodelay;
        proxy_pass http://prs_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Static files
    location /static/ {
        alias /var/www/static/;
        expires 1y;
        add_header Cache-Control "public, no-transform";
    }

    # Media files
    location /media/ {
        alias /var/www/media/;
        expires 30d;
        add_header Cache-Control "public, no-transform";
    }

    # Health check
    location /api/health/ {
        proxy_pass http://prs_backend;
        access_log off;
    }
}
```

### 2. Django Security Settings

```python
# core_config/settings/production.py
import os
from .base import *

# Security Settings
DEBUG = False
ALLOWED_HOSTS = ['api.yourdomain.com', 'yourdomain.com']

# HTTPS Settings
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# CSRF Settings
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Strict'
CSRF_TRUSTED_ORIGINS = ['https://api.yourdomain.com', 'https://yourdomain.com']

# Session Settings
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_COOKIE_AGE = 86400  # 24 hours

# Content Security Policy
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'", "'unsafe-inline'")
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")
CSP_IMG_SRC = ("'self'", "data:", "https:")

# Database Security
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv('DB_NAME'),
        'USER': os.getenv('DB_USER'),
        'PASSWORD': os.getenv('DB_PASSWORD'),
        'HOST': os.getenv('DB_HOST'),
        'PORT': os.getenv('DB_PORT', '5432'),
        'CONN_MAX_AGE': 600,
        'OPTIONS': {
            'sslmode': 'require',
            'connect_timeout': 10,
        },
    }
}

# Logging Configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'json': {
            'format': '{"level": "%(levelname)s", "time": "%(asctime)s", "module": "%(module)s", "message": "%(message)s"}',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/app/logs/django.log',
            'maxBytes': 10485760,  # 10MB
            'backupCount': 10,
            'formatter': 'json',
        },
        'security': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/app/logs/security.log',
            'maxBytes': 10485760,  # 10MB
            'backupCount': 10,
            'formatter': 'json',
        },
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': True,
        },
        'security': {
            'handlers': ['security'],
            'level': 'INFO',
            'propagate': False,
        },
        'prs': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': True,
        },
    },
}
```

---

## 📊 Monitoring and Logging

### 1. Application Monitoring Setup

#### Prometheus Configuration

```yaml
# monitoring/prometheus.yml
global:
  scrape_interval: 15s

rule_files:
  - "alert_rules.yml"

scrape_configs:
  - job_name: 'prs-backend'
    static_configs:
      - targets: ['app:8000']
    metrics_path: '/metrics/'
    scrape_interval: 30s

  - job_name: 'nginx'
    static_configs:
      - targets: ['nginx:9113']

  - job_name: 'postgres-exporter'
    static_configs:
      - targets: ['postgres-exporter:9187']

  - job_name: 'redis-exporter'
    static_configs:
      - targets: ['redis-exporter:9121']

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
```

#### Alert Rules

```yaml
# monitoring/alert_rules.yml
groups:
  - name: prs-backend
    rules:
      - alert: HighErrorRate
        expr: rate(django_http_requests_total{status=~"5.."}[5m]) > 0.1
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ $value }} errors per second"

      - alert: HighResponseTime
        expr: histogram_quantile(0.95, rate(django_http_request_duration_seconds_bucket[5m])) > 1
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High response time"
          description: "95th percentile response time is {{ $value }} seconds"

      - alert: DatabaseConnectionsHigh
        expr: pg_stat_activity_count > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High database connection count"
          description: "Database has {{ $value }} active connections"

      - alert: DiskSpaceLow
        expr: (node_filesystem_avail_bytes / node_filesystem_size_bytes) * 100 < 10
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Low disk space"
          description: "Disk space is {{ $value }}% full"

      - alert: ServiceDown
        expr: up == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Service is down"
          description: "Service {{ $labels.job }} is down"
```

### 2. Log Aggregation

#### ELK Stack Configuration

```yaml
# logging/elasticsearch.yml
version: '3.8'

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.5.0
    environment:
      - discovery.type=single-node
      - "ES_JAVA_OPTS=-Xms1g -Xmx1g"
      - xpack.security.enabled=false
    volumes:
      - elasticsearch_data:/usr/share/elasticsearch/data
    ports:
      - "9200:9200"

  kibana:
    image: docker.elastic.co/kibana/kibana:8.5.0
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch

  logstash:
    image: docker.elastic.co/logstash/logstash:8.5.0
    volumes:
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf:ro
    ports:
      - "5044:5044"
    depends_on:
      - elasticsearch

volumes:
  elasticsearch_data:
```

#### Logstash Configuration

```ruby
# logging/logstash.conf
input {
  beats {
    port => 5044
  }
  
  file {
    path => "/app/logs/django.log"
    codec => "json"
    tags => ["django"]
  }
  
  file {
    path => "/app/logs/security.log"
    codec => "json"
    tags => ["security"]
  }
}

filter {
  if "django" in [tags] {
    mutate {
      add_field => { "service" => "prs-backend" }
    }
  }
  
  if "security" in [tags] {
    mutate {
      add_field => { "service" => "prs-security" }
      add_field => { "priority" => "high" }
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "prs-logs-%{+YYYY.MM.dd}"
  }
  
  if "security" in [tags] {
    elasticsearch {
      hosts => ["elasticsearch:9200"]
      index => "prs-security-%{+YYYY.MM.dd}"
    }
  }
}
```

---

## ✅ Post-Deployment Verification

### Automated Verification Script

```bash
#!/bin/bash
# verify-deployment.sh

set -e

BASE_URL=${1:-"https://api.yourdomain.com"}
TIMEOUT=30

echo "🧪 Starting post-deployment verification for $BASE_URL"

# Function to check HTTP endpoint
check_endpoint() {
    local endpoint=$1
    local expected_status=${2:-200}
    local description=$3
    
    echo -n "🔍 Testing $description... "
    
    status_code=$(curl -s -o /dev/null -w "%{http_code}" \
        --max-time $TIMEOUT \
        "$BASE_URL$endpoint" || echo "000")
    
    if [ "$status_code" = "$expected_status" ]; then
        echo "✅ OK ($status_code)"
        return 0
    else
        echo "❌ FAILED ($status_code, expected $expected_status)"
        return 1
    fi
}

# Function to check JSON response
check_json_endpoint() {
    local endpoint=$1
    local expected_key=$2
    local description=$3
    
    echo -n "🔍 Testing $description... "
    
    response=$(curl -s --max-time $TIMEOUT "$BASE_URL$endpoint" || echo "{}")
    
    if echo "$response" | jq -e ".$expected_key" > /dev/null 2>&1; then
        echo "✅ OK"
        return 0
    else
        echo "❌ FAILED (missing key: $expected_key)"
        echo "Response: $response"
        return 1
    fi
}

# Test basic endpoints
echo "📋 Testing basic endpoints..."
check_endpoint "/api/health/" 200 "Health check"
check_json_endpoint "/api/health/" "status" "Health check JSON"

# Test authentication endpoints
echo "📋 Testing authentication endpoints..."
check_endpoint "/api/auth/login/" 405 "Login endpoint (method not allowed for GET)"

# Test API documentation
echo "📋 Testing API documentation..."
check_endpoint "/swagger/" 200 "Swagger UI"
check_endpoint "/redoc/" 200 "ReDoc"

# Test static files
echo "📋 Testing static files..."
check_endpoint "/static/admin/css/base.css" 200 "Django admin CSS"

# Test HTTPS redirect (if testing HTTP)
if [[ $BASE_URL == http* ]]; then
    echo "📋 Testing HTTPS redirect..."
    http_url=$(echo $BASE_URL | sed 's/https/http/')
    redirect_location=$(curl -s -o /dev/null -w "%{redirect_url}" \
        --max-redirs 0 "$http_url/api/health/" || echo "")
    
    if [[ $redirect_location == https* ]]; then
        echo "✅ HTTPS redirect working"
    else
        echo "⚠️  HTTPS redirect not configured"
    fi
fi

# Test database connectivity
echo "📋 Testing database connectivity..."
response=$(curl -s --max-time $TIMEOUT "$BASE_URL/api/health/" || echo "{}")
if echo "$response" | jq -e '.database' > /dev/null 2>&1; then
    db_status=$(echo "$response" | jq -r '.database')
    if [ "$db_status" = "ok" ]; then
        echo "✅ Database connectivity OK"
    else
        echo "❌ Database connectivity FAILED"
        exit 1
    fi
fi

# Test cache connectivity
if echo "$response" | jq -e '.cache' > /dev/null 2>&1; then
    cache_status=$(echo "$response" | jq -r '.cache')
    if [ "$cache_status" = "ok" ]; then
        echo "✅ Cache connectivity OK"
    else
        echo "⚠️  Cache connectivity issues"
    fi
fi

# Performance test
echo "📋 Running basic performance test..."
response_time=$(curl -s -o /dev/null -w "%{time_total}" \
    --max-time $TIMEOUT "$BASE_URL/api/health/")

if (( $(echo "$response_time < 2.0" | bc -l) )); then
    echo "✅ Response time OK (${response_time}s)"
else
    echo "⚠️  Slow response time (${response_time}s)"
fi

# SSL certificate check (for HTTPS)
if [[ $BASE_URL == https* ]]; then
    echo "📋 Testing SSL certificate..."
    domain=$(echo $BASE_URL | sed 's|https://||' | sed 's|/.*||')
    
    expiry=$(echo | openssl s_client -servername $domain -connect $domain:443 2>/dev/null | \
             openssl x509 -noout -dates | grep notAfter | cut -d= -f2)
    
    expiry_timestamp=$(date -d "$expiry" +%s 2>/dev/null || echo "0")
    current_timestamp=$(date +%s)
    days_until_expiry=$(( (expiry_timestamp - current_timestamp) / 86400 ))
    
    if [ $days_until_expiry -gt 30 ]; then
        echo "✅ SSL certificate valid ($days_until_expiry days remaining)"
    elif [ $days_until_expiry -gt 0 ]; then
        echo "⚠️  SSL certificate expires soon ($days_until_expiry days remaining)"
    else
        echo "❌ SSL certificate expired"
        exit 1
    fi
fi

echo "✅ All verification tests completed successfully!"
echo "🎉 Deployment verification PASSED"
```

---

## 🔄 Rollback Procedures

### Automated Rollback Script

```bash
#!/bin/bash
# rollback-deployment.sh

set -e

NAMESPACE=${1:-"prs-production"}
DEPLOYMENT_NAME=${2:-"prs-backend"}
ROLLBACK_TO=${3:-"previous"}

echo "🔄 Starting rollback procedure..."
echo "🎯 Target: $NAMESPACE/$DEPLOYMENT_NAME"
echo "📦 Rollback to: $ROLLBACK_TO"

# Check current rollout status
echo "📋 Current deployment status:"
kubectl rollout status deployment/$DEPLOYMENT_NAME -n $NAMESPACE --timeout=10s || true

# Show rollout history
echo "📜 Deployment history:"
kubectl rollout history deployment/$DEPLOYMENT_NAME -n $NAMESPACE

# Perform rollback
if [ "$ROLLBACK_TO" = "previous" ]; then
    echo "🔄 Rolling back to previous revision..."
    kubectl rollout undo deployment/$DEPLOYMENT_NAME -n $NAMESPACE
else
    echo "🔄 Rolling back to revision $ROLLBACK_TO..."
    kubectl rollout undo deployment/$DEPLOYMENT_NAME -n $NAMESPACE --to-revision=$ROLLBACK_TO
fi

# Wait for rollback to complete
echo "⏳ Waiting for rollback to complete..."
kubectl rollout status deployment/$DEPLOYMENT_NAME -n $NAMESPACE --timeout=600s

# Verify rollback
echo "✅ Verifying rollback..."
kubectl get pods -n $NAMESPACE -l app=prs-backend

# Wait for all pods to be ready
kubectl wait --for=condition=ready pod \
    -l app=prs-backend \
    -n $NAMESPACE \
    --timeout=300s

# Test endpoint
echo "🧪 Testing rolled back application..."
./verify-deployment.sh https://api.yourdomain.com || {
    echo "❌ Rollback verification failed"
    exit 1
}

echo "✅ Rollback completed successfully!"

# Send notification
echo "📧 Sending rollback notification..."
curl -X POST "https://hooks.slack.com/your-webhook-url" \
    -H 'Content-type: application/json' \
    --data "{
        \"text\": \"🔄 PRS Backend rolled back successfully in $NAMESPACE\",
        \"blocks\": [
            {
                \"type\": \"section\",
                \"text\": {
                    \"type\": \"mrkdwn\",
                    \"text\": \"*PRS Backend Rollback Completed*\n• Environment: $NAMESPACE\n• Deployment: $DEPLOYMENT_NAME\n• Status: ✅ Success\"
                }
            }
        ]
    }" || echo "Failed to send notification"
```

---

## 🚨 Troubleshooting

### Common Issues and Solutions

#### 1. Application Won't Start

```bash
# Check pod logs
kubectl logs -f deployment/prs-backend -n prs-production

# Check for common issues:
# - Environment variables missing
# - Database connection issues
# - Image pull errors
# - Resource constraints

# Debug pod
kubectl exec -it deployment/prs-backend -n prs-production -- /bin/bash

# Check Django configuration
python manage.py check --deploy
python manage.py check --database
```

#### 2. Database Connection Issues

```bash
# Test database connection
kubectl exec -it deployment/prs-backend -n prs-production -- \
    python manage.py dbshell --command="SELECT version();"

# Check database credentials
kubectl get secret prs-secrets -n prs-production -o yaml

# Verify network connectivity
kubectl exec -it deployment/prs-backend -n prs-production -- \
    nc -zv your-db-host 5432
```

#### 3. Performance Issues

```bash
# Check resource usage
kubectl top pods -n prs-production

# Check for CPU/memory limits
kubectl describe deployment prs-backend -n prs-production

# Check database performance
kubectl exec -it deployment/prs-backend -n prs-production -- \
    python manage.py shell << EOF
from django.db import connection
print(connection.queries)
EOF
```

#### 4. SSL/TLS Issues

```bash
# Test SSL certificate
openssl s_client -servername api.yourdomain.com -connect api.yourdomain.com:443

# Check certificate expiry
echo | openssl s_client -servername api.yourdomain.com -connect api.yourdomain.com:443 2>/dev/null | \
    openssl x509 -noout -dates

# Test from inside cluster
kubectl exec -it deployment/prs-backend -n prs-production -- \
    curl -I https://api.yourdomain.com/api/health/
```

### Emergency Procedures

#### 1. Complete Service Outage

```bash
#!/bin/bash
# emergency-response.sh

echo "🚨 EMERGENCY: Service outage detected"

# Scale down to 0 replicas (maintenance mode)
kubectl scale deployment prs-backend --replicas=0 -n prs-production

# Enable maintenance page (via nginx config update)
kubectl create configmap maintenance-config --from-file=maintenance.conf -n prs-production
kubectl patch deployment nginx -n prs-production -p '{"spec":{"template":{"spec":{"containers":[{"name":"nginx","env":[{"name":"MAINTENANCE_MODE","value":"true"}]}]}}}}'

# Investigate issues
kubectl get events -n prs-production --sort-by='.lastTimestamp'
kubectl logs -f deployment/prs-backend -n prs-production --previous

# When ready, scale back up
# kubectl scale deployment prs-backend --replicas=3 -n prs-production
```

#### 2. Data Recovery

```bash
#!/bin/bash
# data-recovery.sh

BACKUP_DATE=${1:-$(date -d "yesterday" +%Y%m%d)}

echo "🔄 Starting data recovery for $BACKUP_DATE"

# Stop application
kubectl scale deployment prs-backend --replicas=0 -n prs-production

# Restore database from backup
aws s3 cp s3://prs-backups/database/prs_production_${BACKUP_DATE}*.backup /tmp/restore.backup

# Restore database
pg_restore -h your-db-host -U prs_admin -d prs_production --clean --if-exists /tmp/restore.backup

# Run migrations to ensure schema is current
kubectl run migration-job --rm -i --tty \
    --image=your-registry.com/prs-backend:latest \
    --env="DJANGO_SETTINGS_MODULE=core_config.settings.production" \
    --command -- python manage.py migrate

# Scale application back up
kubectl scale deployment prs-backend --replicas=3 -n prs-production

echo "✅ Data recovery completed"
```

---

This comprehensive production deployment guide provides all the necessary procedures, scripts, and configurations for successfully deploying and maintaining the PRS backend in production environments. The documentation includes security best practices, monitoring setup, and emergency procedures to ensure reliable and secure operations.
