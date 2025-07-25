# Deployment Guide - Backend_PRS

## Overview

This guide provides comprehensive instructions for deploying the Backend_PRS Payment Receiving System to various environments. The system is designed to be deployed on cloud platforms with support for both staging and production environments.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Environment Setup](#environment-setup)
3. [Render.com Deployment](#rendercom-deployment)
4. [Docker Deployment](#docker-deployment)
5. [AWS Deployment](#aws-deployment)
6. [Manual Server Deployment](#manual-server-deployment)
7. [Database Setup](#database-setup)
8. [Environment Variables](#environment-variables)
9. [Security Configuration](#security-configuration)
10. [Monitoring and Logging](#monitoring-and-logging)
11. [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements
- Python 3.8+
- PostgreSQL 12+
- Redis 6+
- Node.js 16+ (for frontend builds)
- Git

### Required Accounts
- Cloud platform account (Render, AWS, etc.)
- Database hosting (managed PostgreSQL)
- Redis hosting (managed Redis)
- Email service (Gmail, SendGrid, etc.)
- Cloudinary account (for media storage)

## Environment Setup

### 1. Environment Variables

Create a `.env` file with the following variables:

```env
# Django Settings
SECRET_KEY=your-super-secret-key-here
DEBUG=False
ALLOWED_HOSTS=your-domain.com,www.your-domain.com

# Database Configuration
DATABASE_URL=postgresql://user:password@host:port/database
DB_NAME=prs_production
DB_USER=prs_user
DB_PASSWORD=secure_password
DB_HOST=your-db-host.com
DB_PORT=5432

# Redis Configuration
REDIS_URL=redis://user:password@host:port/db

# Email Configuration
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password
EMAIL_USE_TLS=True
DEFAULT_FROM_EMAIL=noreply@your-domain.com

# Cloudinary Configuration
CLOUDINARY_CLOUD_NAME=your-cloud-name
CLOUDINARY_API_KEY=your-api-key
CLOUDINARY_API_SECRET=your-api-secret

# Security Settings
CSRF_TRUSTED_ORIGINS=https://your-domain.com,https://www.your-domain.com
CORS_ALLOWED_ORIGINS=https://your-frontend-domain.com

# Admin Configuration
ADMIN_USER=admin@your-domain.com
ADMIN_PASS=secure_admin_password
ADMIN_EMAIL=admin@your-domain.com
```

### 2. Dependencies

Ensure all dependencies are in `requirements.txt`:

```txt
Django==5.2.2
djangorestframework==3.15.2
psycopg2-binary==2.9.9
django-cors-headers==4.4.0
django-environ==0.11.2
gunicorn==23.0.0
whitenoise==6.7.0
redis==5.0.8
django-redis==5.4.0
cloudinary==1.40.0
drf-yasg==1.21.7
channels==4.0.0
daphne==4.0.0
```

## Render.com Deployment

### 1. Repository Setup

```bash
# Clone repository
git clone https://github.com/your-username/Backend_PRS.git
cd Backend_PRS

# Ensure render.yaml is configured
```

### 2. Render Configuration

Create `render.yaml` in project root:

```yaml
services:
  # Web Service
  - type: web
    name: backend-prs
    env: python
    region: oregon
    plan: starter
    buildCommand: "./render-build.sh"
    startCommand: "./render-start-safe.sh"
    envVars:
      - key: PYTHON_VERSION
        value: 3.11.0
      - key: DATABASE_URL
        fromDatabase:
          name: prs-database
          property: connectionString
      - key: REDIS_URL
        fromService:
          type: redis
          name: prs-redis
          property: connectionString
      - key: SECRET_KEY
        generateValue: true
      - key: DEBUG
        value: "False"

  # Database
  - type: database
    name: prs-database
    databaseName: prs_production
    user: prs_user
    region: oregon
    plan: starter

  # Redis
  - type: redis
    name: prs-redis
    region: oregon
    plan: starter
```

### 3. Build Script (`render-build.sh`)

```bash
#!/usr/bin/env bash
# Build script for Render

set -o errexit  # Exit on error

echo "🚀 Starting Render build process..."

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Collect static files
echo "🔧 Collecting static files..."
python manage.py collectstatic --noinput

# Run database migrations
echo "🗄️ Running database migrations..."
python manage.py migrate

# Create superuser if it doesn't exist
echo "👤 Setting up admin user..."
python manage.py shell << EOF
from django.contrib.auth import get_user_model
from django.conf import settings
import os

User = get_user_model()
email = os.environ.get('ADMIN_EMAIL', 'admin@example.com')
password = os.environ.get('ADMIN_PASS', 'admin123')

if not User.objects.filter(email=email).exists():
    User.objects.create_superuser(
        email=email,
        password=password,
        first_name='Admin',
        last_name='User'
    )
    print(f"✅ Created superuser: {email}")
else:
    print(f"ℹ️ Superuser already exists: {email}")
EOF

echo "✅ Build process completed successfully!"
```

### 4. Start Script (`render-start-safe.sh`)

```bash
#!/usr/bin/env bash
# Safe start script for Render

set -o errexit  # Exit on error

echo "🚀 Starting Backend_PRS server..."

# Wait for database to be ready
echo "⏳ Waiting for database connection..."
python manage.py check --database default

# Initialize application data
echo "🔧 Initializing application..."
python manage.py shell << EOF
try:
    from authentication.management.commands.setup_permissions import Command
    Command().handle()
    print("✅ Permissions initialized")
except Exception as e:
    print(f"⚠️ Permission setup: {e}")
EOF

# Start the server
echo "🌐 Starting Gunicorn server..."
exec gunicorn \
    --bind 0.0.0.0:$PORT \
    --workers 2 \
    --threads 4 \
    --worker-class gthread \
    --worker-connections 1000 \
    --max-requests 1000 \
    --max-requests-jitter 100 \
    --timeout 30 \
    --keep-alive 5 \
    --access-logfile - \
    --error-logfile - \
    core_config.wsgi:application
```

### 5. Deploy to Render

```bash
# Push to GitHub
git add .
git commit -m "Deploy to Render"
git push origin main

# Connect repository in Render dashboard
# https://dashboard.render.com/
```

## Docker Deployment

### 1. Dockerfile

```dockerfile
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Set work directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Collect static files
RUN python manage.py collectstatic --noinput

# Create non-root user
RUN useradd --create-home --shell /bin/bash app
RUN chown -R app:app /app
USER app

# Expose port
EXPOSE 8000

# Run application
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "core_config.wsgi:application"]
```

### 2. Docker Compose

```yaml
version: '3.8'

services:
  db:
    image: postgres:15
    environment:
      POSTGRES_DB: prs_production
      POSTGRES_USER: prs_user
      POSTGRES_PASSWORD: secure_password
    volumes:
      - postgres_data:/var/lib/postgresql/data/
    ports:
      - "5432:5432"

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  web:
    build: .
    command: gunicorn --bind 0.0.0.0:8000 core_config.wsgi:application
    volumes:
      - .:/app
    ports:
      - "8000:8000"
    depends_on:
      - db
      - redis
    environment:
      - DEBUG=False
      - DATABASE_URL=postgresql://prs_user:secure_password@db:5432/prs_production
      - REDIS_URL=redis://redis:6379
      - SECRET_KEY=your-secret-key

volumes:
  postgres_data:
```

### 3. Deploy with Docker

```bash
# Build and run
docker-compose up --build -d

# Run migrations
docker-compose exec web python manage.py migrate

# Create superuser
docker-compose exec web python manage.py createsuperuser

# View logs
docker-compose logs -f web
```

## AWS Deployment

### 1. Elastic Beanstalk

Create `.ebextensions/django.config`:

```yaml
option_settings:
  aws:elasticbeanstalk:container:python:
    WSGIPath: core_config.wsgi:application
  aws:elasticbeanstalk:environment:proxy:staticfiles:
    /static: static

container_commands:
  01_migrate:
    command: "python manage.py migrate"
  02_collectstatic:
    command: "python manage.py collectstatic --noinput"
  03_setup_permissions:
    command: "python manage.py setup_permissions"
```

### 2. RDS Configuration

```bash
# Create RDS instance
aws rds create-db-instance \
    --db-instance-identifier prs-production \
    --db-instance-class db.t3.micro \
    --engine postgres \
    --master-username prs_user \
    --master-user-password secure_password \
    --allocated-storage 20 \
    --vpc-security-group-ids sg-xxxxxxxxx
```

### 3. ElastiCache for Redis

```bash
# Create ElastiCache cluster
aws elasticache create-cache-cluster \
    --cache-cluster-id prs-redis \
    --cache-node-type cache.t3.micro \
    --engine redis \
    --num-cache-nodes 1
```

### 4. Deploy to Elastic Beanstalk

```bash
# Initialize EB
eb init backend-prs

# Create environment
eb create production

# Deploy
eb deploy
```

## Manual Server Deployment

### 1. Server Setup (Ubuntu 20.04)

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y python3.11 python3.11-venv python3-pip postgresql postgresql-contrib redis-server nginx

# Create app user
sudo useradd --create-home --shell /bin/bash prs
sudo usermod -aG sudo prs

# Switch to app user
sudo su - prs
```

### 2. Application Setup

```bash
# Clone repository
git clone https://github.com/your-username/Backend_PRS.git
cd Backend_PRS

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env with production values

# Run migrations
python manage.py migrate
python manage.py collectstatic
python manage.py setup_permissions
```

### 3. Gunicorn Configuration

Create `/etc/systemd/system/prs.service`:

```ini
[Unit]
Description=Backend_PRS gunicorn daemon
After=network.target

[Service]
User=prs
Group=www-data
WorkingDirectory=/home/prs/Backend_PRS
ExecStart=/home/prs/Backend_PRS/venv/bin/gunicorn \
    --access-logfile - \
    --workers 3 \
    --bind unix:/run/gunicorn.sock \
    core_config.wsgi:application

[Install]
WantedBy=multi-user.target
```

### 4. Nginx Configuration

Create `/etc/nginx/sites-available/prs`:

```nginx
server {
    listen 80;
    server_name your-domain.com www.your-domain.com;

    location = /favicon.ico { access_log off; log_not_found off; }
    
    location /static/ {
        root /home/prs/Backend_PRS;
    }
    
    location /media/ {
        root /home/prs/Backend_PRS;
    }

    location / {
        include proxy_params;
        proxy_pass http://unix:/run/gunicorn.sock;
    }
}
```

### 5. SSL Setup with Let's Encrypt

```bash
# Install certbot
sudo apt install certbot python3-certbot-nginx

# Obtain SSL certificate
sudo certbot --nginx -d your-domain.com -d www.your-domain.com

# Test renewal
sudo certbot renew --dry-run
```

## Database Setup

### 1. PostgreSQL Configuration

```sql
-- Create database and user
CREATE USER prs_user WITH PASSWORD 'secure_password';
CREATE DATABASE prs_production OWNER prs_user;
GRANT ALL PRIVILEGES ON DATABASE prs_production TO prs_user;

-- Configure for production
ALTER USER prs_user SET default_transaction_isolation TO 'read committed';
ALTER USER prs_user SET timezone TO 'UTC';
```

### 2. Database Optimization

```sql
-- Performance settings
ALTER SYSTEM SET shared_preload_libraries = 'pg_stat_statements';
ALTER SYSTEM SET pg_stat_statements.max = 10000;
ALTER SYSTEM SET pg_stat_statements.track = all;

-- Restart PostgreSQL
sudo systemctl restart postgresql
```

### 3. Backup Strategy

```bash
# Daily backup script
#!/bin/bash
BACKUP_DIR="/home/prs/backups"
DB_NAME="prs_production"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Create backup
pg_dump -h localhost -U prs_user $DB_NAME | gzip > $BACKUP_DIR/backup_$DATE.sql.gz

# Keep only last 7 days
find $BACKUP_DIR -name "backup_*.sql.gz" -mtime +7 -delete

# Add to crontab
# 0 2 * * * /home/prs/backup.sh
```

## Security Configuration

### 1. Firewall Setup

```bash
# Configure UFW
sudo ufw allow ssh
sudo ufw allow 'Nginx Full'
sudo ufw allow 5432  # PostgreSQL (if external)
sudo ufw enable
```

### 2. Security Headers

In `settings.py`:

```python
# Security settings
SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = 'DENY'
```

### 3. Rate Limiting

```python
# Rate limiting configuration
RATELIMIT_ENABLE = True
RATELIMIT_USE_CACHE = 'default'

# In views
from django_ratelimit.decorators import ratelimit

@ratelimit(key='ip', rate='5/m', method='POST')
def login_view(request):
    pass
```

## Monitoring and Logging

### 1. Logging Configuration

```python
# Logging configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/var/log/prs/django.log',
            'maxBytes': 1024*1024*10,  # 10MB
            'backupCount': 5,
            'formatter': 'verbose',
        },
        'security_file': {
            'level': 'WARNING',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/var/log/prs/security.log',
            'maxBytes': 1024*1024*10,
            'backupCount': 5,
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': True,
        },
        'security': {
            'handlers': ['security_file'],
            'level': 'WARNING',
            'propagate': True,
        },
    },
}
```

### 2. Health Check Endpoint

```python
# health_check/views.py
from django.http import JsonResponse
from django.db import connection

def health_check(request):
    try:
        # Check database
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        
        # Check Redis
        from django.core.cache import cache
        cache.set('health_check', 'ok', 30)
        
        return JsonResponse({
            'status': 'healthy',
            'database': 'ok',
            'cache': 'ok',
            'timestamp': timezone.now().isoformat()
        })
    except Exception as e:
        return JsonResponse({
            'status': 'unhealthy',
            'error': str(e)
        }, status=500)
```

### 3. Monitoring with Prometheus

```yaml
# docker-compose.monitoring.yml
version: '3.8'

services:
  prometheus:
    image: prom/prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml

  grafana:
    image: grafana/grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
```

## Troubleshooting

### 1. Common Issues

#### Database Connection Issues
```bash
# Check database connection
python manage.py check --database default

# Check PostgreSQL logs
sudo tail -f /var/log/postgresql/postgresql-15-main.log

# Test connection manually
psql -h localhost -U prs_user -d prs_production
```

#### Static Files Issues
```bash
# Collect static files
python manage.py collectstatic --noinput

# Check Nginx configuration
sudo nginx -t
sudo systemctl restart nginx
```

#### Permission Issues
```bash
# Check file permissions
ls -la /home/prs/Backend_PRS/
sudo chown -R prs:www-data /home/prs/Backend_PRS/

# Check service logs
sudo journalctl -u prs.service -f
```

### 2. Performance Issues

```bash
# Check database performance
python manage.py shell
>>> from django.db import connection
>>> print(connection.queries)

# Check Redis performance
redis-cli info stats

# Monitor system resources
htop
iotop
```

### 3. Debugging Steps

1. **Check logs**: Always start with application and system logs
2. **Verify configuration**: Ensure all environment variables are set
3. **Test connectivity**: Verify database and Redis connections
4. **Check permissions**: Ensure proper file and directory permissions
5. **Monitor resources**: Check CPU, memory, and disk usage

### 4. Rollback Strategy

```bash
# Keep previous version
cp -r Backend_PRS Backend_PRS.backup

# Quick rollback
sudo systemctl stop prs
mv Backend_PRS.backup Backend_PRS
sudo systemctl start prs

# Database rollback (if needed)
psql -h localhost -U prs_user -d prs_production < backup_previous.sql
```

## Post-Deployment Checklist

- [ ] Application starts without errors
- [ ] Database migrations applied successfully
- [ ] Static files served correctly
- [ ] SSL certificate installed and working
- [ ] Admin user created and accessible
- [ ] API endpoints responding correctly
- [ ] Email notifications working
- [ ] File uploads functioning
- [ ] Monitoring and logging configured
- [ ] Backup strategy implemented
- [ ] Security headers configured
- [ ] Rate limiting active
- [ ] Health check endpoint responding

## Maintenance

### 1. Regular Updates

```bash
# Update dependencies
pip install --upgrade -r requirements.txt

# Update system packages
sudo apt update && sudo apt upgrade

# Database maintenance
python manage.py clearsessions
VACUUM ANALYZE;
```

### 2. Log Rotation

```bash
# Configure logrotate
sudo tee /etc/logrotate.d/prs << EOF
/var/log/prs/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 644 prs prs
    postrotate
        systemctl reload prs
    endscript
}
EOF
```

### 3. Monitoring Scripts

```bash
# Disk space monitoring
#!/bin/bash
USAGE=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
if [ $USAGE -gt 80 ]; then
    echo "Disk usage is above 80%: $USAGE%" | mail -s "Disk Space Alert" admin@your-domain.com
fi
```

This deployment guide provides comprehensive instructions for deploying Backend_PRS in various environments. Choose the deployment method that best fits your infrastructure and requirements.