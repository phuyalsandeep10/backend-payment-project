# Deployment Guide

## Overview
This guide covers the deployment of the Property Reservation System (PRS) Django backend. The system is designed for production deployment with PostgreSQL, security features, and email functionality.

## System Requirements

### Server Requirements
- **OS**: Linux (Ubuntu 20.04+ recommended) or Windows Server
- **Python**: 3.8+ (3.11+ recommended)
- **Memory**: Minimum 2GB RAM (4GB+ recommended)
- **Storage**: Minimum 10GB free space
- **Database**: PostgreSQL 12+ (or SQLite for development)

### Dependencies
See `requirements.txt` for complete list:
- Django 5.2.2
- djangorestframework 3.15.2
- psycopg2-binary 2.9.9
- gunicorn 23.0.0
- whitenoise 6.7.0
- Other supporting packages

## Pre-Deployment Setup

### 1. Environment Variables
Create a `.env` file in the backend directory with the following variables:

```bash
# Core Settings
SECRET_KEY=your-very-secret-key-here
DEBUG=False
ALLOWED_HOSTS=your-domain.com,www.your-domain.com

# Database Configuration
DB_NAME=prs_database
DB_USER=prs_user
DB_PASSWORD=your-secure-database-password
DB_HOST=localhost
DB_PORT=5432

# Email Configuration
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@domain.com
EMAIL_HOST_PASSWORD=your-email-password
DEFAULT_FROM_EMAIL=PRS System <your-email@domain.com>
SUPER_ADMIN_OTP_EMAIL=admin@your-domain.com

# CORS Configuration
CORS_ALLOW_ALL_ORIGINS=False
CORS_ALLOWED_ORIGINS=https://your-frontend-domain.com,https://www.your-frontend-domain.com

# Admin User (for setup command)
ADMIN_USER=admin
ADMIN_EMAIL=admin@your-domain.com
ADMIN_PASS=secure-admin-password
```

### 2. Database Setup

#### PostgreSQL Installation (Ubuntu)
```bash
sudo apt update
sudo apt install postgresql postgresql-contrib
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

#### Database Creation
```bash
sudo -u postgres psql
CREATE DATABASE prs_database;
CREATE USER prs_user WITH PASSWORD 'your-secure-database-password';
GRANT ALL PRIVILEGES ON DATABASE prs_database TO prs_user;
ALTER USER prs_user CREATEDB;
\q
```

### 3. Application Setup

#### Clone and Install
```bash
git clone <your-repository-url>
cd Backend_PRS-1/backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

#### Database Migration
```bash
python manage.py makemigrations
python manage.py migrate
```

#### Create Superuser
```bash
python manage.py setup_superadmin
```

#### Collect Static Files
```bash
python manage.py collectstatic --noinput
```

## Production Deployment

### Option 1: Gunicorn + Nginx

#### 1. Gunicorn Configuration
Create `gunicorn.conf.py`:
```python
bind = "127.0.0.1:8000"
workers = 3
worker_class = "sync"
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 100
timeout = 30
keepalive = 5
user = "www-data"
group = "www-data"
tmp_upload_dir = None
errorlog = "/var/log/gunicorn/error.log"
accesslog = "/var/log/gunicorn/access.log"
loglevel = "info"
```

#### 2. Systemd Service
Create `/etc/systemd/system/prs-backend.service`:
```ini
[Unit]
Description=PRS Backend Django Application
After=network.target

[Service]
Type=notify
User=www-data
Group=www-data
WorkingDirectory=/path/to/Backend_PRS-1/backend
Environment=PATH=/path/to/Backend_PRS-1/backend/venv/bin
ExecStart=/path/to/Backend_PRS-1/backend/venv/bin/gunicorn core_config.wsgi:application --config gunicorn.conf.py
ExecReload=/bin/kill -s HUP $MAINPID
Restart=on-failure
KillMode=mixed
TimeoutStopSec=5
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable prs-backend
sudo systemctl start prs-backend
```

#### 3. Nginx Configuration
Create `/etc/nginx/sites-available/prs-backend`:
```nginx
upstream prs_backend {
    server 127.0.0.1:8000;
}

server {
    listen 80;
    server_name your-domain.com www.your-domain.com;
    
    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com www.your-domain.com;
    
    # SSL Configuration (use Let's Encrypt or your certificates)
    ssl_certificate /path/to/your/certificate.pem;
    ssl_certificate_key /path/to/your/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    ssl_prefer_server_ciphers off;
    
    # Security Headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy "strict-origin-when-cross-origin";
    add_header Content-Security-Policy "default-src 'self'";
    
    # Upload Size
    client_max_body_size 5M;
    
    # Static Files
    location /static/ {
        alias /path/to/Backend_PRS-1/backend/staticfiles/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    # Media Files (Receipts)
    location /media/ {
        alias /path/to/Backend_PRS-1/backend/media/;
        expires 1y;
        add_header Cache-Control "private";
    }
    
    # API Endpoints
    location / {
        proxy_pass http://prs_backend;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }
}
```

Enable the site:
```bash
sudo ln -s /etc/nginx/sites-available/prs-backend /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### Option 2: Docker Deployment

#### Dockerfile
```dockerfile
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        postgresql-client \
        gcc \
        python3-dev \
        musl-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt /app/
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy project
COPY . /app/

# Create user
RUN adduser --disabled-password --gecos '' appuser
RUN chown -R appuser:appuser /app
USER appuser

# Collect static files
RUN python manage.py collectstatic --noinput

# Expose port
EXPOSE 8000

# Run gunicorn
CMD ["gunicorn", "core_config.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3"]
```

#### docker-compose.yml
```yaml
version: '3.8'

services:
  db:
    image: postgres:15
    environment:
      POSTGRES_DB: prs_database
      POSTGRES_USER: prs_user
      POSTGRES_PASSWORD: your-secure-database-password
    volumes:
      - postgres_data:/var/lib/postgresql/data/
    networks:
      - prs_network

  backend:
    build: .
    command: gunicorn core_config.wsgi:application --bind 0.0.0.0:8000 --workers 3
    volumes:
      - .:/app
      - static_volume:/app/staticfiles
      - media_volume:/app/media
    ports:
      - "8000:8000"
    environment:
      - DEBUG=False
      - SECRET_KEY=your-very-secret-key-here
      - DB_HOST=db
      - DB_NAME=prs_database
      - DB_USER=prs_user
      - DB_PASSWORD=your-secure-database-password
    depends_on:
      - db
    networks:
      - prs_network

volumes:
  postgres_data:
  static_volume:
  media_volume:

networks:
  prs_network:
    driver: bridge
```

## Security Configuration

### 1. Production Settings
Ensure these settings in production:
```python
DEBUG = False
ALLOWED_HOSTS = ['your-domain.com', 'www.your-domain.com']
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True  # Enable with HTTPS
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SECURE = True  # Enable with HTTPS
```

### 2. SSL/TLS Certificate
Use Let's Encrypt for free SSL certificates:
```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com -d www.your-domain.com
```

### 3. Firewall Configuration
```bash
sudo ufw enable
sudo ufw allow 22/tcp  # SSH
sudo ufw allow 80/tcp  # HTTP
sudo ufw allow 443/tcp # HTTPS
```

## Monitoring and Logging

### 1. Log Files
- Application logs: `/var/log/gunicorn/`
- Security logs: `backend/logs/security.log`
- Nginx logs: `/var/log/nginx/`

### 2. Log Rotation
Configure logrotate for application logs:
```bash
sudo nano /etc/logrotate.d/prs-backend
```
```
/var/log/gunicorn/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 644 www-data www-data
    postrotate
        systemctl reload prs-backend
    endscript
}
```

### 3. Health Checks
Create a simple health check endpoint and monitor it:
```bash
# Add to crontab
*/5 * * * * curl -f http://localhost:8000/admin/ || echo "PRS Backend is down" | mail -s "Alert" admin@your-domain.com
```

## Backup Strategy

### 1. Database Backup
```bash
#!/bin/bash
# backup_db.sh
BACKUP_DIR="/backups/prs"
DATE=$(date +%Y%m%d_%H%M%S)
mkdir -p $BACKUP_DIR

pg_dump -h localhost -U prs_user -d prs_database > $BACKUP_DIR/prs_backup_$DATE.sql
find $BACKUP_DIR -name "*.sql" -mtime +7 -delete
```

### 2. Media Files Backup
```bash
#!/bin/bash
# backup_media.sh
rsync -av /path/to/Backend_PRS-1/backend/media/ /backups/prs/media/
```

### 3. Automated Backups
Add to crontab:
```bash
0 2 * * * /path/to/backup_db.sh
0 3 * * * /path/to/backup_media.sh
```

## Performance Optimization

### 1. Database Optimization
- Enable connection pooling
- Regular VACUUM and ANALYZE operations
- Index optimization for frequently queried fields

### 2. Caching
Consider implementing Redis for caching:
```python
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379/1',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }
    }
}
```

### 3. Static File Serving
Use CDN for static files in high-traffic scenarios.

## Troubleshooting

### Common Issues

#### 1. Database Connection Errors
- Check PostgreSQL service status
- Verify connection credentials
- Check firewall settings

#### 2. Permission Errors
- Ensure proper file permissions
- Check user/group ownership
- Verify directory access

#### 3. Email Delivery Issues
- Verify SMTP credentials
- Check firewall for email ports
- Review email logs

#### 4. Static Files Not Loading
- Run `collectstatic` command
- Check Nginx configuration
- Verify file permissions

### Debug Commands
```bash
# Check service status
sudo systemctl status prs-backend

# View logs
sudo journalctl -u prs-backend -f
tail -f /var/log/gunicorn/error.log

# Test database connection
python manage.py dbshell

# Check configuration
python manage.py check --deploy
```

## Updates and Maintenance

### 1. Application Updates
```bash
# Backup first
./backup_db.sh

# Pull latest changes
git pull origin main

# Install new dependencies
pip install -r requirements.txt

# Run migrations
python manage.py migrate

# Collect static files
python manage.py collectstatic --noinput

# Restart services
sudo systemctl restart prs-backend
sudo systemctl reload nginx
```

### 2. Security Updates
- Regularly update system packages
- Update Python dependencies
- Monitor security advisories

### 3. Monitoring
- Set up monitoring for system resources
- Monitor application performance
- Track error rates and response times

## Support and Documentation

For additional support:
- Check application logs for error details
- Review Django documentation for framework-specific issues
- Consult PostgreSQL documentation for database issues
- Review security best practices regularly

---

**Note**: Replace placeholder values (domains, passwords, paths) with your actual values before deployment. 