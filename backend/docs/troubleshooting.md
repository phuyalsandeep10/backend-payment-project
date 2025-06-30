# 🔍 Troubleshooting Guide

## Common Issues and Solutions

This guide helps you resolve common issues when working with the PRS Backend.

---

## 🚨 **STARTUP ISSUES**

### **1. Server Won't Start**

#### **Error: "Port already in use"**
```bash
# Find process using port 8000
# Windows
netstat -ano | findstr :8000

# macOS/Linux  
lsof -i :8000

# Kill the process or use different port
python manage.py runserver 8001
```

#### **Error: "No module named 'xyz'"**
```bash
# Ensure virtual environment is activated
# Windows
.venv\Scripts\activate

# macOS/Linux
source .venv/bin/activate

# Reinstall requirements
pip install -r requirements.txt
```

#### **Error: "ImproperlyConfigured: SECRET_KEY"**
```bash
# Check .env file exists and has SECRET_KEY
cat .env | grep SECRET_KEY

# Generate new secret key if needed
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

---

## 🗄️ **DATABASE ISSUES**

### **2. Database Connection Errors**

#### **Error: "OperationalError: no such table"**
```bash
# Run migrations
python manage.py migrate

# If still failing, reset migrations (DANGER - loses data)
python manage.py migrate --run-syncdb
```

#### **Error: "OperationalError: FATAL: database does not exist"**
```bash
# For PostgreSQL, create database
sudo -u postgres psql
CREATE DATABASE prs_production;
\q

# For SQLite, just run migrate (auto-creates)
python manage.py migrate
```

#### **Error: "OperationalError: FATAL: password authentication failed"**
```bash
# Check database credentials in .env
cat .env | grep DB_

# Test database connection manually
psql -h localhost -U prs_user -d prs_production
```

---

## 📧 **EMAIL ISSUES**

### **3. Email Not Sending**

#### **Error: "SMTPAuthenticationError"**
```bash
# For Gmail, ensure you're using App Password, not regular password
# Check email configuration
python manage.py shell
>>> from django.conf import settings
>>> print(f"Email host: {settings.EMAIL_HOST}")
>>> print(f"Email user: {settings.EMAIL_HOST_USER}")
```

#### **Error: "getaddrinfo failed" or Network Issues**
```bash
# Test email system directly
python -c "
from core_config.email_backend import EmailService
result = EmailService.test_email_connection()
print('Connection test:', result)
"

# Check if email appears in console (development mode)
# Look for email output in terminal when running runserver
```

#### **OTP Emails Not Received**
```bash
# Check spam folder
# Verify SUPER_ADMIN_OTP_EMAIL setting
python manage.py shell
>>> from django.conf import settings
>>> print(f"OTP email: {settings.SUPER_ADMIN_OTP_EMAIL}")

# Test OTP generation
>>> from authentication.views import SuperAdminLoginView
>>> otp = SuperAdminLoginView().generate_otp()
>>> print(f"Generated OTP: {otp}")
```

---

## 🔐 **AUTHENTICATION ISSUES**

### **4. Login Problems**

#### **Error: "Invalid credentials"**
```bash
# Check if user exists and is active
python manage.py shell
>>> from authentication.models import User
>>> user = User.objects.get(email='admin@example.com')
>>> print(f"Active: {user.is_active}, Superuser: {user.is_superuser}")

# Reset user password
>>> user.set_password('new_password')
>>> user.save()
```

#### **Error: "Rate limit exceeded"**
```bash
# Check rate limiting in logs
cat logs/security.log | grep "rate limit"

# Wait for rate limit to reset (usually 15-30 minutes)
# Or clear rate limit cache if using Redis
```

#### **Error: "OTP expired or not found"**
```bash
# Check OTP storage and expiration
python manage.py shell
>>> from django.core.cache import cache
>>> print("Cache keys:", cache._cache.keys() if hasattr(cache._cache, 'keys') else 'Unknown')

# Request new OTP by starting login process again
```

---

## 🌐 **API ISSUES**

### **5. API Not Responding**

#### **Error: "CORS policy blocked"**
```bash
# Check CORS configuration in .env
cat .env | grep CORS

# For development, temporarily allow all origins
CORS_ALLOW_ALL_ORIGINS=True

# For production, specify exact origins
CORS_ALLOWED_ORIGINS=https://your-frontend-domain.com
```

#### **Error: "404 Not Found" for API endpoints**
```bash
# Check URL configuration
python manage.py show_urls | grep api

# Verify API base URL includes /api/v1/
# Correct: http://localhost:8000/api/v1/auth/login/
# Wrong: http://localhost:8000/auth/login/
```

#### **Error: "500 Internal Server Error"**
```bash
# Check Django logs
tail -f logs/django.log

# Check for detailed error with DEBUG=True temporarily
# Add to .env: DEBUG=True
# Remove after debugging!
```

---

## 🔧 **PERMISSION ISSUES**

### **6. Access Denied Errors**

#### **Error: "Permission denied"**
```bash
# Check user permissions
python manage.py shell
>>> from authentication.models import User
>>> user = User.objects.get(email='user@example.com')
>>> print(f"Role: {user.role}")
>>> print(f"Permissions: {[p.codename for p in user.role.permissions.all()]}")
```

#### **Error: "Organization access denied"**
```bash
# Check user's organization
>>> user = User.objects.get(email='user@example.com')
>>> print(f"Organization: {user.organization}")
>>> print(f"Organization ID: {user.organization.id}")
```

---

## 🐳 **DOCKER ISSUES**

### **7. Docker Problems**

#### **Error: "Docker build failed"**
```bash
# Check Dockerfile syntax
docker build --no-cache -t prs-backend .

# Check for missing dependencies
docker run -it prs-backend /bin/bash
pip list
```

#### **Error: "Container exits immediately"**
```bash
# Check container logs
docker logs container_name

# Run container interactively
docker run -it prs-backend /bin/bash
```

---

## 📊 **PERFORMANCE ISSUES**

### **8. Slow Response Times**

#### **Database Query Optimization**
```bash
# Enable query logging temporarily
# Add to settings.py:
LOGGING = {
    'version': 1,
    'handlers': {
        'console': {
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

# Check for N+1 queries and optimize with select_related/prefetch_related
```

#### **Memory Usage**
```bash
# Monitor memory usage
# Linux
free -h
top -p $(pgrep python)

# Windows
tasklist | findstr python
```

---

## 🔍 **DEBUGGING TOOLS**

### **9. Useful Debug Commands**

#### **Django System Check**
```bash
# Check for common issues
python manage.py check

# Check specific apps
python manage.py check authentication
```

#### **Database Inspection**
```bash
# List all models
python manage.py shell
>>> from django.apps import apps
>>> for model in apps.get_models():
...     print(f"{model._meta.app_label}.{model.__name__}")

# Check migrations status
python manage.py showmigrations
```

#### **Cache Debugging**
```bash
# Clear cache
python manage.py shell
>>> from django.core.cache import cache
>>> cache.clear()
```

---

## 📝 **LOG ANALYSIS**

### **10. Reading Logs**

#### **Security Logs**
```bash
# View recent security events
tail -50 logs/security.log

# Search for specific events
grep "login attempt" logs/security.log
grep "OTP generated" logs/security.log
```

#### **Email Logs**
```bash
# Check email console output (development)
# Look for email content in runserver output

# Production email logs
grep "email" logs/django.log
```

#### **Error Patterns**
```bash
# Find common errors
grep "ERROR" logs/django.log | sort | uniq -c | sort -nr

# Recent errors
tail -100 logs/django.log | grep ERROR
```

---

## 🚀 **PRODUCTION ISSUES**

### **11. Production-Specific**

#### **SSL Certificate Issues**
```bash
# Check certificate status
sudo certbot certificates

# Test SSL configuration
openssl s_client -connect your-domain.com:443 -servername your-domain.com

# Renew certificate
sudo certbot renew
```

#### **Load Balancer Issues**
```bash
# Test backend directly
curl -H "Host: your-domain.com" http://127.0.0.1:8000/api/v1/health/

# Check nginx configuration
sudo nginx -t
sudo systemctl status nginx
```

---

## 🆘 **EMERGENCY PROCEDURES**

### **12. System Recovery**

#### **Database Recovery**
```bash
# Restore from backup
psql -h localhost -U prs_user -d prs_production < backup_file.sql

# Reset to last known good state
git reset --hard last_known_good_commit
```

#### **Service Recovery**
```bash
# Restart all services
sudo systemctl restart nginx
sudo supervisorctl restart prs_backend
sudo systemctl restart postgresql
```

#### **Rollback Deployment**
```bash
# Quick rollback to previous version
git checkout previous_version_tag
./deploy.sh
```

---

## 📞 **GETTING HELP**

### **13. When to Get Additional Support**

#### **Gather Information First**
```bash
# System information
python manage.py version
python --version
pip list > installed_packages.txt

# Error details
tail -100 logs/django.log > recent_errors.txt
python manage.py check > system_check.txt
```

#### **Include in Support Requests**
1. Exact error message
2. Steps to reproduce
3. System information
4. Recent log entries
5. Recent changes made

---

## 🔄 **MAINTENANCE COMMANDS**

### **14. Regular Maintenance**

#### **Weekly Tasks**
```bash
# Clean up old sessions
python manage.py clearsessions

# Clean up test data
python manage.py cleanup_test_data

# Check system health
python manage.py check
```

#### **Monthly Tasks**
```bash
# Database optimization (PostgreSQL)
sudo -u postgres psql -d prs_production -c "VACUUM ANALYZE;"

# Log rotation
sudo logrotate -f /etc/logrotate.conf
```

---

**Remember: When in doubt, check the logs first! 📋**

Most issues can be diagnosed by carefully reading the error messages and checking the relevant log files. 