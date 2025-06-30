# 📖 Installation & Setup Guide

## Complete Setup Instructions for PRS Backend

This guide will walk you through setting up the PRS Backend from scratch.

---

## 🎯 **PREREQUISITES**

### **Required Software**
- **Python 3.8+** (Python 3.12+ recommended)
- **Git** for version control
- **Virtual Environment** (venv or virtualenv)
- **Database** (SQLite for development, PostgreSQL for production)

### **Optional but Recommended**
- **PostgreSQL** for production database
- **Redis** for caching (future enhancement)
- **Docker** for containerized deployment

---

## 🚀 **QUICK SETUP**

### **1. Clone Repository**
```bash
# Clone the repository
git clone <repository-url>
cd Backend_PRS-1/backend

# Or if already downloaded
cd path/to/Backend_PRS-1/backend
```

### **2. Create Virtual Environment**
```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# macOS/Linux
python3 -m venv .venv
source .venv/bin/activate
```

### **3. Install Dependencies**
```bash
# Install all required packages
pip install -r requirements.txt

# Verify installation
pip list
```

### **4. Environment Configuration**
```bash
# Copy environment template
copy .env.template .env  # Windows
# cp .env.template .env    # macOS/Linux

# Edit .env file with your configuration
notepad .env  # Windows
# nano .env     # macOS/Linux
```

### **5. Database Setup**
```bash
# Run database migrations
python manage.py migrate

# Create superadmin user
python manage.py setup_superadmin --email admin@example.com --password YourSecurePassword123!

# Load initial data (optional)
python manage.py loaddata initial_data.json
```

### **6. Start Development Server**
```bash
# Start the server
python manage.py runserver

# Server will be available at:
# http://127.0.0.1:8000/
```

---

## ⚙️ **DETAILED CONFIGURATION**

### **Environment Variables (.env)**
```bash
# Django Core Settings
SECRET_KEY=your_very_long_secret_key_here_change_this_in_production
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1,0.0.0.0

# Database Configuration (Development - SQLite)
DB_NAME=
DB_USER=
DB_PASSWORD=
DB_HOST=
DB_PORT=

# Database Configuration (Production - PostgreSQL)
# DB_NAME=prs_production
# DB_USER=prs_user
# DB_PASSWORD=secure_password
# DB_HOST=localhost
# DB_PORT=5432

# Email Configuration
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your_email@gmail.com
EMAIL_HOST_PASSWORD=your_app_password
DEFAULT_FROM_EMAIL=PRS System <your_email@gmail.com>

# Super Admin Configuration
ADMIN_EMAIL=admin@example.com
ADMIN_PASS=YourSecurePassword123!
SUPER_ADMIN_OTP_EMAIL=admin@example.com

# Security Settings
CORS_ALLOW_ALL_ORIGINS=False
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
```

### **Email Setup (Gmail)**
1. **Enable 2-Factor Authentication** on your Gmail account
2. **Generate App Password**:
   - Go to Google Account settings
   - Security → 2-Step Verification → App passwords
   - Generate password for "Mail"
   - Use this password in `EMAIL_HOST_PASSWORD`

3. **Configure Email Variables**:
```bash
EMAIL_HOST_USER=your_gmail@gmail.com
EMAIL_HOST_PASSWORD=your_16_char_app_password
SUPER_ADMIN_OTP_EMAIL=where_to_send_otp@gmail.com
```

### **Database Setup Options**

#### **Option 1: SQLite (Development)**
```bash
# Default - no additional setup required
# Database file will be created automatically as db.sqlite3
python manage.py migrate
```

#### **Option 2: PostgreSQL (Production)**
```bash
# Install PostgreSQL
# Windows: Download from postgresql.org
# macOS: brew install postgresql
# Ubuntu: sudo apt install postgresql postgresql-contrib

# Create database and user
sudo -u postgres psql
CREATE DATABASE prs_production;
CREATE USER prs_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE prs_production TO prs_user;
\q

# Update .env file with PostgreSQL settings
DB_NAME=prs_production
DB_USER=prs_user
DB_PASSWORD=secure_password
DB_HOST=localhost
DB_PORT=5432

# Install PostgreSQL adapter
pip install psycopg2-binary

# Run migrations
python manage.py migrate
```

---

## 🔧 **MANAGEMENT COMMANDS**

### **Setup Superadmin**
```bash
# Create superadmin with custom details
python manage.py setup_superadmin --email admin@company.com --password SecurePass123! --username admin

# Create with prompts
python manage.py setup_superadmin

# List existing users
python manage.py setup_superadmin --list-users
```

### **Database Management**
```bash
# Create migrations
python manage.py makemigrations

# Apply migrations
python manage.py migrate

# Reset database (DANGER - deletes all data)
python manage.py flush

# Backup database
python manage.py dumpdata > backup.json

# Restore database
python manage.py loaddata backup.json
```

### **Data Cleanup**
```bash
# Clean up test data
python manage.py cleanup_test_data

# Clean up old sessions
python manage.py clearsessions
```

---

## 🐳 **DOCKER SETUP**

### **Development with Docker**
```dockerfile
# Dockerfile
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
```

### **Docker Compose**
```yaml
# docker-compose.yml
version: '3.8'

services:
  web:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DEBUG=True
    volumes:
      - .:/app
    depends_on:
      - db

  db:
    image: postgres:15
    environment:
      POSTGRES_DB: prs_db
      POSTGRES_USER: prs_user
      POSTGRES_PASSWORD: prs_password
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

### **Run with Docker**
```bash
# Build and run
docker-compose up --build

# Run in background
docker-compose up -d

# View logs
docker-compose logs -f web

# Stop containers
docker-compose down
```

---

## 🧪 **VERIFICATION**

### **1. Test API Connectivity**
```bash
# Test server is running
curl http://127.0.0.1:8000/api/v1/auth/

# Or open in browser
# http://127.0.0.1:8000/api/v1/auth/
```

### **2. Test Authentication**
```bash
# Test superadmin login (step 1)
curl -X POST http://127.0.0.1:8000/api/v1/auth/super-admin/login/ \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"YourSecurePassword123!"}'

# Check response for OTP message
```

### **3. Test Email System**
```bash
# Run email test
python -c "
from core_config.email_backend import EmailService
result = EmailService.send_email(
    subject='Test Email',
    message='Testing PRS email system',
    recipient_list=['admin@example.com']
)
print('Email test result:', result)
"
```

### **4. Access Admin Interface**
```bash
# Visit Django admin
# http://127.0.0.1:8000/admin/

# Login with superadmin credentials
```

### **5. API Documentation**
```bash
# Access Swagger UI
# http://127.0.0.1:8000/swagger/

# Access ReDoc
# http://127.0.0.1:8000/redoc/
```

---

## 🛠️ **TROUBLESHOOTING**

### **Common Issues**

#### **1. ImportError: No module named 'xyz'**
```bash
# Ensure virtual environment is activated
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # macOS/Linux

# Reinstall requirements
pip install -r requirements.txt
```

#### **2. Database Connection Error**
```bash
# Check database configuration in .env
# For SQLite, ensure write permissions to directory
# For PostgreSQL, check service is running
sudo service postgresql status  # Linux
brew services list postgresql   # macOS
```

#### **3. Email Not Sending**
```bash
# Check email configuration
python manage.py shell
>>> from django.core.mail import send_mail
>>> send_mail('Test', 'Message', 'from@example.com', ['to@example.com'])

# Check console output for email content (development mode)
```

#### **4. Port Already in Use**
```bash
# Find process using port 8000
netstat -ano | findstr :8000  # Windows
lsof -i :8000                 # macOS/Linux

# Kill process or use different port
python manage.py runserver 8001
```

#### **5. CORS Errors**
```bash
# Update CORS settings in .env
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://your-frontend-url

# Or temporarily allow all (DEVELOPMENT ONLY)
CORS_ALLOW_ALL_ORIGINS=True
```

---

## 🚀 **PRODUCTION SETUP**

### **Production Environment Variables**
```bash
# Production settings
DEBUG=False
SECRET_KEY=your_production_secret_key_50_chars_long
ALLOWED_HOSTS=your-domain.com,www.your-domain.com

# Database (PostgreSQL)
DB_NAME=prs_production
DB_USER=prs_user
DB_PASSWORD=very_secure_password
DB_HOST=your-db-host
DB_PORT=5432

# Email (Production SMTP)
EMAIL_HOST=your-smtp-server.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=noreply@your-domain.com
EMAIL_HOST_PASSWORD=smtp_password

# Security
CORS_ALLOW_ALL_ORIGINS=False
CORS_ALLOWED_ORIGINS=https://your-frontend-domain.com
```

### **Production Checklist**
- [ ] Set `DEBUG=False`
- [ ] Use strong `SECRET_KEY`
- [ ] Configure proper `ALLOWED_HOSTS`
- [ ] Set up PostgreSQL database
- [ ] Configure production email SMTP
- [ ] Set up proper CORS origins
- [ ] Enable HTTPS
- [ ] Set up proper logging
- [ ] Configure static file serving
- [ ] Set up backup system

---

## 📞 **SUPPORT**

### **Getting Help**
1. Check [Troubleshooting Guide](./troubleshooting.md)
2. Review [API Documentation](./api_reference.md)
3. Check Django logs for errors
4. Verify environment configuration

### **Health Check Commands**
```bash
# Check Django system
python manage.py check

# Check database connectivity
python manage.py shell -c "from django.db import connection; connection.ensure_connection(); print('DB OK')"

# Check email configuration
python manage.py shell -c "from core_config.email_backend import EmailService; print('Email config:', EmailService.test_email_connection())"
```

---

**Setup complete! 🎉 Your PRS Backend is ready for development.**

For next steps, check the [Frontend Integration Guide](./frontend_integration.md). 