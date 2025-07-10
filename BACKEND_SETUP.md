# PRS Backend Setup Guide

## ✅ Backend Compatibility Status
**FULLY COMPATIBLE** with your frontend! All necessary changes have been made.

## 🚀 Quick Start

### Prerequisites
Make sure PostgreSQL is running with these credentials:
- **Database**: postgres
- **User**: postgres  
- **Password**: password
- **Host**: localhost:5432

### Option 1: Automated Setup (Recommended)
```bash
cd Backend_PRS
python setup_backend.py
```

### Option 2: Manual Setup
```bash
cd Backend_PRS/backend

# Set environment variables for PostgreSQL
export SECRET_KEY="django-insecure-dev-key-change-in-production"
export DEBUG=True
export DB_NAME=postgres
export DB_USER=postgres
export DB_PASSWORD=password
export DB_HOST=localhost
export DB_PORT=5432
export SUPER_ADMIN_OTP_EMAIL="admin@example.com"

# Install dependencies (if not already done)
pip install -r requirements.txt

# Create and apply migrations
python manage.py makemigrations
python manage.py migrate

# Create a superuser
python manage.py createsuperuser

# Start the server
python manage.py runserver
```

## 🗄️ PostgreSQL Setup

### Starting PostgreSQL:
```bash
# macOS (with Homebrew)
brew services start postgresql

# Linux
sudo systemctl start postgresql

# Windows
# Start PostgreSQL service from Services panel
```

### Creating Database (if needed):
```bash
# Connect to PostgreSQL
psql -U postgres

# Create database (if it doesn't exist)
CREATE DATABASE postgres;

# Exit psql
\q
```

### Verify Connection:
```bash
psql -U postgres -d postgres -h localhost -p 5432
```

## 📋 What's Changed for Frontend Compatibility

### ✅ API Endpoints Now Available:
- **Users**: `GET/POST/PUT/DELETE /api/users/`
- **Clients**: `GET/POST/PUT/DELETE /api/clients/`
- **Teams**: `GET/POST/PUT/DELETE /api/teams/`
- **Commission**: `GET/POST/PUT/DELETE /api/commission/`
- **Dashboard**: `GET /api/dashboard/stats/`
- **Notifications**: `GET/POST/PUT/DELETE /api/notifications/`

### ✅ Authentication Endpoints:
- **Login**: `POST /api/auth/login/`
- **Logout**: `POST /api/auth/logout/`
- **Refresh Token**: `POST /api/auth/refresh/`
- **Forgot Password**: `POST /api/auth/forgot-password/`
- **Reset Password**: `POST /api/auth/reset-password/`

### ✅ Data Structure Matches Frontend:
- User fields: `name`, `phoneNumber`, `assignedTeam`, `status`, `avatar`
- Client fields: `name`, `category`, `salesperson`, `lastContact`, `value`
- Commission fields: `fullName`, `currency`, `rate`, `percentage`, `bonus`
- Pagination: `{ data: [], pagination: { page, limit, total, totalPages } }`

## 🔧 Configuration

### Database Settings
```python
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "postgres",
        "USER": "postgres",
        "PASSWORD": "password",
        "HOST": "localhost",
        "PORT": "5432",
    }
}
```

### Environment Variables
```env
SECRET_KEY=your-secret-key
DEBUG=True
DB_NAME=postgres
DB_USER=postgres
DB_PASSWORD=password
DB_HOST=localhost
DB_PORT=5432
SUPER_ADMIN_OTP_EMAIL=admin@example.com
DEFAULT_FROM_EMAIL=noreply@example.com
```

## 📚 API Documentation
Once running, visit:
- **Swagger UI**: http://127.0.0.1:8000/swagger/
- **ReDoc**: http://127.0.0.1:8000/redoc/

## 🧪 Testing Frontend Integration

Your frontend should now work seamlessly! The backend provides:

1. **Correct URL structure**: `/api/` instead of `/api/v1/`
2. **Matching field names**: All frontend-expected field names are supported
3. **Proper pagination**: Returns data in expected format
4. **Complete endpoints**: All frontend API calls are now supported

## 🎯 Next Steps

1. **Ensure PostgreSQL is running** with the correct credentials
2. **Run the setup** using the automated script
3. **Create a superuser** for admin access
4. **Test your frontend** - it should now connect successfully!
5. **Check API documentation** at `/swagger/` for full endpoint details

## 🐛 Troubleshooting

### Database Connection Issues:
1. **Check PostgreSQL is running**:
   ```bash
   # Check if PostgreSQL is running
   pg_isready -h localhost -p 5432
   ```

2. **Verify credentials**:
   ```bash
   psql -U postgres -d postgres -h localhost -p 5432
   ```

3. **Create database if missing**:
   ```bash
   createdb -U postgres postgres
   ```

### Common Solutions:
- **Port busy**: Use `python manage.py runserver 8001`
- **Import errors**: Run `pip install -r requirements.txt`
- **Permission denied**: Check PostgreSQL user permissions 