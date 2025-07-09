# 🚀 Quick Start Guide

## **Option 1: Automatic Start (Recommended)**

```bash
cd Backend_PRS
python run_server.py
```

## **Option 2: Manual Start**

```bash
cd Backend_PRS/backend

# Set environment variables
export SECRET_KEY="django-insecure-dev-key-change-in-production-12345"
export DEBUG="True"

# Start server
python manage.py runserver
```

## **Option 3: Full Setup (First Time)**

```bash
cd Backend_PRS
python quick_test_backend.py  # Sets up database
python run_server.py          # Starts server
```

## **🌐 Your API is Ready!**

Once running, your backend will be available at:

- **API Base**: `http://127.0.0.1:8000/api/`
- **Admin Panel**: `http://127.0.0.1:8000/admin/`
- **API Docs**: `http://127.0.0.1:8000/swagger/`

## **🧪 Test Your API**

```bash
# Test users endpoint
curl http://127.0.0.1:8000/api/users/

# Test dashboard stats
curl http://127.0.0.1:8000/api/dashboard/stats/
```

## **✅ Ready for Frontend Integration**

Your frontend can now connect to these endpoints:
- `/api/auth/login/`
- `/api/users/`
- `/api/clients/`
- `/api/commission/`
- `/api/dashboard/stats/`
- `/api/notifications/`

**Your backend is now fully compatible with your frontend!** 🎉 