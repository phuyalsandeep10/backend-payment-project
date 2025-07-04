# PRS Backend Deployment Guide

## 🚀 Recent Fixes & Improvements

### Authentication System Fixes
- **Added Direct Login Endpoint**: `/auth/login/direct/` - Bypasses OTP verification for development and initial setup
- **Fixed Superadmin Creation**: Removed blocking check that prevented initialization on existing deployments
- **SMTP Independence**: System now works without SMTP configuration

### Default Roles & Permissions
- **Comprehensive Role System**: 7 default roles with 47+ permissions
- **Automatic Role Creation**: Roles are created automatically during deployment
- **Organization-Specific Roles**: Each organization gets its own role instances

### Mock Data & Business Flow
- **TechCorp Solutions**: Complete organization with realistic business data
- **5 Users**: Super Admin, Org Admin, Sales Manager, and 3 Salespeople
- **68+ Clients**: Across Technology, Healthcare, Finance, Manufacturing, and Retail
- **180+ Deals**: Realistic deal pipeline with varied statuses and values

## 🔧 Deployment Setup

### Render Configuration

1. **Build Command** (`render-build.sh`):
   ```bash
   pip install -r backend/requirements.txt
   cd backend
   python manage.py migrate
   ```

2. **Start Command** (`startup.sh`):
   ```bash
   cd backend
   python manage.py migrate
   python manage.py create_default_roles
   python manage.py initialize_app
   gunicorn core_config.wsgi:application --bind 0.0.0.0:$PORT
   ```

### Environment Variables
```
DATABASE_URL=postgresql://user:pass@host:port/db
DJANGO_SETTINGS_MODULE=core_config.settings
ADMIN_EMAIL=admin@example.com
ADMIN_PASS=defaultpass
ADMIN_USER=admin
```

## 👥 Default User Accounts

### System Users
| Role | Email | Password | Description |
|------|-------|----------|-------------|
| Super Admin | `admin@example.com` | `defaultpass` | System administrator |

### TechCorp Solutions Users
| Role | Email | Password | Description |
|------|-------|----------|-------------|
| Organization Admin | `admin@techcorp.com` | `admin123` | Organization administrator |
| Sales Manager | `manager@techcorp.com` | `manager123` | Sales team manager |
| Senior Salesperson | `john.smith@techcorp.com` | `john123` | Senior sales representative |
| Salesperson | `sarah.johnson@techcorp.com` | `sarah123` | Sales representative |
| Salesperson | `mike.davis@techcorp.com` | `mike123` | Sales representative |

## 🔐 Authentication Endpoints

### Direct Login (No OTP)
```bash
POST /api/v1/auth/login/direct/
{
  "email": "admin@techcorp.com",
  "password": "admin123"
}
```

### Standard Login (With OTP)
```bash
# Step 1: Initiate login
POST /api/v1/auth/login/
{
  "email": "admin@techcorp.com", 
  "password": "admin123"
}

# Step 2: Verify OTP
POST /api/v1/auth/login/verify/
{
  "session_id": "uuid-from-step-1",
  "otp": "123456"
}
```

### User Registration
```bash
POST /api/v1/auth/register/
{
  "username": "newuser",
  "email": "user@example.com",
  "password": "password123",
  "confirm_password": "password123",
  "organization": 1,
  "role": 2
}
```

## 🎭 Default Roles & Permissions

### Role Hierarchy
1. **Organization Admin** (44 permissions)
   - Full administrative access within organization
   - User, role, client, deal, team, project management
   - Organization dashboard and analytics

2. **Sales Manager** (27 permissions)
   - Manages sales team and operations
   - All client and deal access
   - Team management and reporting

3. **Team Head** (23 permissions)
   - Leads a team and manages members
   - Team-specific access and reporting

4. **Senior Salesperson** (19 permissions)
   - Experienced salesperson with additional privileges
   - Cross-team visibility and reporting

5. **Salesperson** (13 permissions)
   - Standard sales role
   - Own clients, deals, and basic dashboard

6. **Verifier** (11 permissions)
   - Handles verification and approval processes
   - Payment verification and deal approval

7. **Team Member** (11 permissions)
   - Basic team member with limited access
   - Own data access only

### Permission Categories
- **User Management**: Create, view, edit, delete users
- **Role Management**: Manage roles and permissions
- **Organization Management**: Organization settings and analytics
- **Client Management**: Client CRUD and data management
- **Deal Management**: Deal pipeline and verification
- **Team Management**: Team structure and assignments
- **Project Management**: Project tracking and management
- **Commission Management**: Commission calculation and approval
- **Sales Dashboard**: Analytics and reporting
- **Verification**: Payment and document verification
- **System Administration**: System-level operations

## 📊 Mock Data Overview

### TechCorp Solutions Organization
- **Sales Goal**: $1,500,000 annually
- **Total Won Value**: $3,489,111 (233% of goal)
- **Active Deals**: 180 total deals
- **Win Rate**: ~32% average across salespeople

### Client Distribution
- **Technology**: 25+ clients (InnovateTech, CloudFirst, DataStream, etc.)
- **Healthcare**: 15+ clients (MedCare, HealthTech, BioMed, etc.)
- **Finance**: 15+ clients (FinTech Pioneers, Investment Analytics, etc.)
- **Manufacturing**: 10+ clients (AutoMate, SmartFactory, Industrial IoT, etc.)
- **Retail**: 8+ clients (E-Commerce Experts, Digital Marketplace, etc.)

### Deal Types & Values
- **Software License**: $10K - $50K
- **Implementation Services**: $25K - $100K
- **Custom Development**: $50K - $200K
- **Enterprise Solution**: $100K - $500K
- **Consulting Services**: $15K - $75K
- **Annual Support**: $5K - $30K
- **Cloud Migration**: $30K - $150K
- **Security Audit**: $8K - $40K

## 🧪 Testing the Deployment

### Using the Test Script
```bash
python test_login.py
```

### Manual Testing
```bash
# Test Render deployment
curl -X POST https://backend-prs.onrender.com/api/v1/auth/login/direct/ \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@techcorp.com","password":"admin123"}'

# Expected response:
{
  "token": "abc123...",
  "user": {
    "id": 1,
    "username": "orgadmin",
    "email": "admin@techcorp.com",
    "organization_name": "TechCorp Solutions",
    "role_name": "Organization Admin"
  }
}
```

## 🔄 Redeployment Process

1. **Automatic on Git Push**: Render automatically rebuilds and redeploys
2. **Manual Redeploy**: Use Render dashboard "Manual Deploy" button
3. **Database Persistence**: PostgreSQL data persists across deployments
4. **Initialization**: System checks for existing data and updates accordingly

## 🐛 Troubleshooting

### Common Issues

1. **"Application already initialized"**
   - Fixed: Initialization now always runs and creates TechCorp if missing

2. **"OTP email not sent"**
   - Solution: Use `/auth/login/direct/` endpoint

3. **"Superuser not created"**
   - Fixed: Superuser creation now handles existing users gracefully

4. **"Roles not found"**
   - Fixed: Default roles are created automatically during deployment

5. **"Permission denied"**
   - Check user role and permissions
   - Ensure user is active and has correct organization assignment

### Logs & Monitoring
- **Render Logs**: Available in Render dashboard
- **Application Logs**: Printed during startup process
- **Security Logs**: Authentication events logged

## 📞 Support

For issues or questions:
1. Check Render deployment logs
2. Verify environment variables
3. Test endpoints using the provided test script
4. Review this guide for authentication flow

## 🎯 Next Steps

1. **Frontend Integration**: Use the direct login endpoint for development
2. **Production SMTP**: Configure proper email service for OTP in production
3. **Custom Roles**: Organizations can create additional roles as needed
4. **Data Import**: Use the existing client/deal import functionality
5. **API Documentation**: Access Swagger docs at `/swagger/` or `/redoc/` 