# Backend_PRS - Payment Receiving System Backend

## Overview

Backend_PRS is a comprehensive Django REST Framework-based backend system for a Payment Receiving System (PRS). It provides a complete multi-tenant SaaS solution for managing sales operations, client relationships, payment processing, and commission tracking with role-based access control.

## System Architecture

### Core Components

- **Django 5.2.2** - Web framework
- **Django REST Framework 3.15.2** - API framework
- **PostgreSQL** - Primary database (with SQLite fallback for development)
- **Redis** - Caching and real-time features
- **Channels & WebSockets** - Real-time notifications
- **Cloudinary** - Media storage and management
- **Celery** - Background task processing (implied by Redis usage)

### Multi-Tenant Architecture

The system implements a sophisticated multi-tenant architecture where:
- **Organizations** serve as the top-level tenant
- **Users** belong to organizations and have specific roles
- **Data isolation** is maintained across organizations
- **Role-based permissions** control access within organizations

## Django Apps Structure

### 1. Authentication (`authentication/`)
- Custom user model with email-based authentication
- Multi-factor authentication for admin users
- Session management and security tracking
- User profiles and preferences
- Role-based access control

### 2. Organizations (`organization/`)
- Multi-tenant organization management
- Organization registration and administration
- Isolation boundaries for data security

### 3. Permissions (`permissions/`)
- Role-based access control system
- Custom permission management
- Organization-scoped permissions

### 4. Clients (`clients/`)
- Client relationship management
- Client satisfaction tracking
- Hierarchical client-deal relationships

### 5. Deals (`deals/`)
- **Core business logic module**
- Deal creation and management
- Payment processing and tracking
- Invoice generation and management
- Payment approval workflows
- Comprehensive audit trails

### 6. Commission (`commission/`)
- Commission calculation and tracking
- Multi-currency support
- Automatic commission computation
- Performance bonuses and penalties

### 7. Team (`team/`)
- Team management and organization
- Team lead assignments
- Member management

### 8. Project (`project/`)
- Project management system
- Team-based project assignments
- Project status tracking

### 9. Notifications (`notifications/`)
- Real-time notification system
- WebSocket-based delivery
- Notification templates and preferences
- User notification settings

### 10. Sales Dashboard (`Sales_dashboard/`)
- Sales performance analytics
- Streak tracking and gamification
- Performance metrics and reporting
- Goal tracking and progress monitoring

### 11. Verifier Dashboard (`Verifier_dashboard/`)
- Payment verification workflows
- Invoice management and approval
- Audit logging and compliance
- Verification queue management

## Key Features

### 🔐 Security Features
- **Multi-factor authentication** for admin users
- **JWT token-based authentication**
- **Role-based access control (RBAC)**
- **CSRF protection** and security headers
- **File upload security** with validation
- **Audit logging** for compliance
- **Organization data isolation**

### 💰 Payment Processing
- **Multiple payment methods** (cash, bank transfer, cheque, etc.)
- **Payment verification workflow**
- **Automatic invoice generation**
- **Payment approval system**
- **Real-time payment tracking**
- **Commission auto-calculation**

### 📊 Analytics & Reporting
- **Sales dashboard** with performance metrics
- **Streak tracking** and gamification
- **Commission reporting** and analytics
- **Client satisfaction monitoring**
- **Payment method distribution**
- **Audit trail reporting**

### 🔄 Real-time Features
- **WebSocket notifications**
- **Real-time dashboard updates**
- **Live payment status updates**
- **Instant notification delivery**

### 🎯 Role Management
- **Super Admin** - System-wide administration
- **Organization Admin** - Organization management
- **Salesperson** - Sales and client management
- **Verifier** - Payment verification and approval
- **Team Lead** - Team management and oversight

## Database Schema

### Core Models Structure
```
Organization (1) ──┬── (M) User
                   ├── (M) Role
                   ├── (M) Team
                   ├── (M) Client
                   ├── (M) Deal
                   ├── (M) Commission
                   └── (M) Notification

Deal (1) ──┬── (M) Payment
           ├── (M) ActivityLog
           ├── (M) PaymentInvoice
           └── (M) PaymentApproval

User (1) ──┬── (M) Deal (created_by)
           ├── (M) Commission
           └── (1) UserProfile
```

### Key Model Features
- **UUID primary keys** for security
- **Auto-generated IDs** (DLID0001, TXN-0001 format)
- **Audit fields** (created_by, updated_by, timestamps)
- **Soft deletes** where appropriate
- **Version control** for critical data

## API Endpoints

### Authentication (`/api/auth/`)
- User registration and login
- Multi-factor authentication
- Session management
- Profile management
- Password change workflows

### Business Logic (`/api/`)
- **Clients** - Client relationship management
- **Deals** - Deal creation and management
- **Payments** - Payment processing
- **Commission** - Commission tracking
- **Organizations** - Organization management
- **Teams** - Team management
- **Projects** - Project management
- **Notifications** - Real-time notifications

### Dashboards
- **Sales Dashboard** (`/api/dashboard/`) - Sales analytics
- **Verifier Dashboard** (`/api/verifier/`) - Payment verification

### Documentation
- **Swagger UI** (`/swagger/`) - Interactive API documentation
- **ReDoc** (`/redoc/`) - Alternative API documentation

## Development Setup

### Prerequisites
- Python 3.8+
- PostgreSQL 12+
- Redis 6+
- Git

### Quick Start
```bash
# Clone the repository
git clone <repository-url>
cd Backend_PRS

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Environment setup
cp .env.example .env
# Edit .env with your database and Redis credentials

# Database setup
python manage.py migrate
python manage.py collectstatic

# Create superuser
python manage.py createsuperuser

# Run development server
python manage.py runserver
```

### Environment Variables
```env
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/prs_db

# Redis
REDIS_URL=redis://localhost:6379

# Django
SECRET_KEY=your-secret-key
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# Email
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password

# Cloudinary
CLOUDINARY_CLOUD_NAME=your-cloud-name
CLOUDINARY_API_KEY=your-api-key
CLOUDINARY_API_SECRET=your-api-secret
```

## Deployment

### Production Environment
- **Render.com** - Primary deployment platform
- **Gunicorn** - WSGI server
- **WhiteNoise** - Static file serving
- **PostgreSQL** - Production database
- **Redis** - Production caching and channels

### Deployment Scripts
- `render.sh` - Main deployment script
- `render-build.sh` - Build process
- `render-start-safe.sh` - Safe startup script

### Environment Configuration
- Environment-specific settings
- Database connection handling
- Static file management
- Security configurations

## Security

### Authentication & Authorization
- Email-based authentication
- JWT token authentication
- Multi-factor authentication for admins
- Role-based access control
- Organization data isolation

### Security Features
- CSRF protection
- XSS protection
- SQL injection prevention
- File upload security
- Rate limiting
- Security headers
- Audit logging

### Compliance
- Data privacy protection
- Audit trail maintenance
- Secure file handling
- Access control logging

## Testing

### Test Structure
```
tests/
├── test_email.py
├── test_migrations.py
├── test_org_admin_endpoints.py
├── test_salesperson_endpoints.py
├── test_super_admin_endpoints.py
└── test_verifier_endpoints.py
```

### Running Tests
```bash
# Run all tests
python manage.py test

# Run specific test file
python manage.py test tests.test_salesperson_endpoints

# Run with coverage
coverage run manage.py test
coverage report
```

## Monitoring & Logging

### Security Logging
- Failed authentication attempts
- Permission violations
- Suspicious activities
- File upload security events

### Application Logging
- API request/response logging
- Database query logging
- Performance monitoring
- Error tracking

### Log Files
- `logs/security.log` - Security events
- `logs/django.log` - Application logs

## Performance Optimization

### Database Optimization
- Strategic indexes on frequently queried fields
- Query optimization for dashboard views
- Connection pooling
- Database-level constraints

### Caching Strategy
- Redis-based caching
- Model-level caching
- Template fragment caching
- API response caching

### File Handling
- Cloudinary integration for media
- Image compression and optimization
- Secure file upload handling
- CDN integration

## Management Commands

### User Management
- `create_super_admin` - Create super admin user
- `setup_permissions` - Initialize permissions
- `assign_role_permissions` - Assign role permissions

### Data Management
- `seed_demo_data` - Create demo data
- `reset_db_for_deployment` - Reset database
- `calculate_streaks` - Recalculate sales streaks

### Maintenance
- `cleanup_permissions` - Clean up permissions
- `check_migration_safety` - Validate migrations
- `fix_deployment_permissions` - Fix permission issues

## Contributing

### Development Guidelines
1. Follow Django best practices
2. Maintain test coverage
3. Use proper commit messages
4. Document API changes
5. Follow security guidelines

### Code Style
- PEP 8 compliance
- Consistent naming conventions
- Proper documentation
- Security-first development

## Support

### Documentation
- See `documentation/` directory for detailed guides
- API documentation at `/swagger/`
- Database schema documentation available

### Common Issues
- Database connection issues
- Permission-related problems
- File upload problems
- Authentication failures

### Maintenance
- Regular security updates
- Database maintenance
- Performance monitoring
- Log rotation

## License

This project is proprietary software. All rights reserved.

## Version History

- **v1.0.0** - Initial release with core functionality
- **v1.1.0** - Added multi-tenant support
- **v1.2.0** - Enhanced security features
- **v1.3.0** - Real-time notifications
- **v1.4.0** - Advanced analytics and reporting

---

For detailed documentation, please refer to the `documentation/` directory.