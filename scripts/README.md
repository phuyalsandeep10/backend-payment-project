# PRS Backend Management Scripts

This directory contains comprehensive management scripts for the Payment Receiving System (PRS) backend. These scripts provide automated setup, deployment, maintenance, and monitoring capabilities.

## 🚀 Quick Start

### Development
```bash
# Start development server with hot reload
./scripts/manage.sh dev

# Or use the direct script
./scripts/dev_start.sh --port 8000
```

### Full Backend Setup
```bash
# Complete backend startup with all services
./scripts/manage.sh start

# Or use the direct script
./scripts/start_backend.sh --environment development
```

## 📁 Script Overview

### Core Management Scripts

#### `manage.sh` - Central Management Hub
The main entry point for all backend operations. Provides a unified interface for all common tasks.

**Usage:**
```bash
./scripts/manage.sh <command> [options]
```

**Available Commands:**
- `dev` - Start development server
- `start` - Full backend startup
- `stop` - Stop all services
- `restart` - Restart all services
- `migrate` - Run database migrations
- `test` - Run test suite
- `maintenance` - System maintenance
- `health` - Health check
- `shell` - Django shell
- `logs` - View logs

#### `start_backend.sh` - Complete Backend Startup
Comprehensive startup script that initializes all backend services with proper optimization and monitoring.

**Features:**
- Virtual environment activation
- Database migrations
- Static file collection
- System optimizations
- Monitoring setup
- Security checks
- Service startup

**Usage:**
```bash
./scripts/start_backend.sh [OPTIONS]

Options:
  --environment ENV     Set environment (development|staging|production)
  --skip-migrations     Skip database migrations
  --skip-collectstatic  Skip static file collection
  --skip-optimization   Skip system optimizations
  --skip-monitoring     Skip monitoring setup
  --run-tests          Run tests during startup
  --verbose            Enable verbose output
```

#### `stop_backend.sh` - Service Shutdown
Gracefully stops all backend services and performs cleanup tasks.

**Features:**
- Celery worker/beat shutdown
- Django server termination
- Temporary file cleanup
- Maintenance tasks
- Log rotation

**Usage:**
```bash
./scripts/stop_backend.sh [OPTIONS]

Options:
  --skip-maintenance    Skip maintenance tasks
  --skip-cleanup        Skip temporary file cleanup
```

#### `dev_start.sh` - Development Server
Optimized development server with hot reloading and debugging features.

**Features:**
- Quick setup for development
- Hot reloading
- Debug mode
- Development user creation
- Background service management

**Usage:**
```bash
./scripts/dev_start.sh [OPTIONS]

Options:
  --port PORT          Set server port [default: 8000]
  --no-debug           Disable debug mode
  --skip-checks        Skip Django system checks
  --no-watch           Disable file watching
```

#### `maintenance.sh` - System Maintenance
Regular maintenance tasks for optimal system performance.

**Features:**
- File cleanup (logs, backups, temp files)
- Database optimization
- Cache management
- Security checks
- Health monitoring
- Report generation

**Usage:**
```bash
./scripts/maintenance.sh [OPTIONS]

Options:
  --type TYPE              Maintenance type (daily|weekly|monthly)
  --backup-retention DAYS  Backup retention in days [default: 30]
  --log-retention DAYS     Log retention in days [default: 7]
  --skip-cleanup           Skip file cleanup
  --skip-database          Skip database maintenance
  --skip-reports           Skip report generation
```

## 🔧 System Requirements

### Prerequisites
- Python 3.8+
- PostgreSQL (recommended) or SQLite
- Redis (for caching and Celery)
- Virtual environment

### Optional Dependencies
- Celery (for background tasks)
- Coverage.py (for test coverage)
- Django Extensions (for enhanced shell)

## 📊 Management Commands Integration

The scripts integrate with Django management commands for comprehensive system management:

### Database Management
- `optimize_database` - Database performance optimization
- `cleanup_duplicate_commissions` - Commission data cleanup
- `optimize_financial_fields` - Financial field validation

### Performance Monitoring
- `manage_monitoring` - System monitoring and health checks
- `manage_background_tasks` - Background task management
- `analyze_deal_performance` - Deal performance analytics

### Security & Authentication
- `check_password_expiration` - Password policy enforcement
- `analyze_org_queries` - Organization query analysis
- `manage_role_cache` - Role-based permission caching

### Workflow Management
- `workflow_maintenance` - Workflow optimization
- `optimize_commissions` - Commission calculation optimization
- `test_atomic_operations` - Transaction integrity testing

## 🚦 Environment Configuration

### Development Environment
```bash
export ENVIRONMENT=development
export DEBUG=true
export SKIP_OPTIMIZATION=false
export RUN_TESTS=false
```

### Production Environment
```bash
export ENVIRONMENT=production
export DEBUG=false
export SKIP_OPTIMIZATION=false
export RUN_TESTS=true
export BACKUP_DB=true
```

## 📝 Logging

Logs are organized by service type:
- `logs/django/` - Django application logs
- `logs/celery/` - Celery worker and beat logs
- `logs/monitoring/` - System monitoring logs
- `logs/security/` - Security event logs

## 🔍 Health Monitoring

### Health Check Endpoints
- `/api/health/` - Basic health check
- `/api/monitoring/system/health/` - Comprehensive system health
- `/api/monitoring/performance/summary/` - Performance metrics

### Monitoring Commands
```bash
# Check system status
./scripts/manage.sh health

# View monitoring dashboard
python manage.py manage_monitoring status

# Export performance metrics
python manage.py manage_monitoring export-metrics --hours 24
```

## 🧪 Testing

### Test Execution
```bash
# Run full test suite
./scripts/manage.sh test

# Run fast tests (parallel, keepdb)
./scripts/manage.sh test-fast

# Run with coverage report
./scripts/manage.sh coverage
```

### Test Categories
- Unit tests for models and utilities
- Integration tests for API endpoints
- Performance tests for database queries
- Security tests for authentication
- Atomic operation tests for data integrity

## 🔒 Security Features

### Security Checks
- Django deployment security checks
- Password expiration policy enforcement
- Organization query analysis
- Input validation and sanitization
- File upload security scanning

### Security Monitoring
- Real-time security event logging
- Audit trail for sensitive operations
- Automated threat detection
- Security dashboard and alerts

## 📈 Performance Optimization

### Database Optimization
- Query performance analysis
- Index optimization recommendations
- Connection pooling configuration
- Slow query identification

### Caching Strategy
- Role-based permission caching
- Commission calculation caching
- Query result caching
- Session management optimization

### Background Processing
- Celery task optimization
- Queue management
- Task monitoring and retry logic
- Performance metrics collection

## 🚀 Deployment

### Development Deployment
```bash
./scripts/manage.sh dev --port 8000
```

### Production Deployment
```bash
./scripts/start_backend.sh --environment production --run-tests
```

### Zero-Downtime Deployment
```bash
# Stop services gracefully
./scripts/stop_backend.sh

# Deploy new code
git pull origin main

# Start with full checks
./scripts/start_backend.sh --environment production
```

## 🛠️ Troubleshooting

### Common Issues

#### Virtual Environment Not Found
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### Database Connection Issues
```bash
# Check database connectivity
./scripts/manage.sh health

# Run database migrations
./scripts/manage.sh migrate
```

#### Redis Connection Issues
```bash
# Start Redis (macOS with Homebrew)
brew services start redis

# Start Redis (Linux with systemctl)
sudo systemctl start redis
```

#### Celery Worker Issues
```bash
# Check Celery status
./scripts/manage.sh logs celery

# Restart background services
./scripts/manage.sh restart
```

### Log Analysis
```bash
# View Django logs
./scripts/manage.sh logs django

# View Celery logs
./scripts/manage.sh logs celery

# View monitoring logs
./scripts/manage.sh logs monitoring
```

## 📞 Support

For issues or questions:
1. Check the logs using `./scripts/manage.sh logs`
2. Run health check using `./scripts/manage.sh health`
3. Review the troubleshooting section above
4. Check Django management command help: `python manage.py help <command>`

## 🔄 Regular Maintenance

### Daily Tasks
```bash
./scripts/maintenance.sh --type daily
```

### Weekly Tasks
```bash
./scripts/maintenance.sh --type weekly
```

### Monthly Tasks
```bash
./scripts/maintenance.sh --type monthly
```

## 📋 Script Checklist

Before using the scripts, ensure:
- [ ] Virtual environment is created and activated
- [ ] Database is accessible and configured
- [ ] Redis is running (for caching and Celery)
- [ ] Required environment variables are set
- [ ] Scripts have execute permissions (`chmod +x scripts/*.sh`)
- [ ] Dependencies are installed (`pip install -r requirements.txt`)

## 🎯 Best Practices

1. **Always use the management script** (`manage.sh`) for common operations
2. **Run health checks** before and after deployments
3. **Monitor logs** regularly for issues
4. **Perform regular maintenance** using the maintenance script
5. **Test in development** before production deployment
6. **Keep backups** of database and configuration
7. **Use environment-specific configurations**
8. **Monitor system resources** and performance metrics