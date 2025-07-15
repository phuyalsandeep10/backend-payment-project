# Deployment Troubleshooting Guide

## Database Connection Issues

### Error: `[Errno -2] Name or service not known`

This error occurs when your Django application cannot connect to the PostgreSQL database.

### Quick Fix: Use the Safe Startup Script

**Recommended Solution**: Use the new `render-start-safe.sh` script which handles database connectivity issues gracefully:

1. **Update your Render service configuration**:
   - Go to your Render web service settings
   - Change the **Start Command** to: `./render-start-safe.sh`
   - Save and redeploy

2. **What the safe script does**:
   - Checks if database environment variables are set
   - Waits for database to be ready (up to 5 minutes)
   - Falls back to SQLite if PostgreSQL is not available
   - Provides detailed logging for troubleshooting
   - Continues deployment even if database operations fail

### Common Causes and Solutions

#### 1. Database Service Not Ready
**Problem**: PostgreSQL database is still initializing
**Solution**: 
- Wait 2-5 minutes for the database to fully initialize
- Use the safe startup script which handles this automatically

#### 2. Environment Variables Missing/Incorrect
**Problem**: Database connection details are wrong
**Solution**: Check your environment variables in Render dashboard:

Required variables:
- `DB_NAME` - Database name
- `DB_HOST` - Database host (usually provided by Render)
- `DB_USER` - Database username
- `DB_PASSWORD` - Database password
- `DB_PORT` - Database port (usually 5432)
- `DB_ENGINE` - Database engine (django.db.backends.postgresql)

#### 3. Services Not Linked
**Problem**: Web service and database service are not connected
**Solution**: In Render dashboard, ensure your web service is linked to your PostgreSQL database

### Diagnostic Tools

#### 1. Database Debug Script
Use the comprehensive debug script to diagnose connection issues:

```bash
# Run the debug script
python backend/debug_database.py
```

This script will:
- Check all environment variables
- Test network connectivity
- Verify Django settings
- Test actual database connection
- Provide specific troubleshooting advice

#### 2. Environment Setup Helper
Use the setup helper to configure Render properly:

```bash
# Show setup instructions
python setup_render_env.py help

# Check current environment
python setup_render_env.py check

# Generate SECRET_KEY
python setup_render_env.py secret
```

### Render-Specific Setup Steps

1. **Create PostgreSQL Database**:
   - Go to Render dashboard
   - Create a new PostgreSQL service
   - Note the connection details

2. **Link Database to Web Service**:
   - In your web service settings
   - Add the database as an environment variable
   - Or use Render's automatic linking

3. **Set Environment Variables**:
   ```
   DB_NAME=your_database_name
   DB_HOST=your_database_host
   DB_USER=your_database_user
   DB_PASSWORD=your_database_password
   DB_PORT=5432
   DB_ENGINE=django.db.backends.postgresql
   SECRET_KEY=your_generated_secret_key
   DEBUG=False
   ```

4. **Use Safe Startup Script**:
   - Set Start Command to: `./render-start-safe.sh`
   - This script handles all database connectivity issues

5. **Wait for Database Initialization**:
   - PostgreSQL databases take 2-5 minutes to initialize
   - Check the database service logs for completion

### Alternative: Use SQLite for Development

If you're having persistent issues with PostgreSQL, you can temporarily use SQLite:

1. Remove database environment variables
2. Django will automatically fall back to SQLite
3. Deploy and test your application
4. Switch back to PostgreSQL once everything works

### Debugging Commands

```bash
# Comprehensive database diagnostics
python backend/debug_database.py

# Check database connection
python backend/check_db_connection.py

# Check Django settings
python manage.py check

# List migrations
python manage.py showmigrations

# Run migrations (if database is accessible)
python manage.py migrate

# Create superuser
python manage.py setup_superadmin

# Setup permissions
python manage.py setup_permissions
```

### Common Environment Variable Issues

1. **Missing Variables**: Ensure all required database variables are set
2. **Wrong Values**: Double-check host, port, and credentials
3. **Special Characters**: Escape special characters in passwords
4. **Case Sensitivity**: Environment variable names are case-sensitive

### Getting Help

If you're still having issues:

1. **Run the debug script**: `python backend/debug_database.py`
2. **Check Render service logs** for detailed error messages
3. **Verify database service** is running and healthy
4. **Test database connection** manually using `psql` or similar tool
5. **Contact Render support** if database service is not accessible

### New Features

#### Safe Startup Script (`render-start-safe.sh`)
- **Automatic database detection**: Checks if PostgreSQL is available
- **Graceful fallback**: Uses SQLite if PostgreSQL fails
- **Comprehensive logging**: Shows exactly what's happening
- **Error handling**: Continues deployment even if database operations fail
- **Environment validation**: Checks all required variables

#### Debug Script (`backend/debug_database.py`)
- **Complete diagnostics**: Tests all aspects of database connectivity
- **Network testing**: Checks if hostname resolves and port is reachable
- **Specific error advice**: Provides targeted solutions for different errors
- **Render-specific checks**: Detects Render environment and provides relevant advice

#### Setup Helper (`setup_render_env.py`)
- **Step-by-step instructions**: Complete Render setup guide
- **Environment checking**: Verifies current variable setup
- **SECRET_KEY generation**: Creates secure keys for production
- **Quick commands**: Easy access to common tasks 