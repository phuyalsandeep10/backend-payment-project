# Deployment Troubleshooting Guide

## Database Connection Issues

### Error: `[Errno -2] Name or service not known`

This error occurs when your Django application cannot connect to the PostgreSQL database.

### Common Causes and Solutions

#### 1. Database Service Not Ready
**Problem**: PostgreSQL database is still initializing
**Solution**: Wait 2-5 minutes for the database to fully initialize

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

### Quick Fixes

#### Option 1: Use Safe Startup Script
Use the `render-start-safe.sh` script which handles database connectivity gracefully:

```bash
# In your Render service settings, set the build command to:
./render-start-safe.sh
```

#### Option 2: Manual Database Setup
If the database is accessible but migrations fail:

1. Connect to your database manually
2. Run migrations: `python manage.py migrate`
3. Create superuser: `python manage.py setup_superadmin`
4. Setup permissions: `python manage.py setup_permissions`

#### Option 3: Check Database Connection
Use the provided script to diagnose connection issues:

```bash
python check_db_connection.py
```

### Render-Specific Steps

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
   ```

4. **Wait for Database Initialization**:
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
# Check database connection
python check_db_connection.py

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

1. Check Render service logs for detailed error messages
2. Verify database service is running and healthy
3. Test database connection manually using `psql` or similar tool
4. Contact Render support if database service is not accessible 