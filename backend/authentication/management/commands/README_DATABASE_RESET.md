# Database Reset Commands

This document explains the database reset commands available for completely destroying and recreating the database.

## ⚠️ WARNING ⚠️

**These commands will PERMANENTLY DELETE ALL DATA in your database!**
- All tables, data, and migration history will be destroyed
- This operation cannot be undone
- Use only when you're absolutely sure you want to start fresh

## Available Commands

### 1. Nuclear Reset (`nuclear_reset_db`)

The most comprehensive reset option with multiple safety checks.

```bash
# Interactive mode (recommended)
python manage.py nuclear_reset_db

# Force mode (skips all confirmations)
python manage.py nuclear_reset_db --force

# Skip backup creation
python manage.py nuclear_reset_db --skip-backup

# Custom backup file
python manage.py nuclear_reset_db --backup-file my_backup.sql
```

**Features:**
- ✅ Creates automatic backup before reset
- ✅ Multiple confirmation prompts for safety
- ✅ Production environment detection
- ✅ Complete database recreation
- ✅ Fresh migrations
- ✅ Initial data setup
- ✅ Test data generation (development only)

### 2. Deployment Reset (`reset_db_for_deployment`)

Simplified version designed for automated deployment processes.

```bash
# Standard deployment reset
python manage.py reset_db_for_deployment

# Force mode
python manage.py reset_db_for_deployment --force

# Skip migrations
python manage.py reset_db_for_deployment --skip-migrations

# Skip initial setup
python manage.py reset_db_for_deployment --skip-setup
```

**Features:**
- ✅ Designed for automated deployment
- ✅ Less interactive prompts
- ✅ Proper error handling for deployment environments
- ✅ Complete database recreation
- ✅ Fresh migrations
- ✅ Initial data setup

## When to Use Each Command

### Use Nuclear Reset When:
- You want maximum safety and confirmation prompts
- You're manually resetting the database
- You want automatic backup creation
- You're in development and want to be extra careful

### Use Deployment Reset When:
- You're setting up a fresh production environment
- You're using automated deployment (like Render)
- You want minimal user interaction
- You're confident about the reset operation

## Production Deployment

For production deployment on Render, you can enable the nuclear reset by setting an environment variable:

```bash
# In Render environment variables
RESET_DB=true
```

This will trigger the database reset during the build process using the deployment reset command.

## What Happens During Reset

1. **Backup Creation** (nuclear reset only)
   - Creates a timestamped backup file
   - Uses `pg_dump` for PostgreSQL databases

2. **Database Destruction**
   - Terminates all active connections
   - Drops the entire database
   - Creates a fresh, empty database

3. **Migration Application**
   - Runs all migrations from scratch
   - Creates all tables and indexes

4. **Initial Data Setup**
   - Creates superuser account
   - Sets up all permissions and roles
   - Generates test data (development only)

## Safety Measures

### Nuclear Reset Safety:
- Multiple confirmation prompts
- Production environment detection
- Automatic backup creation
- Detailed logging

### Deployment Reset Safety:
- Force flag for automated use
- Proper error handling
- Deployment environment optimization

## Recovery Options

### If Something Goes Wrong:

1. **Restore from Backup** (if created):
   ```bash
   psql -h HOST -p PORT -U USER -d DATABASE < backup_file.sql
   ```

2. **Manual Database Recreation**:
   ```bash
   # Connect to postgres database
   psql -h HOST -p PORT -U USER -d postgres
   
   # Drop and recreate
   DROP DATABASE IF EXISTS your_database;
   CREATE DATABASE your_database;
   ```

3. **Re-run Setup Commands**:
   ```bash
   python manage.py migrate
   python manage.py setup_superadmin
   python manage.py setup_permissions
   ```

## Environment Variables

Make sure these environment variables are set:

```bash
# Database Configuration
DB_ENGINE=django.db.backends.postgresql
DB_NAME=your_database_name
DB_USER=your_database_user
DB_PASSWORD=your_database_password
DB_HOST=your_database_host
DB_PORT=5432

# Admin Configuration
ADMIN_USER=admin
ADMIN_PASS=your_admin_password

# For Render deployment
RESET_DB=true  # Optional: enables database reset
```

## Troubleshooting

### Common Issues:

1. **Permission Denied**:
   - Ensure database user has CREATE/DROP privileges
   - Check database connection permissions

2. **Connection Errors**:
   - Verify database credentials
   - Check network connectivity
   - Ensure database server is running

3. **Migration Errors**:
   - Check for conflicting migrations
   - Verify all apps are properly configured
   - Review migration files for syntax errors

4. **Backup Failures**:
   - Ensure `pg_dump` is available
   - Check disk space for backup files
   - Verify backup directory permissions

### Debug Commands:

```bash
# Check database connection
python manage.py dbshell

# List all migrations
python manage.py showmigrations

# Check for migration conflicts
python manage.py makemigrations --dry-run

# Debug permissions
python manage.py debug_permissions
```

## Best Practices

1. **Always backup before reset** (nuclear reset does this automatically)
2. **Test in development first**
3. **Use force flags only in automated environments**
4. **Monitor the process closely**
5. **Have a rollback plan ready**
6. **Document any custom data that needs to be restored**

## Support

If you encounter issues with database reset:

1. Check the logs for detailed error messages
2. Verify all environment variables are set correctly
3. Ensure database user has sufficient privileges
4. Test the process in a development environment first
5. Contact the development team with specific error details 