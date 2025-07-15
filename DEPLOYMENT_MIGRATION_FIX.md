# Deployment Migration Fix Guide

## Problem
When deploying to production environments (like Render), you may encounter migration conflicts where Django tries to apply migrations that reference columns that don't exist in the production database.

## Common Error
```
psycopg.errors.UndefinedColumn: column "avatar" of relation "authentication_user" does not exist
```

## Root Cause
This happens when:
1. Local development has different migration history than production
2. Production database was created with a different schema state
3. Manual database changes were made without proper migrations

## Solutions

### Solution 1: Use the Fix Script (Recommended)
Run the deployment fix script before migrations:

```bash
# In your deployment environment
python scripts/fix_deployment_migrations.py
python manage.py migrate
```

### Solution 2: Use the Management Command
```bash
python manage.py fix_migration_conflicts
python manage.py migrate
```

### Solution 3: Manual Database Fix
Connect to your production database and run:

```sql
-- Check if avatar column exists and remove it
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'authentication_user' 
        AND column_name = 'avatar'
    ) THEN
        ALTER TABLE authentication_user DROP COLUMN avatar;
    END IF;
END $$;

-- Check if login_count column exists and add it if not
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'authentication_user' 
        AND column_name = 'login_count'
    ) THEN
        ALTER TABLE authentication_user ADD COLUMN login_count integer DEFAULT 0;
    END IF;
END $$;
```

### Solution 4: Update Render Build Script
Add this to your `render-build.sh`:

```bash
#!/usr/bin/env bash
# exit on error
set -o errexit

# Install dependencies
pip install -r requirements.txt

# Fix migration conflicts before running migrations
python scripts/fix_deployment_migrations.py

# Run migrations
python manage.py migrate

# Collect static files
python manage.py collectstatic --no-input
```

## Prevention

### 1. Always Use Migrations
Never make manual database changes. Always create and apply migrations:

```bash
python manage.py makemigrations
python manage.py migrate
```

### 2. Test Migrations Locally
Before deploying, test your migrations on a fresh database:

```bash
# Create a test database
createdb test_db
python manage.py migrate --database=test_db
```

### 3. Use Migration Safety Checks
Add this to your deployment process:

```bash
python manage.py check_migration_safety
```

## Emergency Recovery

If migrations fail completely:

1. **Backup your database**
2. **Reset migrations** (if safe):
   ```bash
   python manage.py migrate --fake-initial
   ```
3. **Recreate migrations**:
   ```bash
   python manage.py makemigrations --empty authentication
   # Then manually add the operations
   ```

## Monitoring

Add these checks to your deployment pipeline:

```bash
# Check migration status
python manage.py showmigrations

# Check for migration conflicts
python manage.py fix_migration_conflicts --dry-run
```

## Files Created

- `backend/authentication/migrations/0006_fix_avatar_login_count_conflict.py` - Safe migration
- `backend/authentication/management/commands/fix_migration_conflicts.py` - Management command
- `backend/scripts/fix_deployment_migrations.py` - Deployment script
- `DEPLOYMENT_MIGRATION_FIX.md` - This guide

## Next Steps

1. Commit these files to your repository
2. Update your deployment scripts to include the fix script
3. Test the deployment process locally
4. Deploy to production with the new safety measures 