# 🚀 Quick Fix for Render Deployment Issue

## The Problem
You're getting this error during deployment:
```
psycopg.OperationalError: [Errno -2] Name or service not known
```

This means your Django app can't connect to the PostgreSQL database.

## ✅ Quick Solution

### Step 1: Update Your Render Service
1. Go to your Render dashboard
2. Open your web service settings
3. Change the **Start Command** to: `./render-start-safe.sh`
4. Save and redeploy

### Step 2: What This Does
The new `render-start-safe.sh` script will:
- ✅ Check if database is ready
- ✅ Wait up to 5 minutes for database initialization
- ✅ Fall back to SQLite if PostgreSQL fails
- ✅ Continue deployment even if database operations fail
- ✅ Provide detailed logging

## 🔧 Alternative Solutions

### Option 1: Check Your Database Setup
1. Ensure you have a PostgreSQL service on Render
2. Link it to your web service
3. Verify environment variables are set:
   - **Recommended**: `DATABASE_URL` (automatically set when linking database)
   - **Legacy**: Individual variables:
     - `DB_NAME`
     - `DB_HOST`
     - `DB_USER`
     - `DB_PASSWORD`
     - `DB_PORT` (usually 5432)
     - `DB_ENGINE` (django.db.backends.postgresql)

### Option 2: Use SQLite Temporarily
1. Remove all `DB_*` environment variables
2. Django will automatically use SQLite
3. Deploy and test your application
4. Switch back to PostgreSQL later

### Option 3: Run Diagnostics
```bash
# Check database connection
python backend/debug_database.py

# Check environment variables
python setup_render_env.py check

# Get setup instructions
python setup_render_env.py help
```

## 📋 Required Environment Variables

Make sure these are set in your Render service:

```
# Recommended (automatically set when linking database)
DATABASE_URL=postgresql://user:password@host:port/database

# Legacy approach (if DATABASE_URL not available)
DB_NAME=your_database_name
DB_HOST=your_database_host
DB_USER=your_database_user
DB_PASSWORD=your_database_password
DB_PORT=5432
DB_ENGINE=django.db.backends.postgresql

# Other required variables
SECRET_KEY=your_generated_secret_key
DEBUG=False
```

## 🎯 Most Likely Cause
The database service is still initializing. PostgreSQL databases on Render take 2-5 minutes to be ready. The safe startup script handles this automatically.

## 🆕 New Issue: Missing Database Tables
If you see errors like `relation "notifications_notification" does not exist`, it means:
- Database connection is working ✅
- But database tables don't exist yet ❌
- Migrations need to be run first

### Quick Fix for Missing Tables:
1. **Use the safe startup script** (recommended):
   - Set Start Command to: `./render-start-safe.sh`
   - This automatically runs migrations before other operations

2. **Manual fix** (if needed):
   ```bash
   # Run migrations first
   python manage.py migrate
   
   # Then run initialization
   python manage.py initialize_app
   ```

3. **Fresh database reset** (if tables are corrupted):
   ```bash
   python backend/reset_database.py
   ```

## 📞 Need Help?
1. Run `python backend/debug_database.py` for detailed diagnostics
2. Check the Render service logs
3. Verify your database service is running
4. Contact Render support if database is not accessible

## 🚀 Files Created/Updated
- `render-start-safe.sh` - New safe startup script
- `backend/debug_database.py` - Comprehensive diagnostics
- `backend/check_and_run_migrations.py` - Migration checker and runner
- `backend/reset_database.py` - Database reset tool
- `setup_render_env.py` - Environment setup helper
- `DEPLOYMENT_TROUBLESHOOTING.md` - Updated troubleshooting guide 