# 🚀 PRS Backend Setup Instructions

## Quick Setup (Recommended)

If you're setting up the PRS backend for the first time and want to avoid any field compatibility issues, use this automated setup script:

```bash
# 1. Navigate to the backend directory
cd backend

# 2. Activate your virtual environment
# Windows:
.venv\Scripts\activate
# or Linux/Mac:
source .venv/bin/activate

# 3. Run the automated setup script
python setup_fresh_environment.py
```

This script will:
- ✅ Install all dependencies
- ✅ Apply migrations in the correct order
- ✅ Handle field compatibility issues automatically
- ✅ Create the super admin user
- ✅ Verify everything is working

---

## Manual Setup (If you prefer step-by-step)

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 2: Apply Migrations (IMPORTANT ORDER)
```bash
# Apply core Django migrations first
python manage.py migrate auth
python manage.py migrate contenttypes
python manage.py migrate sessions
python manage.py migrate admin
python manage.py migrate authtoken

# Apply all remaining migrations
python manage.py migrate
```

### Step 3: Create Super Admin
```bash
# Use the enhanced setup command (handles field compatibility)
python manage.py setup_superadmin
```

---

## ❌ Troubleshooting "invalid field name for model role"

If you encounter the error `"invalid field name for model role"`, this is due to field naming compatibility between different migration states. Here are the solutions:

### Solution 1: Use the Enhanced Command (Recommended)
The `setup_superadmin` command has been updated to handle this automatically:

```bash
python manage.py setup_superadmin
```

The enhanced command will:
- 🔍 Detect whether your database uses 'role' or 'org_role' field
- 🛠️ Automatically use the correct field name
- 🧹 Clean up any duplicate roles
- ✅ Create the super admin regardless of field naming

### Solution 2: Use the Automated Setup Script
```bash
python setup_fresh_environment.py
```

### Solution 3: Manual Fallback
If both above solutions fail, use this manual approach:

```bash
python manage.py shell
```

Then run this in the Django shell:
```python
from authentication.models import User
from permissions.models import Role

# Create Super Admin role
role, created = Role.objects.get_or_create(
    name='Super Admin',
    organization=None,
    defaults={'description': 'System Super Administrator'}
)

# Create super admin user
user, created = User.objects.get_or_create(
    email='admin@example.com',
    defaults={
        'username': 'admin',
        'is_superuser': True,
        'is_staff': True,
        'is_active': True,
    }
)

# Set role (handles both 'role' and 'org_role' fields)
user_fields = [field.name for field in User._meta.fields]
if 'role' in user_fields:
    user.role = role
elif 'org_role' in user_fields:
    user.org_role = role

user.set_password('defaultpass')
user.save()

print(f"Super admin created: {user.email}")
print("Password: defaultpass")
```

---

## 🔐 Default Super Admin Credentials

After successful setup, use these credentials:

**Email:** `admin@example.com` (or the email from your settings)  
**Password:** `defaultpass` (or from your settings)

You can change these by updating the settings file or using command arguments:

```bash
python manage.py setup_superadmin --email your@email.com --password yourpassword --username yourusername
```

---

## ✅ Verification

After setup, verify everything is working:

```bash
# Check system status
python manage.py check

# List all users
python manage.py setup_superadmin --list-users

# Start development server
python manage.py runserver
```

Then visit:
- **Admin Panel:** http://127.0.0.1:8000/admin/
- **API Documentation:** http://127.0.0.1:8000/swagger/
- **ReDoc:** http://127.0.0.1:8000/redoc/

---

## 🐛 Common Issues and Solutions

### Issue: "No migrations to apply" but still getting field errors
**Solution:** The database might be in an inconsistent state. Try:
```bash
python manage.py migrate --fake-initial
python manage.py migrate
```

### Issue: Multiple "Super Admin" roles exist
**Solution:** The enhanced `setup_superadmin` command automatically cleans these up, or run:
```bash
python manage.py shell -c "from permissions.models import Role; Role.objects.filter(name='Super Admin', organization=None)[1:].delete()"
```

### Issue: Virtual environment not activated
**Solution:** Make sure your virtual environment is activated:
```bash
# Windows
.venv\Scripts\activate
# Linux/Mac
source .venv/bin/activate
```

### Issue: Unicode/Encoding errors on Windows
**Solution:** The setup scripts have been updated to handle Windows encoding properly. If you still encounter encoding issues, try:
```bash
# Set UTF-8 encoding in PowerShell (Windows)
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Or use Command Prompt instead of PowerShell
cmd
python setup_fresh_environment.py
```

### Issue: Permission denied errors
**Solution:** Check file permissions or run as administrator if necessary.

---

## 📧 Support

If you continue to experience issues:

1. Check the error message carefully
2. Try the automated setup script first: `python setup_fresh_environment.py`
3. Review the migration files in `authentication/migrations/`
4. Contact the development team with the full error output

---

## 🏗️ Development Environment Info

- **Python:** 3.8+ required
- **Django:** Latest version from requirements.txt
- **Database:** SQLite (default) or PostgreSQL
- **Key Apps:** authentication, permissions, organization, deals, etc.

The setup handles all field compatibility issues automatically, so you shouldn't encounter the "invalid field name" error when following these instructions. 