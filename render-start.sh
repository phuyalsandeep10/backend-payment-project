#!/usr/bin/env bash
# exit on error
set -o errexit

# Change to backend directory to run management commands
cd backend


echo "🧹 Cleaning up duplicate permissions (safe)..."
python manage.py cleanup_permissions

echo "🔧 Running comprehensive permission fix..."
python manage.py fix_deployment_permissions

# -----------------------------------------------------------------------------
# Seed database with real data (if empty) and set up permissions
# -----------------------------------------------------------------------------

echo "🗄️  Seeding database with initial data (if empty)..."
python - <<'PY'
"""Flush the database then load seed data from initial_data.json.
Fails with an explicit message if fixture not found."""
import os, sys, django
from pathlib import Path
from django.core.management import call_command

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')

django.setup()

base_dir = Path(__file__).resolve().parent
candidate_paths = [
    base_dir / 'initial_data.json',
    base_dir / 'backend' / 'initial_data.json',
    base_dir / 'fixtures' / 'initial_data.json',
]
fixture = next((p for p in candidate_paths if p.is_file()), None)
if not fixture:
    sys.stderr.write("❌ initial_data.json fixture not found. Add it to the repository before deployment.\n")
    sys.exit(1)

print("🧹 Flushing existing database data ...")
call_command('flush', '--noinput')
print(f"📥 Importing seed data from {fixture} ...")
call_command('loaddata', str(fixture), verbosity=0)
print("✅ Seed data imported successfully.")
PY

# Re-initialise any dynamic setup (without flush so we keep imported data)
echo "🔧 Initialising app (signals, default roles, etc.)..."
python manage.py initialize_app
python manage.py reset_permissions --force

# -----------------------------------------------------------------------------
# Ensure superadmin exists/updated
# -----------------------------------------------------------------------------

echo "👤 Ensuring superadmin account exists..."
python - <<'PY'
import os, django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')

django.setup()
from authentication.models import User

email = "shishirkafle18@gmail.com"
password = "password123"

user, created = User.objects.get_or_create(email=email, defaults={"is_staff": True, "is_superuser": True})
if not created:
    user.is_superuser = True
    user.is_staff = True
    print("ℹ️  Superadmin already exists – updating password and flags.")
else:
    print("✅ Superadmin created.")

user.set_password(password)
user.save()
PY

echo "🔍 Verifying user permissions..."
python manage.py check_permissions

# echo "📊 Skipping generation of dummy rich test data (using real seed instead)"

echo "🔍 Final verification - checking user permissions..."
python manage.py shell -c "
from authentication.models import User
from permissions.models import Role
try:
    # Check sales user
    sales_user = User.objects.get(email='sales@innovate.com')
    print(f'✅ Sales user found: {sales_user.email}')
    print(f'   Role: {sales_user.role}')
    if sales_user.role:
        permissions = list(sales_user.role.permissions.values_list('codename', flat=True))
        print(f'   Permissions count: {len(permissions)}')
        if 'view_all_deals' in permissions and 'create_deal' in permissions:
            print('✅ Salesperson has required permissions!')
        else:
            print('❌ Salesperson missing required permissions!')
    else:
        print('❌ Sales user has no role assigned!')
        
    # Check verifier user
    verifier_user = User.objects.get(username='verifier')
    print(f'✅ Verifier user found: {verifier_user.username}')
    print(f'   Role: {verifier_user.role}')
    if verifier_user.role:
        permissions = list(verifier_user.role.permissions.values_list('codename', flat=True))
        print(f'   Permissions count: {len(permissions)}')
        if 'view_payment_verification_dashboard' in permissions and 'verify_deal_payment' in permissions:
            print('✅ Verifier has required permissions!')
        else:
            print('❌ Verifier missing required permissions!')
    else:
        print('❌ Verifier user has no role assigned!')
        
except User.DoesNotExist as e:
    print(f'❌ User not found: {e}')
except Exception as e:
    print(f'❌ Error: {e}')
"

python scripts/fix_missing_permissions.py
echo "🎉 Application startup complete!"

# Start the Gunicorn server.
# We are already in the 'backend' directory, so we point to 'core_config.wsgi'.
echo "🚀 Starting Gunicorn server..."
# Start ASGI server (supports WebSockets)
daphne -b 0.0.0.0 -p $PORT core_config.asgi:application