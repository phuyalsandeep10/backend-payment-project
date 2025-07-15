#!/usr/bin/env bash
# exit on error
set -o errexit

# Change to backend directory to run management commands
cd backend


echo "🧹 Cleaning up duplicate permissions (safe)..."
python manage.py cleanup_permissions

echo "🔧 Running comprehensive permission fix..."
python manage.py fix_deployment_permissions

echo "🚀 Initializing app with demo data 
and users (idempotent)..."
python manage.py initialize_app --flush
python manage.py reset_permissions --force
echo "🔍 Verifying user permissions..."
python manage.py check_permissions

echo "📊 Generating additional rich test data..."
python manage.py generate_rich_test_data --deals 100 --clients 30 --projects 19

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
gunicorn core_config.wsgi:application --bind 0.0.0.0:$PORT