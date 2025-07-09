#!/usr/bin/env bash
# exit on error
set -o errexit

# Change to backend directory to run management commands
cd backend

# Step 1: Flush existing data and create base structure
echo "🔄 Flushing existing data and creating base structure..."
python manage.py initialize_app --flush
echo "✅ Base data structure created!"

# Step 2: Run migrations (in case of any pending migrations)
echo "🔄 Running database migrations..."
python manage.py migrate

# Step 3: Fix deployment permission issues comprehensively
echo "🔧 Fixing deployment permissions..."
python manage.py fix_deployment_permissions

# Step 4: Verify that all users have proper permissions
echo "🔍 Verifying user permissions..."
python manage.py check_permissions

# Step 5: Generate additional rich, varied data for comprehensive testing
echo "📊 Generating additional rich test data..."
python manage.py generate_rich_test_data --deals 30 --clients 5 --projects 3

# Final verification - check if sales@innovate.com user has proper permissions
echo "�� Final verification - checking sales user permissions..."
python manage.py shell -c "
from authentication.models import User
from permissions.models import Role
try:
    user = User.objects.get(email='sales@innovate.com')
    print(f'✅ User found: {user.email}')
    print(f'   Role: {user.role}')
    print(f'   Organization: {user.organization}')
    if user.role:
        permissions = list(user.role.permissions.values_list('codename', flat=True))
        print(f'   Permissions count: {len(permissions)}')
        if 'view_all_deals' in permissions and 'create_deal' in permissions:
            print('✅ Salesperson has required permissions!')
        else:
            print('❌ Salesperson missing required permissions!')
    else:
        print('❌ User has no role assigned!')
except User.DoesNotExist:
    print('❌ Sales user not found!')
except Exception as e:
    print(f'❌ Error: {e}')
"

echo "🎉 Application startup complete!"

# Start the Gunicorn server.
# We are already in the 'backend' directory, so we point to 'core_config.wsgi'.
echo "🚀 Starting Gunicorn server..."
gunicorn core_config.wsgi:application --bind 0.0.0.0:$PORT