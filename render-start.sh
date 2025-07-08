#!/usr/bin/env bash
# exit on error
set -o errexit

# Change to backend directory to run management commands
cd backend

# Nuclear option: Reset database completely (ONE-TIME FIX)
echo "⚠️  NUCLEAR OPTION: Resetting database completely..."
echo "This will destroy all data and start fresh!"
python manage.py nuclear_reset_db --force
echo "✅ Database reset completed!"

# Run database migrations
echo "🔄 Running database migrations..."
python manage.py migrate

# Initialize the application with a superuser and mock data.
# This command will run on every startup.
# It is designed to be safe to re-run, but for a production environment
# with real data, you may want to run this only once.
echo "🚀 Initializing application..."
python manage.py initialize_app

# Fix deployment permission issues comprehensively
echo "🔧 Fixing deployment permissions..."
python manage.py fix_deployment_permissions

# Verify that all users have proper permissions
echo "🔍 Verifying user permissions..."
python manage.py check_permissions

# Generate rich, varied data for all API endpoints
echo "📊 Generating test data..."
python manage.py generate_rich_test_data

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