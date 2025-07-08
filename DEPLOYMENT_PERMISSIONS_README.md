# Deployment Permissions Fix Guide

This guide explains the fixes implemented to resolve permission and unauthorized errors in the PRS backend deployment.

## Problem Summary

The main issue was that users were getting 403 Forbidden errors when accessing API endpoints, even though they had the correct roles and permissions. This was happening because:

1. Permissions weren't being properly created during deployment
2. Roles weren't being assigned the correct permissions
3. Users weren't being properly linked to their roles
4. The deployment scripts weren't comprehensive enough

## Files Modified/Created

### 1. `render-build.sh` (Updated)
- Added comprehensive permission creation steps
- Ensures all permissions are created before assignment
- Added verification steps

### 2. `render-start.sh` (Updated)
- Added comprehensive permission fixing using `fix_deployment_permissions`
- Added verification steps to ensure permissions are working
- Added final verification for sales@innovate.com user

### 3. `backend/authentication/management/commands/fix_deployment_permissions.py` (New)
- Comprehensive command to fix all deployment permission issues
- Creates missing organizations, roles, and permissions
- Assigns proper permissions to roles
- Fixes user-role assignments
- Verifies critical permissions exist

### 4. `backend/verify_deployment_permissions.py` (New)
- Standalone script to verify deployment permissions
- Checks organizations, roles, users, and permissions
- Simulates dashboard access conditions

### 5. `backend/test_api_access.py` (New)
- Tests API access for different user roles
- Verifies that endpoints return correct status codes
- Helps identify permission issues

## How the Fix Works

### Step 1: Permission Creation
The build script now creates all necessary permissions:
```bash
python manage.py create_all_permissions
python manage.py create_deal_permissions
```

### Step 2: Permission Assignment
The start script runs comprehensive permission fixing:
```bash
python manage.py fix_deployment_permissions
```

This command:
- Ensures organizations exist
- Creates all permissions
- Creates roles for each organization
- Assigns proper permissions to each role
- Fixes user-role assignments
- Verifies critical permissions

### Step 3: Verification
Multiple verification steps ensure everything is working:
```bash
python manage.py check_permissions
python manage.py shell -c "..." # Final verification
```

## Testing the Fix

### Local Testing
1. Run the verification script:
```bash
cd backend
python verify_deployment_permissions.py
```

2. Test API access:
```bash
python test_api_access.py
```

### Production Testing
After deployment, test these endpoints:

**Salesperson (sales@innovate.com):**
- `GET /api/v1/dashboard/dashboard/` - Should return 200
- `GET /api/v1/clients/` - Should return 200
- `GET /api/v1/deals/deals/` - Should return 200

**Verifier (verifier@innovate.com):**
- `GET /api/v1/verifier/dashboard/` - Should return 200
- `GET /api/v1/verifier/invoices/` - Should return 200

## Expected Results

After the fix, you should see:

1. **No 403 Forbidden errors** for properly authenticated users
2. **Proper role-based access** - users can only access endpoints for their role
3. **All critical permissions present** for each role
4. **Users properly assigned to roles** with correct organizations

## Troubleshooting

### If you still get 403 errors:

1. **Check if permissions exist:**
```bash
python manage.py shell -c "
from django.contrib.auth.models import Permission
print('Total permissions:', Permission.objects.count())
"
```

2. **Check user role assignment:**
```bash
python manage.py shell -c "
from authentication.models import User
user = User.objects.get(email='sales@innovate.com')
print(f'Role: {user.role}')
print(f'Organization: {user.organization}')
"
```

3. **Check role permissions:**
```bash
python manage.py shell -c "
from permissions.models import Role
role = Role.objects.get(name='Salesperson')
perms = list(role.permissions.values_list('codename', flat=True))
print(f'Salesperson permissions: {perms}')
"
```

4. **Run the fix command manually:**
```bash
python manage.py fix_deployment_permissions
```

### If users don't exist:

1. **Run initialization:**
```bash
python manage.py initialize_app
```

2. **Then run permission fix:**
```bash
python manage.py fix_deployment_permissions
```

## Key Permissions for Each Role

### Salesperson
- `view_all_deals`, `create_deal`, `edit_deal`, `delete_deal`
- `view_all_clients`, `create_new_client`, `edit_client_details`
- `view_all_teams`, `view_all_projects`, `view_all_commissions`

### Verifier
- `view_payment_verification_dashboard`
- `verify_deal_payment`, `verify_payments`
- `manage_invoices`, `access_verification_queue`
- `view_audit_logs`

### Organization Admin
- All permissions except super admin specific ones
- User management, team management, etc.

## Deployment Checklist

Before deploying, ensure:

- [ ] All migration files are committed
- [ ] `render-build.sh` and `render-start.sh` are updated
- [ ] New management commands are committed
- [ ] Test scripts are available for verification

After deployment:

- [ ] Check deployment logs for permission setup messages
- [ ] Run verification script to confirm permissions
- [ ] Test API endpoints with different user roles
- [ ] Verify no 403 errors for authenticated users

## Notes

- The `fix_deployment_permissions` command is idempotent - safe to run multiple times
- All commands include proper error handling and rollback
- The verification steps help identify issues before they affect users
- The test scripts can be run locally or on the deployment to verify functionality 