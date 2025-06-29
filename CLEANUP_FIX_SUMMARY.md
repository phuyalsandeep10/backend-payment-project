# Critical Fix: Foreign Key Constraint Issue in Test Cleanup

## Problem Description

**Critical Defect**: When running API tests multiple times without restarting the Django server, the second and subsequent test runs would fail due to cascading foreign key relationship issues.

### Root Cause

1. **Protected Foreign Keys**: The `Deal.created_by` field has `on_delete=models.PROTECT` constraint
2. **Incomplete Cleanup**: The original cleanup function didn't handle cascading relationships properly
3. **Data Persistence**: Data from the first test run remained in the database, causing conflicts

### Error Symptoms

```
django.db.models.deletion.ProtectedError: ("Cannot delete some instances of model 'User' because they are referenced through protected foreign keys: 'Deal.created_by'.", {<Deal: DLID0001 - Global Corp>})
```

## Solution Implemented

### 1. Improved API-Based Cleanup (`api_test.py`)

**Enhanced cleanup order**:
1. Delete clients (cascades to deals and payments)
2. Delete users (now safe after deals are gone)
3. Delete roles
4. Delete organization

**Better error handling**:
- Added status code verification
- Graceful handling of duplicate user creation
- Comprehensive verification steps

### 2. Django Management Command Fallback

Created `backend/authentication/management/commands/cleanup_test_data.py`:

**Features**:
- `--dry-run`: Preview what will be deleted
- `--force`: Force cleanup even when deals exist
- `--org-name`: Specify organization to clean up
- Raw SQL deletion to bypass PROTECT constraints

**Usage**:
```bash
# Preview cleanup
python manage.py cleanup_test_data --dry-run

# Force cleanup
python manage.py cleanup_test_data --force

# Clean specific organization
python manage.py cleanup_test_data --org-name "Company Name" --force
```

### 3. Model Configuration Fix

**Removed invalid dependency**:
- Removed `'rest_framework_nested'` from `INSTALLED_APPS` in `settings.py`
- This was causing import errors as it's a library, not a Django app

### 4. Test Script Improvements

**Enhanced `api_test.py`**:
- Better error handling for user creation conflicts
- Automatic fallback to management command when API cleanup fails
- Detailed logging and verification steps
- Improved status tracking throughout the test process

## Files Modified

1. `api_test.py` - Enhanced cleanup logic and error handling
2. `backend/authentication/management/commands/cleanup_test_data.py` - New management command
3. `backend/backend/settings.py` - Removed invalid app from INSTALLED_APPS

## Prevention Strategy

### For Production
- Keep `on_delete=models.PROTECT` for data integrity
- Implement proper soft deletion if needed
- Use the management command for maintenance cleanup

### For Testing
- Always run cleanup before each test suite
- Use the management command as fallback
- Consider using Django's `TransactionTestCase` for isolation

## Verification

The fix has been tested and verified:
1. ✅ Management command works correctly
2. ✅ API cleanup handles errors gracefully  
3. ✅ Fallback mechanism activates when needed
4. ✅ Foreign key constraints are properly bypassed
5. ✅ No data persistence between test runs

## Impact

This fix resolves a **critical production defect** that would prevent:
- Continuous integration pipelines
- Repeated testing scenarios  
- Development workflow efficiency
- Database maintenance operations

The solution maintains data integrity in production while enabling reliable testing and cleanup operations. 