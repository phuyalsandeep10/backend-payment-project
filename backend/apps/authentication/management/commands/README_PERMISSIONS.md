# Permission Management Commands

This directory contains Django management commands for managing permissions and roles in the PRS system.

## Commands Overview

### 1. `setup_permissions` - Main Setup Command
**Purpose:** Complete permission setup in the correct order
**Usage:** `python manage.py setup_permissions`
**What it does:**
- Cleans up orphaned permission assignments
- Creates all missing permissions
- Creates deal-specific permissions (backward compatibility)
- Assigns permissions to roles

**Options:**
- `--organization`: Process specific organization only
- `--role`: Process specific role only
- `--skip-permission-creation`: Skip creating permissions (assume they exist)

### 2. `create_all_permissions` - Create Permissions
**Purpose:** Create all custom and standard permissions
**Usage:** `python manage.py create_all_permissions`
**What it does:**
- Creates all custom permissions for deals, clients, teams, etc.
- Creates standard Django permissions (add, change, delete, view)
- Handles duplicates gracefully

### 3. `assign_role_permissions` - Assign Permissions to Roles
**Purpose:** Assign permissions to roles based on their responsibilities
**Usage:** `python manage.py assign_role_permissions`
**What it does:**
- Assigns permissions to Super Admin, Organization Admin, Salesperson, and Verifier roles
- Uses safe permission lookup to avoid foreign key violations
- Provides detailed logging and error handling

**Options:**
- `--organization`: Process specific organization only
- `--role`: Process specific role only

### 4. `cleanup_permissions` - Clean Up Orphaned Assignments
**Purpose:** Remove orphaned permission assignments
**Usage:** `python manage.py cleanup_permissions`
**What it does:**
- Finds and removes permission assignments that reference non-existent permissions
- Verifies all required permissions exist
- Shows statistics about current permission state

### 5. `check_permissions` - Debug Permissions
**Purpose:** Show current state of permissions in the database
**Usage:** `python manage.py check_permissions`
**What it does:**
- Lists all permissions grouped by model
- Shows permission IDs and names
- Useful for debugging permission issues

**Options:**
- `--model`: Filter by model name
- `--codename`: Filter by permission codename

### 6. `debug_permissions` - Debug Permission Issues
**Purpose:** Debug specific permission problems
**Usage:** `python manage.py debug_permissions`
**What it does:**
- Shows database statistics
- Checks for specific problematic permission IDs
- Lists role-permission assignments
- Identifies orphaned assignments

### 7. `reset_permissions` - Nuclear Reset (Use with caution!)
**Purpose:** Completely reset all permissions and roles
**Usage:** `python manage.py reset_permissions --force`
**What it does:**
- Deletes ALL roles and their permission assignments
- Deletes ALL custom permissions
- Recreates everything from scratch
- **WARNING:** This will delete all role assignments!

## Production Deployment

### For Render Deployment
The `render-build.sh` script automatically runs:
1. `cleanup_permissions` - Clean up any orphaned assignments
2. `setup_permissions` - Complete permission setup

### Manual Production Setup
```bash
# 1. Clean up any existing issues
python manage.py cleanup_permissions

# 2. Create all permissions
python manage.py create_all_permissions

# 3. Assign permissions to roles
python manage.py assign_role_permissions
```

## Troubleshooting

### Foreign Key Violation Error
If you see: `Key (permission_id)=(30) is not present in table "permissions_permission"`

**Solution:**
```bash
# 1. Debug the issue
python manage.py debug_permissions

# 2. Clean up orphaned assignments
python manage.py cleanup_permissions

# 3. Recreate permissions
python manage.py create_all_permissions

# 4. Reassign permissions
python manage.py assign_role_permissions
```

### Nuclear Option (Last Resort)
If all else fails:
```bash
python manage.py reset_permissions --force
```

### Permission Not Found Warnings
If you see warnings about missing permissions:
```bash
# Create missing permissions
python manage.py create_all_permissions

# Then assign them
python manage.py assign_role_permissions
```

## Role Permissions Overview

### Super Admin
- **All permissions** (142 total)
- Can access everything in the system

### Organization Admin
- **66-82 permissions** (varies by organization)
- User management, client management, deal management
- Project and team management
- Commission management
- Payment and invoice management

### Salesperson
- **24-75 permissions** (varies by organization)
- View own clients and deals
- Create and edit deals
- Project and team management
- Commission viewing

### Verifier
- **20-54 permissions** (varies by organization)
- Payment verification
- Invoice management
- Audit logs
- Verification queue access

## Best Practices

1. **Always run `setup_permissions` after migrations**
2. **Use `cleanup_permissions` if you see foreign key violations**
3. **Use `debug_permissions` to investigate issues**
4. **Never manually edit permission assignments in the database**
5. **Test permission changes locally before deploying**

## File Locations

- **Commands:** `backend/authentication/management/commands/`
- **Build Script:** `render-build.sh`
- **Models:** `backend/permissions/models.py`
- **Permissions:** `backend/*/permissions.py`

## Support

If you encounter permission issues:
1. Run `python manage.py debug_permissions`
2. Check the output for orphaned assignments
3. Run `python manage.py cleanup_permissions`
4. If problems persist, use the nuclear reset option 