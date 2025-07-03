"""
Django Management Command: Setup Super Admin
Robust super admin creation and verification with field compatibility
"""
from django.core.management.base import BaseCommand
from django.contrib.auth import authenticate
from authentication.models import User
from permissions.models import Role as OrgRole
from django.conf import settings
from django.db import connection
import os

class Command(BaseCommand):
    help = 'Creates or updates super admin user with robust verification and field compatibility'

    def add_arguments(self, parser):
        parser.add_argument(
            '--email',
            type=str,
            help='Super admin email (default from settings)',
        )
        parser.add_argument(
            '--password',
            type=str,
            help='Super admin password (default from settings)',
        )
        parser.add_argument(
            '--username',
            type=str,
            help='Super admin username (default from settings)',
        )
        parser.add_argument(
            '--list-users',
            action='store_true',
            help='List all users in the system',
        )

    def handle(self, *args, **options):
        if options['list_users']:
            self.list_all_users()
            return

        self.stdout.write(self.style.SUCCESS('[SUCCESS] SUPER-ADMIN SETUP & VERIFICATION'))
        self.stdout.write('=' * 50)
        
        # Get credentials
        admin_email = options.get('email') or getattr(settings, 'ADMIN_EMAIL', 'admin@example.com')
        admin_password = options.get('password') or getattr(settings, 'ADMIN_PASS', 'defaultpass')
        admin_username = options.get('username') or getattr(settings, 'ADMIN_USER', 'admin')
        
        self.stdout.write(f"[USER] Email: {admin_email}")
        self.stdout.write(f"[NAME] Username: {admin_username}")
        
        try:
            # Detect role field name first
            role_field_name = self.detect_role_field_name()
            self.stdout.write(f"[DETECT] Detected role field name: {role_field_name}")
            
            user = self.check_and_create_superadmin(admin_email, admin_password, admin_username, role_field_name)
            if user:
                self.test_authentication(admin_email, admin_password)
                self.stdout.write(self.style.SUCCESS('\n[SUCCESS] SUPER-ADMIN READY!'))
                self.stdout.write(f"[EMAIL] Email: {admin_email}")
                self.stdout.write(f"[INFO] Use for OTP: python manage.py shell")
            else:
                self.stdout.write(self.style.ERROR('[ERROR] Failed to setup super-admin'))
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'[ERROR] Error: {e}'))
            # Additional debugging info
            self.stdout.write(self.style.WARNING('[DEBUG] Debugging info:'))
            self.stdout.write(f"   Django DB table columns: {self.get_user_table_columns()}")

    def detect_role_field_name(self):
        """Detect whether the role field is named 'role' or 'org_role'"""
        try:
            # Try to access the role field on the model
            test_user = User.objects.first()
            if test_user:
                # Try accessing role field
                try:
                    _ = test_user.role
                    return 'role'
                except AttributeError:
                    # Try org_role field
                    try:
                        _ = test_user.org_role
                        return 'org_role'
                    except AttributeError:
                        pass
            
            # Fallback: check model meta fields
            user_fields = [field.name for field in User._meta.fields]
            if 'role' in user_fields:
                return 'role'
            elif 'org_role' in user_fields:
                return 'org_role'
            else:
                # Check database table directly
                table_columns = self.get_user_table_columns()
                if 'role_id' in table_columns:
                    return 'role'
                elif 'org_role_id' in table_columns:
                    return 'org_role'
                    
        except Exception as e:
            self.stdout.write(self.style.WARNING(f'[WARNING] Field detection failed: {e}'))
        
        # Default to 'role' if detection fails
        return 'role'

    def get_user_table_columns(self):
        """Get actual database table columns for debugging"""
        try:
            with connection.cursor() as cursor:
                table_name = User._meta.db_table
                cursor.execute(f"PRAGMA table_info({table_name})")
                columns = [row[1] for row in cursor.fetchall()]
                return columns
        except Exception:
            return []

    def get_user_role(self, user, role_field_name):
        """Safely get user role using the detected field name"""
        try:
            return getattr(user, role_field_name, None)
        except AttributeError:
            return None

    def set_user_role(self, user, role, role_field_name):
        """Safely set user role using the detected field name"""
        try:
            setattr(user, role_field_name, role)
            return True
        except AttributeError:
            return False

    def check_and_create_superadmin(self, admin_email, admin_password, admin_username, role_field_name):
        """Check if super admin exists and create if needed"""
        self.stdout.write('\n[CHECK] CHECKING SUPER-ADMIN USER')
        self.stdout.write('-' * 40)
        
        # Ensure Super Admin role exists - handle duplicates
        super_admin_roles = OrgRole.objects.filter(name='Super Admin', organization=None)
        
        if super_admin_roles.exists():
            # Use the first one if multiple exist
            super_admin_role = super_admin_roles.first()
            if super_admin_roles.count() > 1:
                self.stdout.write(self.style.WARNING(f'[WARNING] Found {super_admin_roles.count()} duplicate Super Admin roles, using the first one (ID: {super_admin_role.id})'))
                # Optionally clean up duplicates
                duplicate_roles = super_admin_roles.exclude(id=super_admin_role.id)
                self.stdout.write(f'[CLEANUP] Cleaning up {duplicate_roles.count()} duplicate roles...')
                duplicate_roles.delete()
                self.stdout.write(self.style.SUCCESS('[SUCCESS] Duplicate roles cleaned up'))
            else:
                self.stdout.write('[SUCCESS] Super Admin role found')
        else:
            # Create new Super Admin role
            super_admin_role = OrgRole.objects.create(
                name='Super Admin',
                organization=None,
                description='System Super Administrator'
            )
            self.stdout.write(self.style.SUCCESS('[SUCCESS] Super Admin role created'))
        
        # Check if user exists
        user = User.objects.filter(email=admin_email).first()
        
        if user:
            self.stdout.write(f"[SUCCESS] User found: {user.email}")
            self.stdout.write(f"   [USER] Username: {user.username}")
            self.stdout.write(f"   [STAFF] Is Staff: {user.is_staff}")
            self.stdout.write(f"   [SUPER] Is Superuser: {user.is_superuser}")
            self.stdout.write(f"   [ACTIVE] Is Active: {user.is_active}")
            self.stdout.write(f"   [ROLE] Role: {self.get_user_role(user, role_field_name)}")
            
            # Check password
            if user.check_password(admin_password):
                self.stdout.write("[SUCCESS] Password is correct")
            else:
                self.stdout.write("[ERROR] Password is incorrect")
                self.stdout.write("   [UPDATE] Updating password...")
                user.set_password(admin_password)
                user.save()
                self.stdout.write("[SUCCESS] Password updated")
            
            # Ensure user is super admin
            if not user.is_superuser or not user.is_staff or self.get_user_role(user, role_field_name) != super_admin_role:
                self.stdout.write("[UPDATE] Making user superuser...")
                user.is_superuser = True
                user.is_staff = True
                self.set_user_role(user, super_admin_role, role_field_name)
                user.save()
                self.stdout.write("[SUCCESS] User is now superuser")
            
        else:
            self.stdout.write("[ERROR] User not found. Creating new super-admin...")
            
            # Create super admin user
            user = User.objects.create_superuser(
                username=admin_username,
                email=admin_email,
                password=admin_password,
            )
            self.set_user_role(user, super_admin_role, role_field_name)
            user.save()
            self.stdout.write(f"[SUCCESS] Super-admin created: {user.email}")
        
        # Show final status
        self.stdout.write('\n[STATUS] FINAL USER STATUS:')
        self.stdout.write(f"   [EMAIL] Email: {user.email}")
        self.stdout.write(f"   [USER] Username: {user.username}")
        self.stdout.write(f"   [STAFF] Is Staff: {user.is_staff}")
        self.stdout.write(f"   [SUPER] Is Superuser: {user.is_superuser}")
        self.stdout.write(f"   [ACTIVE] Is Active: {user.is_active}")
        self.stdout.write(f"   [ROLE] Role: {self.get_user_role(user, role_field_name)}")
        
        return user

    def test_authentication(self, admin_email, admin_password):
        """Test authentication with the credentials"""
        self.stdout.write('\n[AUTH] TESTING AUTHENTICATION')
        self.stdout.write('-' * 30)
        
        user = authenticate(username=admin_email, password=admin_password)
        if user:
            self.stdout.write(self.style.SUCCESS(f"[SUCCESS] Authentication successful: {user.email}"))
            return True
        else:
            self.stdout.write(self.style.ERROR("[ERROR] Authentication failed"))
            return False

    def list_all_users(self):
        """List all users in the system"""
        self.stdout.write('[USERS] ALL USERS IN SYSTEM')
        self.stdout.write('=' * 30)
        
        try:
            # Detect role field name
            role_field_name = self.detect_role_field_name()
            self.stdout.write(f"[DETECT] Using role field: {role_field_name}")
            
            users = User.objects.all().select_related(f'{role_field_name}', f'{role_field_name}__organization')
            
            if users:
                for user in users:
                    user_role = self.get_user_role(user, role_field_name)
                    if user_role and hasattr(user_role, 'organization') and user_role.organization:
                        org_name = user_role.organization.name
                        role_display = f"{user_role.name} ({org_name})"
                    elif user_role:
                        role_display = f"{user_role.name} (System Role)"
                    else:
                        role_display = "None"
                    
                    self.stdout.write(f"[EMAIL] {user.email} | [USER] {user.username} | [ROLE] {role_display} | [SUPER] {user.is_superuser}")
            else:
                self.stdout.write("[ERROR] No users found")
            
            self.stdout.write(f"\n[COUNT] Total users: {users.count()}")
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'[ERROR] Error listing users: {e}'))
            # Fallback: simple listing without role info
            users = User.objects.all()
            for user in users:
                self.stdout.write(f"[EMAIL] {user.email} | [USER] {user.username} | [SUPER] {user.is_superuser}")
            self.stdout.write(f"\n[COUNT] Total users: {users.count()}")