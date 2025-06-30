"""
Django Management Command: Setup Super Admin
Robust super admin creation and verification
"""
from django.core.management.base import BaseCommand
from django.contrib.auth import authenticate
from authentication.models import User
from permissions.models import Role as OrgRole
from django.conf import settings
import os

class Command(BaseCommand):
    help = 'Creates or updates super admin user with robust verification'

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

        self.stdout.write(self.style.SUCCESS('🚀 SUPER-ADMIN SETUP & VERIFICATION'))
        self.stdout.write('=' * 50)
        
        # Get credentials
        admin_email = options.get('email') or getattr(settings, 'ADMIN_EMAIL', 'admin@example.com')
        admin_password = options.get('password') or getattr(settings, 'ADMIN_PASS', 'defaultpass')
        admin_username = options.get('username') or getattr(settings, 'ADMIN_USER', 'admin')
        
        self.stdout.write(f"👤 Email: {admin_email}")
        self.stdout.write(f"🏷️  Username: {admin_username}")
        
        try:
            user = self.check_and_create_superadmin(admin_email, admin_password, admin_username)
            if user:
                self.test_authentication(admin_email, admin_password)
                self.stdout.write(self.style.SUCCESS('\n🎉 SUPER-ADMIN READY!'))
                self.stdout.write(f"📧 Email: {admin_email}")
                self.stdout.write(f"🔑 Use for OTP: python manage.py shell")
            else:
                self.stdout.write(self.style.ERROR('❌ Failed to setup super-admin'))
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'❌ Error: {e}'))

    def check_and_create_superadmin(self, admin_email, admin_password, admin_username):
        """Check if super admin exists and create if needed"""
        self.stdout.write('\n🔍 CHECKING SUPER-ADMIN USER')
        self.stdout.write('-' * 40)
        
        # Ensure Super Admin role exists
        super_admin_role, created = OrgRole.objects.get_or_create(
            name='Super Admin',
            organization=None,
            defaults={'description': 'System Super Administrator'}
        )
        if created:
            self.stdout.write(self.style.SUCCESS('✅ Super Admin role created'))
        
        # Check if user exists
        user = User.objects.filter(email=admin_email).first()
        
        if user:
            self.stdout.write(f"✅ User found: {user.email}")
            self.stdout.write(f"   👤 Username: {user.username}")
            self.stdout.write(f"   🔰 Is Staff: {user.is_staff}")
            self.stdout.write(f"   🔱 Is Superuser: {user.is_superuser}")
            self.stdout.write(f"   ✅ Is Active: {user.is_active}")
            self.stdout.write(f"   🏢 Role: {user.role}")
            
            # Check password
            if user.check_password(admin_password):
                self.stdout.write("✅ Password is correct")
            else:
                self.stdout.write("❌ Password is incorrect")
                self.stdout.write("   🔧 Updating password...")
                user.set_password(admin_password)
                user.save()
                self.stdout.write("✅ Password updated")
            
            # Ensure user is super admin
            if not user.is_superuser or not user.is_staff or user.role != super_admin_role:
                self.stdout.write("🔧 Making user superuser...")
                user.is_superuser = True
                user.is_staff = True
                user.role = super_admin_role
                user.save()
                self.stdout.write("✅ User is now superuser")
            
        else:
            self.stdout.write("❌ User not found. Creating new super-admin...")
            
            # Create super admin user
            user = User.objects.create_superuser(
                username=admin_username,
                email=admin_email,
                password=admin_password,
            )
            user.role = super_admin_role
            user.save()
            self.stdout.write(f"✅ Super-admin created: {user.email}")
        
        # Show final status
        self.stdout.write('\n🎯 FINAL USER STATUS:')
        self.stdout.write(f"   📧 Email: {user.email}")
        self.stdout.write(f"   👤 Username: {user.username}")
        self.stdout.write(f"   🔰 Is Staff: {user.is_staff}")
        self.stdout.write(f"   🔱 Is Superuser: {user.is_superuser}")
        self.stdout.write(f"   ✅ Is Active: {user.is_active}")
        self.stdout.write(f"   🏢 Role: {user.role}")
        
        return user

    def test_authentication(self, admin_email, admin_password):
        """Test authentication with the credentials"""
        self.stdout.write('\n🔐 TESTING AUTHENTICATION')
        self.stdout.write('-' * 30)
        
        user = authenticate(username=admin_email, password=admin_password)
        if user:
            self.stdout.write(self.style.SUCCESS(f"✅ Authentication successful: {user.email}"))
            return True
        else:
            self.stdout.write(self.style.ERROR("❌ Authentication failed"))
            return False

    def list_all_users(self):
        """List all users in the system"""
        self.stdout.write('👥 ALL USERS IN SYSTEM')
        self.stdout.write('=' * 30)
        
        users = User.objects.all().select_related('role', 'role__organization')
        
        if users:
            for user in users:
                org_name = user.role.organization.name if user.role and user.role.organization else "System"
                role_display = f"{user.role.name} ({org_name})" if user.role else "None"
                self.stdout.write(f"📧 {user.email} | 👤 {user.username} | 🏢 {role_display} | 🔱 Super: {user.is_superuser}")
        else:
            self.stdout.write("❌ No users found")
        
        self.stdout.write(f"\n📊 Total users: {users.count()}") 