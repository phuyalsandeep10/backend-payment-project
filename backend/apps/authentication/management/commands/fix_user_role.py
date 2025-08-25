from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from apps.organization.models import Organization
from apps.permissions.models import Role

User = get_user_model()

class Command(BaseCommand):
    help = 'Manually fix user role assignment for testing'

    def add_arguments(self, parser):
        parser.add_argument(
            '--email',
            type=str,
            help='Email of the user to fix',
        )

    def handle(self, *args, **options):
        email = options['email']
        
        if not email:
            self.stdout.write("❌ Please provide an email with --email")
            return
        
        try:
            # Find the user
            user = User.objects.get(email=email)
            self.stdout.write(f"Found user: {user.email} (ID: {user.id})")
            self.stdout.write(f"Current organization: {user.organization.name if user.organization else 'None'}")
            self.stdout.write(f"Current role: {user.role.name if user.role else 'None'}")
            
            if not user.organization:
                self.stdout.write("❌ User has no organization assigned")
                return
            
            # Find the Organization Admin role for this organization
            org_admin_role = Role.objects.filter(
                name="Organization Admin", 
                organization=user.organization
            ).first()
            
            if not org_admin_role:
                self.stdout.write("❌ Organization Admin role not found for this organization")
                return
            
            self.stdout.write(f"Found Organization Admin role: {org_admin_role.name} (ID: {org_admin_role.id})")
            
            # Assign the role
            user.role = org_admin_role
            user.save()
            
            self.stdout.write(f"✅ Successfully assigned role {org_admin_role.name} to user {user.email}")
            
            # Verify the change
            user.refresh_from_db()
            self.stdout.write(f"User role after fix: {user.role.name if user.role else 'None'}")
            
        except User.DoesNotExist:
            self.stdout.write(f"❌ User with email {email} not found")
        except Exception as e:
            self.stdout.write(f"❌ Error: {e}")
        
        self.stdout.write("\n=== Fix Complete ===")
