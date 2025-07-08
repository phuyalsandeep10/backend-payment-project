from django.core.management.base import BaseCommand
from django.contrib.auth.models import Permission
from permissions.models import Role
from organization.models import Organization

class Command(BaseCommand):
    help = 'Debug permission issues by showing current state of permissions and role assignments'

    def handle(self, *args, **options):
        self.stdout.write(self.style.HTTP_INFO("🔍 Debugging permission state..."))
        
        # Check total counts
        total_permissions = Permission.objects.count()
        total_roles = Role.objects.count()
        total_organizations = Organization.objects.count()
        
        self.stdout.write(f"📊 Database Statistics:")
        self.stdout.write(f"  - Total permissions: {total_permissions}")
        self.stdout.write(f"  - Total roles: {total_roles}")
        self.stdout.write(f"  - Total organizations: {total_organizations}")
        
        # Check for specific problematic permission ID
        self.stdout.write(f"\n🔍 Checking for permission ID 30 (the problematic one):")
        try:
            perm_30 = Permission.objects.get(id=30)
            self.stdout.write(f"  ✅ Permission ID 30 exists: {perm_30.codename} - {perm_30.name}")
        except Permission.DoesNotExist:
            self.stdout.write(f"  ❌ Permission ID 30 does NOT exist!")
        
        # Show all permissions with their IDs
        self.stdout.write(f"\n📋 All permissions (ID, codename, name):")
        for perm in Permission.objects.all().order_by('id')[:20]:  # Show first 20
            self.stdout.write(f"  {perm.id:3d}: {perm.codename:30s} - {perm.name}")
        
        if Permission.objects.count() > 20:
            self.stdout.write(f"  ... and {Permission.objects.count() - 20} more permissions")
        
        # Check role-permission assignments
        self.stdout.write(f"\n📋 Role-permission assignments:")
        for role in Role.objects.all():
            permission_count = role.permissions.count()
            self.stdout.write(f"  Role '{role.name}' ({role.organization.name if role.organization else 'No Org'}): {permission_count} permissions")
            
            # Show first few permission IDs for this role
            if permission_count > 0:
                perm_ids = list(role.permissions.values_list('id', flat=True)[:5])
                self.stdout.write(f"    Permission IDs: {perm_ids}")
                if permission_count > 5:
                    self.stdout.write(f"    ... and {permission_count - 5} more")
        
        # Check for orphaned assignments
        self.stdout.write(f"\n🔍 Checking for orphaned permission assignments:")
        orphaned_found = False
        for role in Role.objects.all():
            role_permission_ids = list(role.permissions.values_list('id', flat=True))
            existing_permission_ids = list(Permission.objects.filter(id__in=role_permission_ids).values_list('id', flat=True))
            orphaned_ids = set(role_permission_ids) - set(existing_permission_ids)
            
            if orphaned_ids:
                orphaned_found = True
                self.stdout.write(f"  ❌ Role '{role.name}' has orphaned permissions: {orphaned_ids}")
        
        if not orphaned_found:
            self.stdout.write(f"  ✅ No orphaned permission assignments found")
        
        self.stdout.write(self.style.SUCCESS(f"\n🎉 Debug information complete!"))
        
        if orphaned_found:
            self.stdout.write(self.style.WARNING(f"💡 Run 'python manage.py cleanup_permissions' to fix orphaned assignments")) 