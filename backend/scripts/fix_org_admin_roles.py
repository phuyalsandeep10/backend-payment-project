from permissions.models import Role
from organization.models import Organization

# Clean up all org admin variants
variants = ["Org Admin", "org-admin", "org admin", "orgadmin"]
Role.objects.filter(name__in=variants).delete()

# Ensure every org has a canonical Organization Admin role
for org in Organization.objects.all():
    Role.objects.get_or_create(name="Organization Admin", organization=org)

# If you use a global org admin role (organization=None), ensure it exists:
Role.objects.get_or_create(name="Organization Admin", organization=None)

print("✅ Org admin roles cleaned and canonicalized.") 