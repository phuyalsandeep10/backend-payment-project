from permissions.models import Role
from organization.models import Organization

for org in Organization.objects.all():
    Role.objects.get_or_create(name="Organization Admin", organization=org)
print("✅ Ensured every org has an Organization Admin role.") 