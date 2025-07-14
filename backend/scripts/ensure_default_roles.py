from permissions.models import Role
from organization.models import Organization

default_roles = [
    'Organization Admin',
    'Salesperson',
    'Verifier',
    'Team Member',
    'Supervisor',
]

for org in Organization.objects.all():
    for role_name in default_roles:
        Role.objects.get_or_create(name=role_name, organization=org)
print('✅ Ensured all orgs have default roles.') 