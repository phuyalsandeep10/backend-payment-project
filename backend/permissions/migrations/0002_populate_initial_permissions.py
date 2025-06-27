from django.db import migrations

def populate_permissions(apps, schema_editor):
    Permission = apps.get_model('permissions', 'Permission')
    
    permissions_data = [
        # User Management
        {'name': 'Create User', 'codename': 'create_user', 'category': 'User Management'},
        {'name': 'View User', 'codename': 'view_user', 'category': 'User Management'},
        {'name': 'Edit User', 'codename': 'edit_user', 'category': 'User Management'},
        {'name': 'Delete User', 'codename': 'delete_user', 'category': 'User Management'},
        
        # Role Management
        {'name': 'Manage Roles', 'codename': 'manage_roles', 'category': 'Role Management'},
        
        # Project Management
        {'name': 'Create Project', 'codename': 'create_project', 'category': 'Project Management'},
        {'name': 'View Project', 'codename': 'view_project', 'category': 'Project Management'},
        {'name': 'Edit Project', 'codename': 'edit_project', 'category': 'Project Management'},
        {'name': 'Delete Project', 'codename': 'delete_project', 'category': 'Project Management'},

        # Team Management
        {'name': 'Create Team', 'codename': 'create_team', 'category': 'Team Management'},
        {'name': 'View Team', 'codename': 'view_team', 'category': 'Team Management'},
        {'name': 'Edit Team', 'codename': 'edit_team', 'category': 'Team Management'},
        {'name': 'Delete Team', 'codename': 'delete_team', 'category': 'Team Management'},
    ]

    for perm_data in permissions_data:
        Permission.objects.update_or_create(codename=perm_data['codename'], defaults=perm_data)

class Migration(migrations.Migration):

    dependencies = [
        ('permissions', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(populate_permissions),
    ] 