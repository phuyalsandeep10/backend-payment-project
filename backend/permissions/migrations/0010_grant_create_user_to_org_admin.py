# -*- coding: utf-8 -*-
from django.db import migrations

def grant_create_user_permission(apps, schema_editor):
    """
    Grant the 'create_user' permission to all existing 'Org Admin' roles.
    """
    Role = apps.get_model('permissions', 'Role')
    Permission = apps.get_model('permissions', 'Permission')
    db_alias = schema_editor.connection.alias

    try:
        # Get the specific permission we want to assign
        perm = Permission.objects.using(db_alias).get(codename='create_user')
        
        # Find all roles named 'Org Admin'
        org_admin_roles = Role.objects.using(db_alias).filter(name='Org Admin')
        
        for role in org_admin_roles:
            role.permissions.add(perm)
            print(f"Granted 'create_user' to 'Org Admin' in org: {role.organization}")

    except Permission.DoesNotExist:
        print("Permission 'create_user' not found, skipping.")
        pass

def revert_create_user_permission(apps, schema_editor):
    """
    Revert the 'create_user' permission from all 'Org Admin' roles.
    """
    Role = apps.get_model('permissions', 'Role')
    Permission = apps.get_model('permissions', 'Permission')
    db_alias = schema_editor.connection.alias
    
    try:
        perm = Permission.objects.using(db_alias).get(codename='create_user')
        org_admin_roles = Role.objects.using(db_alias).filter(name='Org Admin')

        for role in org_admin_roles:
            role.permissions.remove(perm)

    except Permission.DoesNotExist:
        pass

class Migration(migrations.Migration):

    dependencies = [
        ('permissions', '0009_grant_view_user_to_org_admin'),
    ]

    operations = [
        migrations.RunPython(grant_create_user_permission, reverse_code=revert_create_user_permission),
    ]
