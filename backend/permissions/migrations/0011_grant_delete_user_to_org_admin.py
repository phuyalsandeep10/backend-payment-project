# -*- coding: utf-8 -*-
from django.db import migrations


def grant_delete_user_permission(apps, schema_editor):
    """
    Grant the 'delete_user' permission to all existing 'Org Admin' roles.
    """
    Role = apps.get_model('permissions', 'Role')
    Permission = apps.get_model('permissions', 'Permission')
    db_alias = schema_editor.connection.alias

    try:
        perm = Permission.objects.using(db_alias).get(codename='delete_user')
        org_admin_roles = Role.objects.using(db_alias).filter(name='Org Admin')
        for role in org_admin_roles:
            role.permissions.add(perm)
            # Optional: print for migration logs
            print(f"Granted 'delete_user' to 'Org Admin' in org: {role.organization}")
    except Permission.DoesNotExist:
        print("Permission 'delete_user' not found, skipping.")
        return


def revert_delete_user_permission(apps, schema_editor):
    """
    Remove the 'delete_user' permission from all 'Org Admin' roles.
    """
    Role = apps.get_model('permissions', 'Role')
    Permission = apps.get_model('permissions', 'Permission')
    db_alias = schema_editor.connection.alias

    try:
        perm = Permission.objects.using(db_alias).get(codename='delete_user')
        org_admin_roles = Role.objects.using(db_alias).filter(name='Org Admin')
        for role in org_admin_roles:
            role.permissions.remove(perm)
    except Permission.DoesNotExist:
        return


class Migration(migrations.Migration):

    dependencies = [
        ('permissions', '0010_grant_create_user_to_org_admin'),
    ]

    operations = [
        migrations.RunPython(grant_delete_user_permission, reverse_code=revert_delete_user_permission),
    ] 