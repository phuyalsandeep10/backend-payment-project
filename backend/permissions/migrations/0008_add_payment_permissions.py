from django.db import migrations


def add_payment_permissions(apps, schema_editor):
    Permission = apps.get_model('permissions', 'Permission')
    Role = apps.get_model('permissions', 'Role')

    perms_data = [
        {'name': 'Create Deal Payment', 'codename': 'create_deal_payment', 'category': 'Deal Payments'},
        {'name': 'Verify Deal Payment', 'codename': 'verify_deal_payment', 'category': 'Deal Payments'},
    ]

    created = {}
    for perm in perms_data:
        obj, _ = Permission.objects.update_or_create(codename=perm['codename'], defaults=perm)
        created[perm['codename']] = obj

    # Attach to system roles (organization is null)
    salesperson = Role.objects.filter(name__iexact='Salesperson', organization__isnull=True).first()
    verifier = Role.objects.filter(name__iexact='Verifier', organization__isnull=True).first()
    org_admin = Role.objects.filter(name__iexact='Org Admin', organization__isnull=True).first()

    if salesperson:
        salesperson.permissions.add(created['create_deal_payment'])

    if verifier:
        verifier.permissions.add(created['verify_deal_payment'])

    if org_admin:
        org_admin.permissions.add(*created.values())


def remove_payment_permissions(apps, schema_editor):
    Permission = apps.get_model('permissions', 'Permission')
    Permission.objects.filter(codename__in=['create_deal_payment', 'verify_deal_payment']).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('permissions', '0007_assign_full_client_permissions_to_salesperson'),
    ]

    operations = [
        migrations.RunPython(add_payment_permissions, remove_payment_permissions),
    ] 