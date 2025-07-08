from django.core.management.base import BaseCommand
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType

class Command(BaseCommand):
    help = 'Check what permissions exist in the database'

    def add_arguments(self, parser):
        parser.add_argument(
            '--model',
            type=str,
            help='Filter permissions by model name (e.g., deal, client)'
        )
        parser.add_argument(
            '--codename',
            type=str,
            help='Filter permissions by codename'
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.HTTP_INFO("🔍 Checking permissions in database..."))
        
        # Get all permissions
        permissions = Permission.objects.all()
        
        # Apply filters
        if options['model']:
            try:
                content_type = ContentType.objects.get(model=options['model'])
                permissions = permissions.filter(content_type=content_type)
                self.stdout.write(f"📋 Filtering by model: {options['model']}")
            except ContentType.DoesNotExist:
                self.stdout.write(self.style.ERROR(f"❌ Model '{options['model']}' not found!"))
                return
        
        if options['codename']:
            permissions = permissions.filter(codename__icontains=options['codename'])
            self.stdout.write(f"📋 Filtering by codename: {options['codename']}")
        
        # Group by content type
        content_types = {}
        for perm in permissions.order_by('content_type__app_label', 'content_type__model', 'codename'):
            ct_key = f"{perm.content_type.app_label}.{perm.content_type.model}"
            if ct_key not in content_types:
                content_types[ct_key] = []
            content_types[ct_key].append(perm)
        
        # Display results
        total_permissions = 0
        for ct_key, perms in content_types.items():
            self.stdout.write(self.style.SUCCESS(f"\n📦 {ct_key} ({len(perms)} permissions):"))
            for perm in perms:
                self.stdout.write(f"  • {perm.codename} (ID: {perm.id}) - {perm.name}")
                total_permissions += 1
        
        self.stdout.write(self.style.SUCCESS(f"\n📊 Total permissions found: {total_permissions}"))
        
        # Show content types
        self.stdout.write(self.style.HTTP_INFO("\n📋 Available content types:"))
        for ct in ContentType.objects.all().order_by('app_label', 'model'):
            self.stdout.write(f"  • {ct.app_label}.{ct.model} (ID: {ct.id})") 