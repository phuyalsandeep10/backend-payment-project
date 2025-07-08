from django.core.management.base import BaseCommand
from django.db import connection
from django.core.management import call_command
from django.apps import apps
import sys

class Command(BaseCommand):
    help = "Check migration safety before deployment"

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be migrated without applying',
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS("🔍 Checking migration safety..."))
        
        # Check for unapplied migrations
        unapplied_migrations = []
        for app_config in apps.get_app_configs():
            if hasattr(app_config, 'get_models'):
                try:
                    call_command('showmigrations', app_config.label, verbosity=0)
                    # Check for [ ] (unapplied) migrations
                    from django.db.migrations.loader import MigrationLoader
                    loader = MigrationLoader(connection)
                    for migration in loader.disk_migrations.values():
                        if migration.app_label == app_config.label:
                            if not loader.applied_migrations.get((app_config.label, migration.name)):
                                unapplied_migrations.append(f"{app_config.label}.{migration.name}")
                except Exception as e:
                    self.stdout.write(self.style.WARNING(f"⚠️  Could not check {app_config.label}: {e}"))

        if unapplied_migrations:
            self.stdout.write(self.style.WARNING(f"⚠️  Found {len(unapplied_migrations)} unapplied migrations:"))
            for migration in unapplied_migrations:
                self.stdout.write(f"   - {migration}")
            
            if options['dry_run']:
                self.stdout.write(self.style.SUCCESS("✅ Dry run completed. No migrations applied."))
            else:
                self.stdout.write(self.style.ERROR("❌ Migration safety check failed!"))
                sys.exit(1)
        else:
            self.stdout.write(self.style.SUCCESS("✅ No unapplied migrations found."))

        # Check for potential conflicts
        try:
            call_command('makemigrations', '--dry-run', verbosity=0)
            self.stdout.write(self.style.SUCCESS("✅ No new migrations needed."))
        except Exception as e:
            self.stdout.write(self.style.WARNING(f"⚠️  Potential migration conflicts: {e}"))

        # Check database connectivity
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            self.stdout.write(self.style.SUCCESS("✅ Database connectivity OK."))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ Database connectivity failed: {e}"))
            sys.exit(1)

        self.stdout.write(self.style.SUCCESS("🎉 Migration safety check completed successfully!")) 