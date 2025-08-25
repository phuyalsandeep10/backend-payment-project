from django.core.management.base import BaseCommand
from django.db import connection


class Command(BaseCommand):
    help = "Fix migration conflicts by checking and resolving database schema inconsistencies"

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be done without making changes',
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS("🔧 Checking for migration conflicts..."))
        
        dry_run = options['dry_run']
        
        with connection.cursor() as cursor:
            # Check authentication_user table structure
            cursor.execute("""
                SELECT column_name, data_type, is_nullable, column_default
                FROM information_schema.columns 
                WHERE table_name = 'authentication_user'
                ORDER BY ordinal_position
            """)
            columns = cursor.fetchall()
            
            self.stdout.write(self.style.HTTP_INFO("Current authentication_user table columns:"))
            for col in columns:
                self.stdout.write(f"  - {col[0]} ({col[1]})")
            
            # Check for specific issues
            column_names = [col[0] for col in columns]
            
            # Issue 1: avatar column exists but shouldn't
            if 'avatar' in column_names:
                if dry_run:
                    self.stdout.write(self.style.WARNING("  Would remove 'avatar' column"))
                else:
                    self.stdout.write(self.style.WARNING("  Removing 'avatar' column..."))
                    cursor.execute("ALTER TABLE authentication_user DROP COLUMN avatar")
                    self.stdout.write(self.style.SUCCESS("  ✅ avatar column removed"))
            
            # Issue 2: login_count column doesn't exist but should
            if 'login_count' not in column_names:
                if dry_run:
                    self.stdout.write(self.style.WARNING("  Would add 'login_count' column"))
                else:
                    self.stdout.write(self.style.WARNING("  Adding 'login_count' column..."))
                    cursor.execute("ALTER TABLE authentication_user ADD COLUMN login_count integer DEFAULT 0")
                    self.stdout.write(self.style.SUCCESS("  ✅ login_count column added"))
            
            # Check for other potential issues
            if not dry_run:
                self.stdout.write(self.style.SUCCESS("✅ Migration conflict check completed"))
            else:
                self.stdout.write(self.style.SUCCESS("✅ Dry run completed - no changes made")) 