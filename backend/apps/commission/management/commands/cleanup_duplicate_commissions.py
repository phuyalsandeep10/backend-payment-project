"""
Clean up duplicate commission records
"""

from django.core.management.base import BaseCommand
from django.db import transaction
from commission.models import Commission
from collections import defaultdict

class Command(BaseCommand):
    help = 'Clean up duplicate commission records'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be deleted without actually deleting'
        )

    def handle(self, *args, **options):
        dry_run = options.get('dry_run', False)
        
        self.stdout.write("Analyzing commission records for duplicates...")
        
        # Find duplicates based on the unique constraint: user, organization, start_date, end_date
        duplicates = defaultdict(list)
        
        for commission in Commission.objects.all().order_by('created_at'):
            key = (commission.user_id, commission.organization_id, commission.start_date, commission.end_date)
            duplicates[key].append(commission)
        
        # Filter to only groups with duplicates
        duplicate_groups = {k: v for k, v in duplicates.items() if len(v) > 1}
        
        if not duplicate_groups:
            self.stdout.write(self.style.SUCCESS("No duplicate commission records found."))
            return
        
        self.stdout.write(f"Found {len(duplicate_groups)} groups of duplicate records:")
        
        total_to_delete = 0
        
        for key, records in duplicate_groups.items():
            user_id, org_id, start_date, end_date = key
            self.stdout.write(f"\nDuplicate group: User {user_id}, Org {org_id}, {start_date} to {end_date}")
            self.stdout.write(f"  Found {len(records)} records:")
            
            # Keep the most recent record (last created)
            records_sorted = sorted(records, key=lambda x: x.created_at)
            to_keep = records_sorted[-1]  # Keep the last one
            to_delete = records_sorted[:-1]  # Delete all others
            
            for i, record in enumerate(records_sorted):
                status = "KEEP" if record == to_keep else "DELETE"
                self.stdout.write(f"    {i+1}. ID {record.id}, Created: {record.created_at}, Total Sales: {record.total_sales} - {status}")
            
            total_to_delete += len(to_delete)
            
            if not dry_run:
                with transaction.atomic():
                    for record in to_delete:
                        record.delete()
                        self.stdout.write(f"    Deleted commission ID {record.id}")
        
        if dry_run:
            self.stdout.write(f"\nDRY RUN: Would delete {total_to_delete} duplicate records")
            self.stdout.write("Run without --dry-run to actually delete the duplicates")
        else:
            self.stdout.write(self.style.SUCCESS(f"\nDeleted {total_to_delete} duplicate commission records"))
            self.stdout.write("You can now run the migration: python manage.py migrate commission")