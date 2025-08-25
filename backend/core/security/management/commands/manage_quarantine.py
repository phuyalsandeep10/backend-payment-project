"""
Management command for quarantine file operations
Task 1.2.2 Implementation - Quarantine review workflow
"""

import os
import json
import shutil
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from django.utils import timezone


class Command(BaseCommand):
    help = 'Manage quarantined files - list, review, restore, or clean up'

    def add_arguments(self, parser):
        parser.add_argument(
            'action',
            choices=['list', 'review', 'restore', 'delete', 'cleanup'],
            help='Action to perform on quarantined files'
        )
        parser.add_argument(
            '--file-id',
            type=str,
            help='Specific quarantined file ID to operate on'
        )
        parser.add_argument(
            '--days',
            type=int,
            default=30,
            help='Number of days for cleanup (default: 30)'
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force action without confirmation'
        )

    def handle(self, *args, **options):
        self.quarantine_dir = getattr(
            settings, 
            'FILE_QUARANTINE_DIR', 
            os.path.join(settings.MEDIA_ROOT, 'quarantine')
        )
        
        if not os.path.exists(self.quarantine_dir):
            raise CommandError(f"Quarantine directory does not exist: {self.quarantine_dir}")

        action = options['action']
        
        if action == 'list':
            self.list_quarantined_files()
        elif action == 'review':
            self.review_file(options['file_id'])
        elif action == 'restore':
            self.restore_file(options['file_id'], options['force'])
        elif action == 'delete':
            self.delete_file(options['file_id'], options['force'])
        elif action == 'cleanup':
            self.cleanup_old_files(options['days'], options['force'])

    def list_quarantined_files(self):
        """List all quarantined files with their details"""
        files = []
        
        for filename in os.listdir(self.quarantine_dir):
            if filename.endswith('.json'):
                report_path = os.path.join(self.quarantine_dir, filename)
                file_path = report_path[:-5]  # Remove .json extension
                
                if os.path.exists(file_path):
                    try:
                        with open(report_path, 'r') as f:
                            report = json.load(f)
                        
                        file_info = {
                            'id': filename[:-5],  # Remove .json extension
                            'original_name': report.get('original_filename', 'Unknown'),
                            'quarantine_date': report.get('quarantine_timestamp', 'Unknown'),
                            'file_size': report.get('file_size', 0),
                            'threat_count': len(report.get('suspicious_content', [])),
                            'file_exists': True
                        }
                        files.append(file_info)
                    except Exception as e:
                        self.stdout.write(
                            self.style.ERROR(f"Error reading report {filename}: {e}")
                        )

        if not files:
            self.stdout.write(self.style.WARNING("No quarantined files found."))
            return

        # Sort by quarantine date (newest first)
        files.sort(key=lambda x: x['quarantine_date'], reverse=True)

        self.stdout.write(self.style.SUCCESS(f"Found {len(files)} quarantined files:\n"))
        
        # Header
        self.stdout.write(
            f"{'ID':<20} {'Original Name':<30} {'Date':<20} {'Size':<10} {'Threats':<8}"
        )
        self.stdout.write("-" * 90)
        
        # File list
        for file_info in files:
            date_str = file_info['quarantine_date'][:19] if len(file_info['quarantine_date']) > 19 else file_info['quarantine_date']
            size_str = f"{file_info['file_size']:,}B"
            
            self.stdout.write(
                f"{file_info['id']:<20} "
                f"{file_info['original_name'][:29]:<30} "
                f"{date_str:<20} "
                f"{size_str:<10} "
                f"{file_info['threat_count']:<8}"
            )

    def review_file(self, file_id):
        """Review a specific quarantined file in detail"""
        if not file_id:
            raise CommandError("File ID is required for review action")

        report_path = os.path.join(self.quarantine_dir, f"{file_id}.json")
        file_path = os.path.join(self.quarantine_dir, file_id)

        if not os.path.exists(report_path):
            raise CommandError(f"Quarantine report not found: {file_id}")

        if not os.path.exists(file_path):
            self.stdout.write(
                self.style.WARNING(f"Quarantined file missing: {file_id}")
            )

        try:
            with open(report_path, 'r') as f:
                report = json.load(f)
        except Exception as e:
            raise CommandError(f"Error reading quarantine report: {e}")

        # Display detailed information
        self.stdout.write(self.style.SUCCESS(f"\n=== Quarantine Review: {file_id} ===\n"))
        
        self.stdout.write(f"Original Filename: {report.get('original_filename', 'Unknown')}")
        self.stdout.write(f"Quarantine Date: {report.get('quarantine_timestamp', 'Unknown')}")
        self.stdout.write(f"File Size: {report.get('file_size', 0):,} bytes")
        
        # Validation results
        validation_result = report.get('validation_result', {})
        self.stdout.write(f"Extension: {validation_result.get('extension', 'Unknown')}")
        self.stdout.write(f"Threat Level: {validation_result.get('threat_level', 'Unknown')}")
        
        # Suspicious content
        suspicious_content = report.get('suspicious_content', [])
        if suspicious_content:
            self.stdout.write(f"\n--- Detected Threats ({len(suspicious_content)}) ---")
            for i, threat in enumerate(suspicious_content[:10], 1):  # Show first 10
                pattern = threat.get('pattern', 'Unknown')[:50]
                match = threat.get('match', 'Unknown')[:50]
                position = threat.get('position', 'Unknown')
                
                self.stdout.write(f"{i}. Pattern: {pattern}")
                self.stdout.write(f"   Match: {match}")
                self.stdout.write(f"   Position: {position}")
                self.stdout.write("")
            
            if len(suspicious_content) > 10:
                self.stdout.write(f"... and {len(suspicious_content) - 10} more threats")

        # Bypass attempts
        bypass_attempts = validation_result.get('bypass_attempts', [])
        if bypass_attempts:
            self.stdout.write(f"\n--- Bypass Attempts ({len(bypass_attempts)}) ---")
            for i, attempt in enumerate(bypass_attempts, 1):
                self.stdout.write(f"{i}. {attempt}")

        # Warnings
        warnings = validation_result.get('warnings', [])
        if warnings:
            self.stdout.write(f"\n--- Warnings ({len(warnings)}) ---")
            for i, warning in enumerate(warnings, 1):
                self.stdout.write(f"{i}. {warning}")

        self.stdout.write(f"\n--- Available Actions ---")
        self.stdout.write("1. Restore file (if safe)")
        self.stdout.write("2. Delete file permanently")
        self.stdout.write("3. Keep in quarantine")

    def restore_file(self, file_id, force=False):
        """Restore a quarantined file to uploads directory"""
        if not file_id:
            raise CommandError("File ID is required for restore action")

        report_path = os.path.join(self.quarantine_dir, f"{file_id}.json")
        file_path = os.path.join(self.quarantine_dir, file_id)

        if not os.path.exists(report_path) or not os.path.exists(file_path):
            raise CommandError(f"Quarantined file not found: {file_id}")

        try:
            with open(report_path, 'r') as f:
                report = json.load(f)
        except Exception as e:
            raise CommandError(f"Error reading quarantine report: {e}")

        original_filename = report.get('original_filename', file_id)
        validation_result = report.get('validation_result', {})
        threat_level = validation_result.get('threat_level', 'UNKNOWN')

        # Safety check
        if threat_level in ['HIGH', 'CRITICAL'] and not force:
            raise CommandError(
                f"File has {threat_level} threat level. Use --force to restore anyway."
            )

        # Confirm action
        if not force:
            confirm = input(f"Restore '{original_filename}' to uploads? (y/N): ")
            if confirm.lower() != 'y':
                self.stdout.write("Restore cancelled.")
                return

        # Create uploads directory if it doesn't exist
        uploads_dir = os.path.join(settings.MEDIA_ROOT, 'uploads')
        os.makedirs(uploads_dir, exist_ok=True)

        # Generate unique filename to avoid conflicts
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        restore_filename = f"restored_{timestamp}_{original_filename}"
        restore_path = os.path.join(uploads_dir, restore_filename)

        try:
            # Copy file to uploads
            shutil.copy2(file_path, restore_path)
            
            # Create restore log
            restore_log = {
                'original_quarantine_id': file_id,
                'original_filename': original_filename,
                'restored_filename': restore_filename,
                'restore_timestamp': datetime.now().isoformat(),
                'threat_level': threat_level,
                'restored_by': 'management_command'
            }
            
            log_path = os.path.join(uploads_dir, f"{restore_filename}.restore_log.json")
            with open(log_path, 'w') as f:
                json.dump(restore_log, f, indent=2)

            self.stdout.write(
                self.style.SUCCESS(f"File restored to: {restore_path}")
            )

        except Exception as e:
            raise CommandError(f"Error restoring file: {e}")

    def delete_file(self, file_id, force=False):
        """Permanently delete a quarantined file"""
        if not file_id:
            raise CommandError("File ID is required for delete action")

        report_path = os.path.join(self.quarantine_dir, f"{file_id}.json")
        file_path = os.path.join(self.quarantine_dir, file_id)

        if not os.path.exists(report_path):
            raise CommandError(f"Quarantine report not found: {file_id}")

        try:
            with open(report_path, 'r') as f:
                report = json.load(f)
            original_filename = report.get('original_filename', file_id)
        except Exception:
            original_filename = file_id

        # Confirm action
        if not force:
            confirm = input(f"Permanently delete '{original_filename}'? (y/N): ")
            if confirm.lower() != 'y':
                self.stdout.write("Delete cancelled.")
                return

        try:
            # Delete files
            if os.path.exists(file_path):
                os.remove(file_path)
            if os.path.exists(report_path):
                os.remove(report_path)

            self.stdout.write(
                self.style.SUCCESS(f"Quarantined file deleted: {original_filename}")
            )

        except Exception as e:
            raise CommandError(f"Error deleting file: {e}")

    def cleanup_old_files(self, days, force=False):
        """Clean up quarantined files older than specified days"""
        cutoff_date = timezone.now() - timedelta(days=days)
        
        old_files = []
        
        for filename in os.listdir(self.quarantine_dir):
            if filename.endswith('.json'):
                report_path = os.path.join(self.quarantine_dir, filename)
                
                try:
                    with open(report_path, 'r') as f:
                        report = json.load(f)
                    
                    quarantine_date_str = report.get('quarantine_timestamp')
                    if quarantine_date_str:
                        # Parse ISO format datetime
                        quarantine_date = datetime.fromisoformat(
                            quarantine_date_str.replace('Z', '+00:00')
                        )
                        
                        if quarantine_date.replace(tzinfo=timezone.utc) < cutoff_date:
                            old_files.append({
                                'id': filename[:-5],
                                'name': report.get('original_filename', filename),
                                'date': quarantine_date_str
                            })
                
                except Exception as e:
                    self.stdout.write(
                        self.style.WARNING(f"Error checking file {filename}: {e}")
                    )

        if not old_files:
            self.stdout.write(
                self.style.SUCCESS(f"No quarantined files older than {days} days found.")
            )
            return

        self.stdout.write(
            self.style.WARNING(f"Found {len(old_files)} files older than {days} days:")
        )
        
        for file_info in old_files:
            self.stdout.write(f"  - {file_info['name']} ({file_info['date']})")

        # Confirm cleanup
        if not force:
            confirm = input(f"\nDelete {len(old_files)} old quarantined files? (y/N): ")
            if confirm.lower() != 'y':
                self.stdout.write("Cleanup cancelled.")
                return

        # Delete old files
        deleted_count = 0
        for file_info in old_files:
            try:
                file_id = file_info['id']
                report_path = os.path.join(self.quarantine_dir, f"{file_id}.json")
                file_path = os.path.join(self.quarantine_dir, file_id)
                
                if os.path.exists(file_path):
                    os.remove(file_path)
                if os.path.exists(report_path):
                    os.remove(report_path)
                
                deleted_count += 1
                
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f"Error deleting {file_info['name']}: {e}")
                )

        self.stdout.write(
            self.style.SUCCESS(f"Cleanup complete. Deleted {deleted_count} files.")
        )