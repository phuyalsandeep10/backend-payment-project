"""
Nuclear Database Reset Command

This command completely destroys and recreates the database, including:
1. Dropping all tables and data
2. Removing all migration history
3. Recreating the database from scratch
4. Running fresh migrations
5. Setting up initial data

WARNING: This will permanently delete ALL data in the database!
Only use this in production if you're absolutely sure you want to start fresh.
"""

import os
import sys
import psycopg
from django.core.management.base import BaseCommand, CommandError
from django.core.management import call_command
from django.conf import settings
from django.db import connection
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Completely destroy and recreate the database (NUCLEAR OPTION)'

    def add_arguments(self, parser):
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force the operation without confirmation (REQUIRED for non-interactive environments)',
        )
        parser.add_argument(
            '--skip-backup',
            action='store_true',
            help='Skip creating a backup before destroying the database',
        )
        parser.add_argument(
            '--backup-file',
            type=str,
            help='Custom backup file path',
        )

    def handle(self, *args, **options):
        # Check if we're in a non-interactive environment (like Render)
        is_non_interactive = not sys.stdin.isatty() or 'RENDER' in os.environ
        
        if not options['force'] and not is_non_interactive:
            self.stdout.write(
                self.style.WARNING(
                    '⚠️  NUCLEAR DATABASE RESET ⚠️\n'
                    'This will PERMANENTLY DELETE ALL DATA in your database!\n'
                    'This operation cannot be undone.\n\n'
                    'Are you absolutely sure you want to continue?'
                )
            )
            
            confirm = input('Type "YES I AM SURE" to continue: ')
            if confirm != 'YES I AM SURE':
                self.stdout.write(
                    self.style.ERROR('Operation cancelled by user.')
                )
                return

        # Check if we're in production
        if not settings.DEBUG and not options['force'] and not is_non_interactive:
            self.stdout.write(
                self.style.WARNING(
                    '⚠️  PRODUCTION ENVIRONMENT DETECTED ⚠️\n'
                    'You are about to destroy the PRODUCTION database!\n'
                    'Make sure you have proper backups and this is intentional.'
                )
            )
            
            confirm_prod = input('Type "PRODUCTION RESET" to confirm: ')
            if confirm_prod != 'PRODUCTION RESET':
                self.stdout.write(
                    self.style.ERROR('Production reset cancelled by user.')
                )
                return

        # For non-interactive environments, show warnings but proceed
        if is_non_interactive:
            self.stdout.write(
                self.style.WARNING(
                    '🔄 Non-interactive environment detected (Render/Railway/etc.)\n'
                    'Proceeding with nuclear database reset...\n'
                    'This will destroy all data and recreate the database from scratch.'
                )
            )

        try:
            # Step 1: Create backup (optional)
            if not options['skip_backup']:
                self.create_backup(options.get('backup_file'))

            # Step 2: Get database connection info
            db_info = self.get_database_info()
            
            # Step 3: Drop and recreate database
            self.recreate_database(db_info)
            
            # Step 4: Run migrations
            self.run_migrations()
            
            # Step 5: Setup initial data
            self.setup_initial_data()
            
            self.stdout.write(
                self.style.SUCCESS(
                    '✅ Database successfully destroyed and recreated!\n'
                    'All tables, data, and migration history have been reset.'
                )
            )

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'❌ Database reset failed: {str(e)}')
            )
            logger.error(f'Nuclear database reset failed: {str(e)}', exc_info=True)
            raise CommandError(f'Database reset failed: {str(e)}')

    def create_backup(self, backup_file=None):
        """Create a backup of the current database"""
        self.stdout.write('📦 Creating database backup...')
        
        try:
            if not backup_file:
                backup_file = f'backup_before_nuclear_reset_{os.getpid()}.sql'
            
            # Get database connection info
            db_info = self.get_database_info()
            
            # Check if pg_dump is available
            import subprocess
            try:
                subprocess.run(['pg_dump', '--version'], capture_output=True, check=True)
            except (subprocess.CalledProcessError, FileNotFoundError):
                self.stdout.write(
                    self.style.WARNING(
                        '⚠️  pg_dump not available. Skipping backup creation. '
                        'This is normal on managed platforms like Render.'
                    )
                )
                return
            
            # Create backup using pg_dump
            backup_command = f'pg_dump -h {db_info["host"]} -p {db_info["port"]} -U {db_info["user"]} -d {db_info["name"]} -f {backup_file}'
            
            # Set password environment variable for pg_dump
            env = os.environ.copy()
            env['PGPASSWORD'] = db_info['password']
            
            result = subprocess.run(
                backup_command,
                shell=True,
                env=env,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                self.stdout.write(
                    self.style.SUCCESS(f'✅ Backup created: {backup_file}')
                )
            else:
                self.stdout.write(
                    self.style.WARNING(f'⚠️  Backup failed: {result.stderr}')
                )
                
        except Exception as e:
            self.stdout.write(
                self.style.WARNING(f'⚠️  Could not create backup: {str(e)}')
            )

    def get_database_info(self):
        """Extract database connection information"""
        db_settings = settings.DATABASES['default']
        
        return {
            'host': db_settings['HOST'],
            'port': db_settings['PORT'],
            'user': db_settings['USER'],
            'password': db_settings['PASSWORD'],
            'name': db_settings['NAME'],
            'engine': db_settings['ENGINE']
        }

    def recreate_database(self, db_info):
        """Drop and recreate the database"""
        self.stdout.write('🗑️  Dropping and recreating database...')
        
        try:
            # Connect to postgres database (not the target database)
            conn = psycopg.connect(
                host=db_info['host'],
                port=db_info['port'],
                user=db_info['user'],
                password=db_info['password'],
                dbname='postgres'  # Connect to default postgres database
            )
            conn.autocommit = True
            cursor = conn.cursor()
            
            # Try to terminate connections, but handle permission errors gracefully
            self.stdout.write('🔌 Attempting to terminate existing connections...')
            try:
                cursor.execute("""
                    SELECT pg_terminate_backend(pid)
                    FROM pg_stat_activity
                    WHERE datname = %s
                    AND pid <> pg_backend_pid();
                """, [db_info['name']])
                self.stdout.write('✅ Successfully terminated existing connections')
            except Exception as term_error:
                if 'permission denied' in str(term_error).lower() or 'insufficientprivilege' in str(term_error).lower():
                    self.stdout.write(
                        self.style.WARNING(
                            '⚠️  Cannot terminate connections (insufficient privileges). '
                            'This is normal on managed databases like Render. '
                            'Proceeding with database recreation...'
                        )
                    )
                else:
                    # Re-raise if it's not a permission error
                    raise term_error
            
            # Drop the database
            self.stdout.write(f'🗑️  Dropping database: {db_info["name"]}')
            cursor.execute(f'DROP DATABASE IF EXISTS "{db_info["name"]}";')
            
            # Create the database
            self.stdout.write(f'🆕 Creating database: {db_info["name"]}')
            cursor.execute(f'CREATE DATABASE "{db_info["name"]}";')
            
            cursor.close()
            conn.close()
            
            self.stdout.write(
                self.style.SUCCESS('✅ Database dropped and recreated successfully')
            )
            
        except Exception as e:
            raise Exception(f'Failed to recreate database: {str(e)}')

    def run_migrations(self):
        """Run all migrations from scratch"""
        self.stdout.write('🔄 Running migrations...')
        
        try:
            # Run migrations
            call_command('migrate', verbosity=1)
            
            self.stdout.write(
                self.style.SUCCESS('✅ Migrations completed successfully')
            )
            
        except Exception as e:
            raise Exception(f'Failed to run migrations: {str(e)}')

    def setup_initial_data(self):
        """Setup initial data after database recreation"""
        self.stdout.write('🚀 Setting up initial data...')
        
        try:
            # Create superuser
            self.stdout.write('👤 Creating superuser...')
            call_command('setup_superadmin', verbosity=1)
            
            # Setup permissions
            self.stdout.write('🔐 Setting up permissions...')
            call_command('setup_permissions', verbosity=1)
            
            # Generate test data (optional - only in development)
            if settings.DEBUG:
                self.stdout.write('🧪 Generating test data...')
                try:
                    call_command('generate_rich_test_data', verbosity=1)
                except Exception as e:
                    self.stdout.write(
                        self.style.WARNING(f'⚠️  Test data generation failed: {str(e)}')
                    )
            
            self.stdout.write(
                self.style.SUCCESS('✅ Initial data setup completed')
            )
            
        except Exception as e:
            raise Exception(f'Failed to setup initial data: {str(e)}') 