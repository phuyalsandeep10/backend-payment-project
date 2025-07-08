"""
Database Reset for Deployment

This command is designed for deployment scenarios where you need to reset the database.
It's safer than the nuclear option and includes proper error handling for deployment environments.
"""

import os
import psycopg2
from django.core.management.base import BaseCommand, CommandError
from django.core.management import call_command
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Reset database for deployment (safer than nuclear reset)'

    def add_arguments(self, parser):
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force the operation without confirmation',
        )
        parser.add_argument(
            '--skip-migrations',
            action='store_true',
            help='Skip running migrations after reset',
        )
        parser.add_argument(
            '--skip-setup',
            action='store_true',
            help='Skip initial data setup after reset',
        )

    def handle(self, *args, **options):
        # In deployment environments, we can be more aggressive
        if not settings.DEBUG and not options['force']:
            self.stdout.write(
                self.style.WARNING(
                    '🔄 Deployment database reset initiated...'
                )
            )

        try:
            # Step 1: Get database connection info
            db_info = self.get_database_info()
            
            # Step 2: Reset database
            self.reset_database(db_info)
            
            # Step 3: Run migrations (if not skipped)
            if not options['skip_migrations']:
                self.run_migrations()
            
            # Step 4: Setup initial data (if not skipped)
            if not options['skip_setup']:
                self.setup_initial_data()
            
            self.stdout.write(
                self.style.SUCCESS(
                    '✅ Database reset completed successfully!'
                )
            )

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'❌ Database reset failed: {str(e)}')
            )
            logger.error(f'Deployment database reset failed: {str(e)}', exc_info=True)
            raise CommandError(f'Database reset failed: {str(e)}')

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

    def reset_database(self, db_info):
        """Reset the database by dropping and recreating it"""
        self.stdout.write('🔄 Resetting database...')
        
        try:
            # Connect to postgres database (not the target database)
            conn = psycopg2.connect(
                host=db_info['host'],
                port=db_info['port'],
                user=db_info['user'],
                password=db_info['password'],
                database='postgres'  # Connect to default postgres database
            )
            conn.autocommit = True
            cursor = conn.cursor()
            
            # Terminate all connections to the target database
            self.stdout.write('🔌 Terminating existing connections...')
            cursor.execute(f"""
                SELECT pg_terminate_backend(pid)
                FROM pg_stat_activity
                WHERE datname = '{db_info['name']}'
                AND pid <> pg_backend_pid();
            """)
            
            # Drop the database
            self.stdout.write(f'🗑️  Dropping database: {db_info["name"]}')
            cursor.execute(f'DROP DATABASE IF EXISTS "{db_info["name"]}";')
            
            # Create the database
            self.stdout.write(f'🆕 Creating database: {db_info["name"]}')
            cursor.execute(f'CREATE DATABASE "{db_info["name"]}";')
            
            cursor.close()
            conn.close()
            
            self.stdout.write(
                self.style.SUCCESS('✅ Database reset successfully')
            )
            
        except Exception as e:
            raise Exception(f'Failed to reset database: {str(e)}')

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
        """Setup initial data after database reset"""
        self.stdout.write('🚀 Setting up initial data...')
        
        try:
            # Create superuser
            self.stdout.write('👤 Creating superuser...')
            call_command('setup_superadmin', verbosity=1)
            
            # Setup permissions
            self.stdout.write('🔐 Setting up permissions...')
            call_command('setup_permissions', verbosity=1)
            
            # Generate test data (only in development)
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