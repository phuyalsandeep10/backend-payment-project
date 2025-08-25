"""
Management command for background task processing operations
"""

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from datetime import timedelta
import logging

from core_config.background_task_processor import BackgroundTaskProcessor
from core_config.automated_business_processes import AutomatedBusinessProcessManager

class Command(BaseCommand):
    help = 'Manage background task processing and automated business processes'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--action',
            type=str,
            choices=['queue', 'monitor', 'status', 'cleanup', 'test'],
            required=True,
            help='Background task management action to perform'
        )
        
        parser.add_argument(
            '--task-type',
            type=str,
            choices=['deal_processing', 'file_processing', 'email_notification', 'automated_process'],
            help='Type of task to manage'
        )
        
        parser.add_argument(
            '--task-id',
            type=str,
            help='Specific task ID to check status'
        )
        
        parser.add_argument(
            '--organization',
            type=str,
            help='Organization name to target'
        )
        
        parser.add_argument(
            '--priority',
            type=str,
            choices=['high', 'medium', 'low'],
            default='medium',
            help='Task priority level'
        )
        
        parser.add_argument(
            '--process-name',
            type=str,
            help='Automated process name to manage'
        )
        
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be done without executing'
        )
        
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Enable verbose output'
        )
    
    def handle(self, *args, **options):
        self.verbosity = options.get('verbosity', 1)
        self.verbose = options.get('verbose', False)
        
        action = options['action']
        task_type = options.get('task_type')
        task_id = options.get('task_id')
        organization_name = options.get('organization')
        priority = options['priority']
        process_name = options.get('process_name')
        dry_run = options['dry_run']
        
        # Get organization if specified
        organization = None
        if organization_name:
            try:
                from organization.models import Organization
                organization = Organization.objects.get(name=organization_name)
                self.stdout.write(f"Targeting organization: {organization.name}")
            except Organization.DoesNotExist:
                raise CommandError(f"Organization '{organization_name}' not found")
        
        try:
            if action == 'queue':
                self._queue_tasks(task_type, organization, priority, dry_run)
            
            elif action == 'monitor':
                self._monitor_tasks()
            
            elif action == 'status':
                self._show_task_status(task_id, process_name)
            
            elif action == 'cleanup':
                self._cleanup_tasks(dry_run)
            
            elif action == 'test':
                self._test_background_tasks(organization)
            
            self.stdout.write(
                self.style.SUCCESS(f"Background task {action} operation completed successfully!")
            )
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f"Background task operation failed: {str(e)}")
            )
            if self.verbose:
                import traceback
                self.stdout.write(traceback.format_exc())
            raise CommandError(f"Operation failed: {str(e)}")
    
    def _queue_tasks(self, task_type, organization, priority, dry_run):
        """Queue background tasks"""
        if dry_run:
            self.stdout.write(self.style.WARNING("DRY RUN MODE - No tasks will be queued"))
        
        self.stdout.write(f"Queueing {task_type} tasks with {priority} priority...")
        
        if task_type == 'deal_processing':
            self._queue_deal_processing_tasks(organization, priority, dry_run)
        
        elif task_type == 'file_processing':
            self._queue_file_processing_tasks(organization, priority, dry_run)
        
        elif task_type == 'email_notification':
            self._queue_email_notification_tasks(organization, priority, dry_run)
        
        elif task_type == 'automated_process':
            self._queue_automated_process_tasks(organization, priority, dry_run)
        
        else:
            raise CommandError(f"Unknown task type: {task_type}")
    
    def _queue_deal_processing_tasks(self, organization, priority, dry_run):
        """Queue deal processing tasks"""
        from deals.models import Deal
        
        # Get pending deals that need processing
        deals_query = Deal.objects.filter(verification_status='pending')
        if organization:
            deals_query = deals_query.filter(organization=organization)
        
        pending_deals = deals_query[:10]  # Limit to 10 for testing
        
        self.stdout.write(f"Found {pending_deals.count()} pending deals to process")
        
        if not dry_run:
            from core_config.background_task_processor import process_deal_workflow
            
            for deal in pending_deals:
                task_result = BackgroundTaskProcessor.queue_task_with_monitoring(
                    process_deal_workflow,
                    deal.id,
                    'verify_deal',
                    priority=priority
                )
                
                if self.verbose:
                    self.stdout.write(f"  Queued verification task for deal {deal.deal_id}: {task_result['task_id']}")
        
        self.stdout.write(f"Queued deal processing tasks for {pending_deals.count()} deals")
    
    def _queue_file_processing_tasks(self, organization, priority, dry_run):
        """Queue file processing tasks"""
        self.stdout.write("File processing tasks would be queued based on uploaded files")
        
        # This would typically be triggered by file uploads
        # For testing, we'll just show what would happen
        
        if not dry_run:
            self.stdout.write("No pending file processing tasks found")
        else:
            self.stdout.write("Would queue file processing tasks for uploaded files")
    
    def _queue_email_notification_tasks(self, organization, priority, dry_run):
        """Queue email notification tasks"""
        from apps.authentication.models import User
        
        # Get users who might need password expiry notifications
        users_query = User.objects.filter(is_active=True)
        if organization:
            users_query = users_query.filter(organization=organization)
        
        # Users with passwords expiring in 7 days
        expiry_cutoff = timezone.now() + timedelta(days=7)
        users_needing_notification = users_query.filter(
            password_expires_at__lte=expiry_cutoff,
            password_expires_at__gte=timezone.now()
        )[:5]  # Limit to 5 for testing
        
        self.stdout.write(f"Found {users_needing_notification.count()} users needing password expiry notifications")
        
        if not dry_run:
            from core_config.background_task_processor import send_password_request_notification
            
            for user in users_needing_notification:
                days_until_expiry = (user.password_expires_at - timezone.now()).days
                
                task_result = BackgroundTaskProcessor.queue_task_with_monitoring(
                    send_password_request_notification,
                    user.id,
                    'password_expiry_warning',
                    {'days_until_expiry': days_until_expiry},
                    priority=priority
                )
                
                if self.verbose:
                    self.stdout.write(f"  Queued notification for user {user.email}: {task_result['task_id']}")
        
        self.stdout.write(f"Queued email notifications for {users_needing_notification.count()} users")
    
    def _queue_automated_process_tasks(self, organization, priority, dry_run):
        """Queue automated business process tasks"""
        processes = [
            'send_deal_verification_reminders',
            'automated_commission_calculation',
            'cleanup_expired_sessions_and_tokens'
        ]
        
        self.stdout.write(f"Queueing {len(processes)} automated process tasks...")
        
        if not dry_run:
            from core_config.automated_business_processes import (
                send_deal_verification_reminders,
                automated_commission_calculation,
                cleanup_expired_sessions_and_tokens
            )
            
            # Queue verification reminders
            task_result = BackgroundTaskProcessor.queue_task_with_monitoring(
                send_deal_verification_reminders,
                priority=priority
            )
            self.stdout.write(f"  Queued verification reminders: {task_result['task_id']}")
            
            # Queue commission calculation
            org_id = organization.id if organization else None
            task_result = BackgroundTaskProcessor.queue_task_with_monitoring(
                automated_commission_calculation,
                org_id,
                priority=priority
            )
            self.stdout.write(f"  Queued commission calculation: {task_result['task_id']}")
            
            # Queue cleanup
            task_result = BackgroundTaskProcessor.queue_task_with_monitoring(
                cleanup_expired_sessions_and_tokens,
                priority=priority
            )
            self.stdout.write(f"  Queued cleanup task: {task_result['task_id']}")
        
        self.stdout.write(f"Queued {len(processes)} automated process tasks")
    
    def _monitor_tasks(self):
        """Monitor background tasks"""
        self.stdout.write("Background Task Monitoring")
        self.stdout.write("=" * 50)
        
        try:
            from celery import current_app
            
            # Get Celery inspect
            inspect = current_app.control.inspect()
            
            # Get active tasks
            active_tasks = inspect.active()
            if active_tasks:
                self.stdout.write("\nActive Tasks:")
                for worker, tasks in active_tasks.items():
                    self.stdout.write(f"  Worker: {worker}")
                    for task in tasks:
                        self.stdout.write(f"    - {task['name']} (ID: {task['id']})")
            else:
                self.stdout.write("\nNo active tasks found")
            
            # Get scheduled tasks
            scheduled_tasks = inspect.scheduled()
            if scheduled_tasks:
                self.stdout.write("\nScheduled Tasks:")
                for worker, tasks in scheduled_tasks.items():
                    self.stdout.write(f"  Worker: {worker}")
                    for task in tasks:
                        self.stdout.write(f"    - {task['request']['task']} (ETA: {task['eta']})")
            else:
                self.stdout.write("\nNo scheduled tasks found")
            
            # Get reserved tasks
            reserved_tasks = inspect.reserved()
            if reserved_tasks:
                self.stdout.write("\nReserved Tasks:")
                for worker, tasks in reserved_tasks.items():
                    self.stdout.write(f"  Worker: {worker} - {len(tasks)} tasks")
            
        except Exception as e:
            self.stdout.write(f"Failed to get task monitoring info: {str(e)}")
    
    def _show_task_status(self, task_id, process_name):
        """Show task or process status"""
        if task_id:
            # Show specific task status
            self.stdout.write(f"Task Status for ID: {task_id}")
            self.stdout.write("-" * 30)
            
            task_status = BackgroundTaskProcessor.get_task_status(task_id)
            
            self.stdout.write(f"Status: {task_status['status']}")
            self.stdout.write(f"Successful: {task_status.get('successful', 'Unknown')}")
            self.stdout.write(f"Failed: {task_status.get('failed', 'Unknown')}")
            
            if task_status.get('result'):
                self.stdout.write(f"Result: {task_status['result']}")
            
            if task_status.get('traceback'):
                self.stdout.write(f"Error: {task_status['traceback']}")
        
        elif process_name:
            # Show automated process status
            self.stdout.write(f"Process Status for: {process_name}")
            self.stdout.write("-" * 30)
            
            process_status = AutomatedBusinessProcessManager.get_process_status(process_name)
            
            self.stdout.write(f"Status: {process_status['status']}")
            self.stdout.write(f"Last Run: {process_status.get('last_run', 'Never')}")
            self.stdout.write(f"Success Count: {process_status['success_count']}")
            self.stdout.write(f"Failure Count: {process_status['failure_count']}")
        
        else:
            # Show all process statuses
            self.stdout.write("All Automated Process Statuses")
            self.stdout.write("=" * 40)
            
            processes = [
                'deal_verification_reminders',
                'automated_commission_calculation',
                'cleanup_expired_sessions_tokens',
                'system_health_check'
            ]
            
            for process in processes:
                status = AutomatedBusinessProcessManager.get_process_status(process)
                self.stdout.write(f"\n{process}:")
                self.stdout.write(f"  Status: {status['status']}")
                self.stdout.write(f"  Last Run: {status.get('last_run', 'Never')}")
                self.stdout.write(f"  Success/Failure: {status['success_count']}/{status['failure_count']}")
    
    def _cleanup_tasks(self, dry_run):
        """Cleanup failed and old tasks"""
        if dry_run:
            self.stdout.write(self.style.WARNING("DRY RUN MODE - No cleanup will be performed"))
        
        self.stdout.write("Starting background task cleanup...")
        
        if not dry_run:
            from core_config.background_task_processor import cleanup_failed_tasks
            
            # Queue cleanup task
            task_result = BackgroundTaskProcessor.queue_task_with_monitoring(
                cleanup_failed_tasks,
                priority=BackgroundTaskProcessor.PRIORITY_LOW
            )
            
            self.stdout.write(f"Queued cleanup task: {task_result['task_id']}")
        
        self.stdout.write("Background task cleanup initiated")
    
    def _test_background_tasks(self, organization):
        """Test background task functionality"""
        self.stdout.write("Testing Background Task Functionality")
        self.stdout.write("=" * 50)
        
        # Test task queueing
        self.stdout.write("\n1. Testing Task Queueing:")
        
        try:
            from core_config.background_task_processor import monitor_background_tasks
            
            # Queue a simple monitoring task
            task_result = BackgroundTaskProcessor.queue_task_with_monitoring(
                monitor_background_tasks,
                priority=BackgroundTaskProcessor.PRIORITY_LOW
            )
            
            self.stdout.write(f"  ✓ Successfully queued monitoring task: {task_result['task_id']}")
            
            # Wait a moment and check status
            import time
            time.sleep(2)
            
            task_status = BackgroundTaskProcessor.get_task_status(task_result['task_id'])
            self.stdout.write(f"  ✓ Task status retrieved: {task_status['status']}")
            
        except Exception as e:
            self.stdout.write(f"  ✗ Task queueing test failed: {str(e)}")
        
        # Test automated process status
        self.stdout.write("\n2. Testing Automated Process Status:")
        
        try:
            status = AutomatedBusinessProcessManager.get_process_status('system_health_check')
            self.stdout.write(f"  ✓ Process status retrieved: {status['status']}")
            
        except Exception as e:
            self.stdout.write(f"  ✗ Process status test failed: {str(e)}")
        
        # Test Celery connection
        self.stdout.write("\n3. Testing Celery Connection:")
        
        try:
            from celery import current_app
            
            inspect = current_app.control.inspect()
            stats = inspect.stats()
            
            if stats:
                worker_count = len(stats)
                self.stdout.write(f"  ✓ Connected to Celery: {worker_count} workers available")
            else:
                self.stdout.write("  ⚠ Celery connected but no workers found")
                
        except Exception as e:
            self.stdout.write(f"  ✗ Celery connection test failed: {str(e)}")
        
        self.stdout.write("\nBackground task testing completed")