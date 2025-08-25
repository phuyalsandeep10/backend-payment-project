"""
Celery configuration for the PRS project
"""

import os
from celery import Celery
from django.conf import settings

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')

app = Celery('prs')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django apps.
app.autodiscover_tasks()

# Celery configuration
app.conf.update(
    # Task routing
    task_routes={
        'deals.workflow_automation.*': {'queue': 'workflow'},
        'authentication.tasks.*': {'queue': 'auth'},
        'core_config.background_task_processor.*': {'queue': 'file_processing'},
        'core_config.automated_business_processes.*': {'queue': 'business_processes'},
        'core_config.*': {'queue': 'system'},
    },
    
    # Task execution settings
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    
    # Task result settings
    result_expires=3600,  # 1 hour
    
    # Worker settings
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    worker_max_tasks_per_child=1000,
    
    # Beat schedule for periodic tasks
    beat_schedule={
        'automated-workflow-maintenance': {
            'task': 'deals.workflow_automation.automated_workflow_maintenance',
            'schedule': 3600.0,  # Run every hour
        },
        'check-password-expiration': {
            'task': 'authentication.tasks.check_password_expiration_task',
            'schedule': 86400.0,  # Run daily
        },
        'cleanup-password-history': {
            'task': 'authentication.tasks.cleanup_password_history',
            'schedule': 604800.0,  # Run weekly
        },
        # 4.2.2 Automated Business Processes
        'deal-verification-reminders': {
            'task': 'core_config.automated_business_processes.send_deal_verification_reminders',
            'schedule': 86400.0,  # Run daily
            'options': {'queue': 'business_processes'}
        },
        'automated-commission-calculation': {
            'task': 'core_config.automated_business_processes.automated_commission_calculation',
            'schedule': 21600.0,  # Run every 6 hours
            'options': {'queue': 'business_processes'}
        },
        'generate-audit-report': {
            'task': 'core_config.automated_business_processes.generate_audit_report',
            'schedule': 604800.0,  # Run weekly
            'options': {'queue': 'reports'}
        },
        'cleanup-expired-sessions-tokens': {
            'task': 'core_config.automated_business_processes.cleanup_expired_sessions_and_tokens',
            'schedule': 3600.0,  # Run hourly
            'options': {'queue': 'maintenance'}
        },
        'system-health-check': {
            'task': 'core_config.automated_business_processes.system_health_check',
            'schedule': 300.0,  # Run every 5 minutes
            'options': {'queue': 'monitoring'}
        },
        # Background task monitoring
        'monitor-background-tasks': {
            'task': 'core_config.background_task_processor.monitor_background_tasks',
            'schedule': 600.0,  # Run every 10 minutes
            'options': {'queue': 'monitoring'}
        },
        'cleanup-failed-tasks': {
            'task': 'core_config.background_task_processor.cleanup_failed_tasks',
            'schedule': 3600.0,  # Run hourly
            'options': {'queue': 'maintenance'}
        },
    },
)

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')