# Background Task Processing Implementation

This document describes the comprehensive background task processing implementation for tasks 4.2.1 and 4.2.2 of the security and performance overhaul.

## Overview

The background task processing system includes two main components:

1. **Background Task Processing (4.2.1)** - Celery-based task processing for deal workflows, file processing, and email notifications
2. **Automated Business Processes (4.2.2)** - Automated deal verification reminders, commission calculations, audit reports, and system maintenance

## Components Implemented

### 1. Background Task Processor (`background_task_processor.py`)

**Key Features:**
- Centralized task processing with monitoring and retry logic
- Deal workflow processing with state machine validation
- File processing for profile pictures and deal attachments
- Email notification system for password requests and deal updates
- Task monitoring and management capabilities

**Main Classes:**
- `BackgroundTaskProcessor`: Central processor with task queuing and monitoring

**Task Types:**
- **Deal Processing**: Verification, commission calculation, payment status updates, invoice generation
- **File Processing**: Profile picture optimization, deal attachment processing with security validation
- **Email Notifications**: Password requests, deal notifications, verification alerts
- **Task Monitoring**: Active task monitoring, failed task cleanup, performance tracking

### 2. Automated Business Processes (`automated_business_processes.py`)

**Key Features:**
- Deal verification reminder system
- Automated commission calculation processing
- Background audit report generation
- Automated cleanup of expired sessions and tokens
- System health monitoring and reporting

**Main Classes:**
- `AutomatedBusinessProcessManager`: Manager for automated process status and monitoring

**Process Types:**
- **Deal Verification Reminders**: Daily reminders for pending deals over 24 hours
- **Commission Calculation**: Automated calculation every 6 hours with reconciliation
- **Audit Report Generation**: Weekly comprehensive audit reports with organizational data
- **System Cleanup**: Hourly cleanup of expired sessions, tokens, and old logs
- **Health Monitoring**: System health checks every 5 minutes

### 3. Background Task Views (`background_task_views.py`)

**Key Features:**
- RESTful API endpoints for task management
- Task queuing and monitoring interfaces
- Automated process control and status reporting
- System health and audit report access

**Main ViewSets:**
- `BackgroundTaskViewSet`: Task queuing, monitoring, and status management
- `AutomatedProcessViewSet`: Automated process control and reporting

### 4. Management Command (`manage_background_tasks.py`)

**Key Features:**
- Command-line interface for task management
- Task queuing, monitoring, and cleanup operations
- Testing and debugging capabilities
- Comprehensive status reporting

**Usage Examples:**
```bash
# Queue deal processing tasks
python manage.py manage_background_tasks --action=queue --task-type=deal_processing --priority=high

# Monitor active tasks
python manage.py manage_background_tasks --action=monitor

# Check task status
python manage.py manage_background_tasks --action=status --task-id=<task_id>

# Test background task functionality
python manage.py manage_background_tasks --action=test --organization="MyOrg"

# Cleanup failed tasks
python manage.py manage_background_tasks --action=cleanup
```

## Celery Configuration

### Enhanced Celery Setup (`celery.py`)

**Queue Configuration:**
- `workflow`: Deal workflow processing
- `auth`: Authentication-related tasks
- `file_processing`: File upload and processing tasks
- `business_processes`: Automated business processes
- `system`: System maintenance tasks
- `reports`: Report generation tasks
- `monitoring`: System monitoring tasks
- `maintenance`: Cleanup and maintenance tasks

**Beat Schedule:**
- **Deal verification reminders**: Daily at midnight
- **Commission calculation**: Every 6 hours
- **Audit report generation**: Weekly on Sundays
- **Session cleanup**: Every hour
- **System health check**: Every 5 minutes
- **Task monitoring**: Every 10 minutes
- **Failed task cleanup**: Every hour

### Task Routing and Priorities

```python
task_routes = {
    'deals.workflow_automation.*': {'queue': 'workflow'},
    'authentication.tasks.*': {'queue': 'auth'},
    'core_config.background_task_processor.*': {'queue': 'file_processing'},
    'core_config.automated_business_processes.*': {'queue': 'business_processes'},
    'core_config.*': {'queue': 'system'},
}
```

## Task Types and Implementation

### Deal Processing Tasks

#### Deal Workflow Processing
```python
@shared_task(bind=True, max_retries=3)
def process_deal_workflow(self, deal_id, workflow_action, user_id=None):
    # Processes deal verification, commission calculation, payment updates
    # Includes state machine validation and audit logging
```

**Workflow Actions:**
- `verify_deal`: Automated deal verification with checks
- `calculate_commission`: Commission calculation with rate application
- `update_payment_status`: Payment status synchronization
- `generate_invoice`: Invoice generation for deals

### File Processing Tasks

#### Profile Picture Processing
```python
@shared_task(bind=True, max_retries=3)
def process_profile_picture(self, user_id, file_path, original_filename):
    # Processes profile pictures with multiple size generation
    # Includes security validation and optimization
```

**Processing Features:**
- Multiple size generation (thumbnail, medium, large)
- Image optimization and compression
- Security validation with malware scanning
- Format conversion and standardization

#### Deal Attachment Processing
```python
@shared_task(bind=True, max_retries=3)
def process_deal_attachment(self, deal_id, file_path, original_filename, file_type):
    # Processes deal attachments with security validation
    # Supports images, PDFs, and generic files
```

### Email Notification Tasks

#### Password Request Notifications
```python
@shared_task(bind=True, max_retries=3)
def send_password_request_notification(self, user_id, request_type, additional_data=None):
    # Sends password-related notifications
    # Supports reset, creation, and expiry warnings
```

**Notification Types:**
- `password_reset`: Password reset requests
- `password_created`: New password notifications
- `password_expiry_warning`: Expiration warnings

#### Deal Notifications
```python
@shared_task(bind=True, max_retries=3)
def send_deal_notification(self, deal_id, notification_type, user_id=None, additional_data=None):
    # Sends deal-related notifications to stakeholders
```

**Notification Types:**
- `verification_approved`: Deal verification approval
- `verification_rejected`: Deal verification rejection
- `payment_received`: Payment confirmation
- `deal_overdue`: Overdue payment alerts

### Automated Business Processes

#### Deal Verification Reminders
```python
@shared_task(bind=True, max_retries=3)
def send_deal_verification_reminders(self):
    # Daily reminders for deals pending verification > 24 hours
    # Groups by organization and notifies admins/verifiers
```

#### Commission Calculation
```python
@shared_task(bind=True, max_retries=3)
def automated_commission_calculation(self, organization_id=None):
    # Automated commission calculation for verified deals
    # Includes reconciliation and discrepancy fixing
```

#### Audit Report Generation
```python
@shared_task(bind=True, max_retries=3)
def generate_audit_report(self, organization_id=None, report_type='comprehensive', days=30):
    # Generates comprehensive audit reports
    # Includes deal, payment, user, and security audits
```

#### System Cleanup
```python
@shared_task(bind=True, max_retries=3)
def cleanup_expired_sessions_and_tokens(self):
    # Cleans up expired sessions, tokens, and old logs
    # Includes temporary file cleanup
```

## API Endpoints

### Background Task Management

#### Queue Deal Processing
```http
POST /api/background-tasks/queue-deal-processing/
Content-Type: application/json

{
    "deal_id": "uuid",
    "workflow_action": "verify_deal",
    "priority": "high"
}
```

#### Queue File Processing
```http
POST /api/background-tasks/queue-file-processing/
Content-Type: application/json

{
    "file_type": "profile_picture",
    "file_path": "/tmp/upload.jpg",
    "original_filename": "profile.jpg",
    "priority": "medium"
}
```

#### Send Notification
```http
POST /api/background-tasks/send-notification/
Content-Type: application/json

{
    "notification_type": "password_expiry_warning",
    "recipient_type": "user",
    "user_id": 123,
    "additional_data": {"days_until_expiry": 7}
}
```

#### Get Task Status
```http
GET /api/background-tasks/{task_id}/status/
```

### Automated Process Management

#### Trigger Verification Reminders
```http
POST /api/automated-processes/trigger-verification-reminders/
```

#### Trigger Commission Calculation
```http
POST /api/automated-processes/trigger-commission-calculation/
```

#### Generate Audit Report
```http
POST /api/automated-processes/generate-audit-report/
Content-Type: application/json

{
    "report_type": "comprehensive",
    "days": 30
}
```

#### Get System Health
```http
GET /api/automated-processes/system-health/
```

#### Get Process Status
```http
GET /api/automated-processes/process-status/?process_name=deal_verification_reminders
```

## Monitoring and Analytics

### Task Performance Monitoring

**Metrics Tracked:**
- Task execution times
- Success/failure rates
- Queue lengths and processing times
- Worker utilization
- Error patterns and retry statistics

### Process Status Tracking

**Status Information:**
- Last run timestamp
- Success/failure counts
- Process health indicators
- Performance metrics
- Error logs and debugging info

### System Health Monitoring

**Health Checks:**
- Database connectivity and performance
- Cache system functionality
- Celery worker availability
- File system access and space
- External service dependencies

## Configuration

### Celery Settings
```python
# Task execution settings
CELERY_TASK_SERIALIZER = 'json'
CELERY_ACCEPT_CONTENT = ['json']
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = 'UTC'
CELERY_ENABLE_UTC = True

# Task result settings
CELERY_RESULT_EXPIRES = 3600  # 1 hour

# Worker settings
CELERY_WORKER_PREFETCH_MULTIPLIER = 1
CELERY_TASK_ACKS_LATE = True
CELERY_WORKER_MAX_TASKS_PER_CHILD = 1000
```

### Queue Configuration
```python
CELERY_TASK_ROUTES = {
    'deals.workflow_automation.*': {'queue': 'workflow'},
    'authentication.tasks.*': {'queue': 'auth'},
    'core_config.background_task_processor.*': {'queue': 'file_processing'},
    'core_config.automated_business_processes.*': {'queue': 'business_processes'},
}
```

### URL Configuration
```python
from core_config.background_task_urls import urlpatterns as background_task_urls

urlpatterns += background_task_urls
```

## Usage Examples

### Queueing Tasks Programmatically

```python
from core_config.background_task_processor import BackgroundTaskProcessor, process_deal_workflow

# Queue a deal processing task
task_result = BackgroundTaskProcessor.queue_task_with_monitoring(
    process_deal_workflow,
    deal_id='123',
    workflow_action='verify_deal',
    user_id=456,
    priority=BackgroundTaskProcessor.PRIORITY_HIGH
)

print(f"Task queued: {task_result['task_id']}")
```

### Checking Task Status

```python
from core_config.background_task_processor import BackgroundTaskProcessor

# Get task status
status = BackgroundTaskProcessor.get_task_status('task-id-here')
print(f"Task status: {status['status']}")
print(f"Successful: {status['successful']}")
```

### Managing Automated Processes

```python
from core_config.automated_business_processes import AutomatedBusinessProcessManager

# Get process status
status = AutomatedBusinessProcessManager.get_process_status('deal_verification_reminders')
print(f"Process status: {status['status']}")
print(f"Last run: {status['last_run']}")
```

## Testing

### Unit Tests
```bash
python manage.py test core_config.tests.test_background_task_processor
python manage.py test core_config.tests.test_automated_business_processes
```

### Integration Tests
```bash
python manage.py test core_config.tests.test_background_task_integration
```

### Management Command Testing
```bash
# Test background task functionality
python manage.py manage_background_tasks --action=test --organization="TestOrg"

# Monitor active tasks
python manage.py manage_background_tasks --action=monitor

# Queue test tasks
python manage.py manage_background_tasks --action=queue --task-type=deal_processing --dry-run
```

## Troubleshooting

### Common Issues

1. **Tasks Not Processing**
   - Check Celery worker status
   - Verify Redis/broker connection
   - Check queue configuration

2. **High Task Failure Rate**
   - Review task retry settings
   - Check error logs for patterns
   - Verify database connections

3. **Slow Task Processing**
   - Monitor worker utilization
   - Check database query performance
   - Review task complexity

### Debug Commands

```bash
# Check Celery worker status
celery -A core_config inspect active

# Monitor task queues
celery -A core_config inspect reserved

# Check worker statistics
celery -A core_config inspect stats
```

### Logging Configuration

```python
LOGGING = {
    'loggers': {
        'celery': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': True,
        },
        'core_config.background_task_processor': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': True,
        },
    }
}
```

## Performance Optimization

### Task Optimization
- Use appropriate task priorities
- Implement efficient batch processing
- Optimize database queries in tasks
- Use caching for frequently accessed data

### Queue Management
- Separate queues by task type and priority
- Monitor queue lengths and processing times
- Scale workers based on queue load
- Implement dead letter queues for failed tasks

### Resource Management
- Monitor memory usage in long-running tasks
- Implement task timeouts for resource protection
- Use connection pooling for database access
- Clean up temporary resources in tasks

## Future Enhancements

### Planned Improvements
1. **Advanced Task Scheduling**
   - Cron-like scheduling for complex patterns
   - Dynamic task scheduling based on system load
   - Task dependency management

2. **Enhanced Monitoring**
   - Real-time task monitoring dashboard
   - Performance analytics and reporting
   - Predictive failure detection

3. **Scalability Improvements**
   - Auto-scaling worker pools
   - Distributed task processing
   - Load balancing across multiple brokers

4. **Integration Enhancements**
   - Webhook support for external integrations
   - API rate limiting for task queuing
   - Advanced retry strategies with backoff

## Conclusion

The background task processing implementation provides comprehensive asynchronous processing capabilities for the PRS system. It includes robust task management, automated business processes, monitoring, and error handling to ensure reliable operation of business-critical workflows.

The system is designed to be scalable, maintainable, and provides both automated and manual task management capabilities through APIs, management commands, and scheduled processes.