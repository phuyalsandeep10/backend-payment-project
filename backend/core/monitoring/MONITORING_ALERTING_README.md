# Monitoring and Alerting System

This document describes the comprehensive monitoring and alerting system implemented for the PRS (Payment Receiving System) application.

## Overview

The monitoring and alerting system provides real-time performance monitoring, automated alerting, and comprehensive analytics for database queries, API response times, and system metrics.

## Components

### 1. Performance Monitor (`performance_monitor.py`)

The core monitoring component that tracks:
- **Database Query Performance**: Execution times, slow queries, organization-scoped metrics
- **API Response Times**: Endpoint performance, error rates, user-specific metrics
- **System Metrics**: CPU, memory, disk usage, database connections
- **Cache Performance**: Hit rates, memory usage (when available)

#### Key Features:
- Singleton pattern for global access
- Thread-safe operations
- Automatic background system monitoring
- Configurable thresholds for slow queries and API calls
- Automatic cleanup of old metrics
- Performance trend analysis

#### Usage:
```python
from core_config.performance_monitor import performance_monitor

# Record query performance
performance_monitor.record_query_performance(
    query="SELECT * FROM deals WHERE organization_id = %s",
    execution_time=0.5,
    organization_id=123
)

# Record API performance
performance_monitor.record_api_performance(
    endpoint="/api/deals/",
    method="GET",
    response_time=1.2,
    status_code=200,
    organization_id=123,
    user_id=456
)

# Get performance summary
summary = performance_monitor.get_performance_summary(hours=24)
```

### 2. Alerting System (`alerting_system.py`)

Automated alerting system that monitors performance metrics and triggers notifications:

#### Alert Rules:
- **High CPU Usage**: > 80% (Warning), > 90% (Critical)
- **High Memory Usage**: > 80% (Warning), > 90% (Critical)
- **Low Disk Space**: > 90% (Warning), > 95% (Critical)
- **High Slow Query Rate**: > 15% (Warning), > 30% (Critical)
- **High API Error Rate**: > 10% (Warning), > 20% (Critical)
- **Database Connection Issues**: > 50 connections (Critical)

#### Features:
- Configurable alert cooldown periods
- Alert frequency limiting
- Email notifications for administrators
- Alert history tracking
- Custom alert rule support
- Webhook endpoint for external alerts

#### Usage:
```python
from core_config.alerting_system import alerting_system

# Add custom alert rule
rule = {
    'name': 'custom_metric_alert',
    'condition': lambda metrics: metrics.get('custom_value', 0) > 100,
    'severity': 'warning',
    'message_template': 'Custom metric exceeded threshold: {custom_value}',
    'cooldown_minutes': 10
}
alerting_system.add_alert_rule(rule)

# Get alert history
alerts = alerting_system.get_alert_history(hours=24, severity='critical')
```

### 3. Monitoring Middleware

#### Performance Monitoring Middleware (`PerformanceMonitoringMiddleware`)
Automatically monitors all API requests:
- Response times
- Status codes
- User and organization context
- Endpoint-specific metrics

Add to `MIDDLEWARE` in settings:
```python
MIDDLEWARE = [
    # ... other middleware
    'core_config.performance_monitor.PerformanceMonitoringMiddleware',
]
```

#### Decorators
For manual monitoring of specific functions:

```python
from core_config.performance_monitor import monitor_query_performance, monitor_api_performance

@monitor_query_performance
def complex_database_query():
    # Your database query logic
    pass

@monitor_api_performance
def api_endpoint(request):
    # Your API endpoint logic
    pass
```

## API Endpoints

### Monitoring Endpoints (`/api/monitoring/`)

#### Performance Summary
- `GET /api/monitoring/performance/summary/?hours=24`
- Returns comprehensive performance metrics for specified time period

#### Performance Trends
- `GET /api/monitoring/performance/trends/?hours=24`
- Returns time-series performance data for trend analysis

#### Database Metrics
- `GET /api/monitoring/database/metrics/?hours=1`
- Returns database-specific performance metrics
- `GET /api/monitoring/database/slow-queries/?limit=50`
- Returns slowest database queries

#### API Metrics
- `GET /api/monitoring/api/metrics/?hours=1`
- Returns API-specific performance metrics
- `GET /api/monitoring/api/slow-calls/?limit=50`
- Returns slowest API calls

#### System Metrics
- `GET /api/monitoring/system/metrics/`
- Returns current system resource usage
- `GET /api/monitoring/system/health/`
- Health check endpoint (no authentication required)

#### Configuration (Admin Only)
- `GET/POST /api/monitoring/config/`
- Get/update monitoring configuration
- `POST /api/monitoring/maintenance/`
- Perform maintenance operations

### Alerting Endpoints (`/api/alerting/`)

#### Alert History and Status
- `GET /api/alerting/history/?hours=24&severity=warning`
- Returns alert history with optional filtering
- `GET /api/alerting/summary/?hours=24`
- Returns alert summary statistics
- `GET /api/alerting/status/`
- Returns current alerting system status

#### Alert Rules Management (Admin Only)
- `GET /api/alerting/rules/`
- List all alert rules
- `POST /api/alerting/rules/`
- Add new alert rule
- `DELETE /api/alerting/rules/`
- Remove alert rule
- `POST /api/alerting/rules/test/`
- Test alert rule with current metrics

#### Configuration (Admin Only)
- `GET/POST /api/alerting/config/`
- Get/update alerting configuration

#### Webhook
- `POST /api/alerting/webhook/`
- Receive external alerts (no authentication required)

## Management Commands

### `manage_monitoring` Command

Comprehensive command-line interface for monitoring operations:

```bash
# Show system status
python manage.py manage_monitoring status

# Show performance summary
python manage.py manage_monitoring summary --hours 24

# Show alerts
python manage.py manage_monitoring alerts --hours 24 --severity critical

# Test alert rule
python manage.py manage_monitoring test-alert --rule-name high_cpu_usage

# Clean up old data
python manage.py manage_monitoring cleanup

# Export metrics to JSON
python manage.py manage_monitoring export-metrics --hours 24 --output-file metrics.json

# Reset performance counters
python manage.py manage_monitoring reset-counters

# Perform health check
python manage.py manage_monitoring health-check
```

## Configuration

### Settings Configuration

Add to your Django settings:

```python
# Monitoring Configuration
MONITORING_SETTINGS = {
    'SLOW_QUERY_THRESHOLD': 1.0,  # seconds
    'SLOW_API_THRESHOLD': 2.0,    # seconds
    'MEMORY_WARNING_THRESHOLD': 80,  # percent
    'CPU_WARNING_THRESHOLD': 80,     # percent
    'METRICS_RETENTION_HOURS': 24,
}

# Alerting Configuration
ALERTING_SETTINGS = {
    'ALERT_COOLDOWN_MINUTES': 15,
    'MAX_ALERTS_PER_HOUR': 10,
    'EMAIL_BATCH_SIZE': 5,
}

# Email configuration for alerts
EMAIL_HOST = 'smtp.your-email-provider.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'your-email@domain.com'
EMAIL_HOST_PASSWORD = 'your-password'
DEFAULT_FROM_EMAIL = 'alerts@your-domain.com'

# Admin emails for alerts
ADMINS = [
    ('Admin Name', 'admin@your-domain.com'),
]
```

### Logging Configuration

Configure logging for monitoring and alerting:

```python
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'performance_file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': 'logs/performance.log',
        },
        'alerting_file': {
            'level': 'WARNING',
            'class': 'logging.FileHandler',
            'filename': 'logs/alerts.log',
        },
    },
    'loggers': {
        'performance': {
            'handlers': ['performance_file'],
            'level': 'INFO',
            'propagate': True,
        },
        'alerting': {
            'handlers': ['alerting_file'],
            'level': 'WARNING',
            'propagate': True,
        },
    },
}
```

## Integration Examples

### Frontend Dashboard Integration

```javascript
// Fetch performance summary
const fetchPerformanceSummary = async (hours = 24) => {
  const response = await fetch(`/api/monitoring/performance/summary/?hours=${hours}`);
  return response.json();
};

// Fetch recent alerts
const fetchRecentAlerts = async (hours = 1) => {
  const response = await fetch(`/api/alerting/history/?hours=${hours}`);
  return response.json();
};

// Health check
const checkSystemHealth = async () => {
  const response = await fetch('/api/monitoring/system/health/');
  return response.json();
};
```

### External Monitoring Integration

Send alerts from external monitoring systems:

```bash
# Send external alert via webhook
curl -X POST /api/alerting/webhook/ \
  -H "Content-Type: application/json" \
  -d '{
    "name": "external_service_down",
    "severity": "critical",
    "message": "External payment service is unreachable",
    "metrics": {
      "service": "payment_gateway",
      "status": "down",
      "last_check": "2024-01-15T10:30:00Z"
    }
  }'
```

### Custom Alert Rules

```python
# Add custom business logic alert
def check_deal_processing_backlog():
    from deals.models import Deal
    pending_deals = Deal.objects.filter(status='pending').count()
    return pending_deals > 100

custom_rule = {
    'name': 'deal_processing_backlog',
    'condition': lambda metrics: check_deal_processing_backlog(),
    'severity': 'warning',
    'message_template': 'Deal processing backlog detected',
    'cooldown_minutes': 30
}

alerting_system.add_alert_rule(custom_rule)
```

## Performance Considerations

### Memory Usage
- Metrics are stored in memory with configurable retention periods
- Automatic cleanup prevents memory buildup
- Use `deque` with `maxlen` for bounded collections

### Thread Safety
- All operations are thread-safe using appropriate locking
- Background monitoring runs in separate daemon threads
- No blocking operations in request handling

### Database Impact
- Monitoring adds minimal overhead to database operations
- Query monitoring uses Django's connection.queries when available
- No additional database queries for monitoring itself

## Troubleshooting

### Common Issues

1. **High Memory Usage**
   - Reduce `METRICS_RETENTION_HOURS`
   - Run cleanup more frequently
   - Check for memory leaks in application code

2. **Missing Alerts**
   - Check email configuration
   - Verify alert rules are properly configured
   - Check alert cooldown periods

3. **Performance Impact**
   - Monitor the monitoring system itself
   - Adjust collection intervals if needed
   - Use sampling for high-traffic applications

### Debug Commands

```bash
# Check monitoring system status
python manage.py manage_monitoring status

# Test email alerts
python manage.py manage_monitoring test-alert --rule-name high_cpu_usage

# Export data for analysis
python manage.py manage_monitoring export-metrics --hours 168 --output-file weekly_metrics.json
```

## Security Considerations

- All monitoring endpoints require authentication
- Admin-only endpoints require admin privileges
- Sensitive data is not logged in performance metrics
- Alert emails contain only necessary information
- Webhook endpoint validates input data

## Future Enhancements

- Integration with external APM tools (New Relic, DataDog)
- Slack/Teams notification channels
- Machine learning-based anomaly detection
- Custom dashboard with real-time charts
- Mobile app notifications
- Integration with infrastructure monitoring (Prometheus, Grafana)

## Support

For issues or questions about the monitoring and alerting system:
1. Check the logs in `logs/performance.log` and `logs/alerts.log`
2. Use the management commands for diagnostics
3. Review the API endpoints for programmatic access
4. Consult this documentation for configuration options