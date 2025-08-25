# Monitoring and Alerting Setup Guide

## Overview

This guide provides comprehensive instructions for setting up monitoring, alerting, and observability for the Payment Receiving System (PRS) Backend. It covers application monitoring, infrastructure monitoring, log aggregation, and alerting configurations.

---

## 📋 Table of Contents

1. [Monitoring Architecture](#monitoring-architecture)
2. [Application Monitoring](#application-monitoring)
3. [Infrastructure Monitoring](#infrastructure-monitoring)
4. [Log Aggregation](#log-aggregation)
5. [Alerting Configuration](#alerting-configuration)
6. [Dashboard Setup](#dashboard-setup)
7. [Health Checks](#health-checks)
8. [Performance Monitoring](#performance-monitoring)

---

## 🏗️ Monitoring Architecture

### Overview Architecture

```mermaid
graph TB
    subgraph "Application Layer"
        A[PRS Backend] --> M1[Prometheus Metrics]
        A --> L1[Application Logs]
        A --> T1[Traces]
    end
    
    subgraph "Infrastructure Layer"
        I1[Node Exporter] --> M2[System Metrics]
        I2[PostgreSQL Exporter] --> M3[DB Metrics]
        I3[Redis Exporter] --> M4[Cache Metrics]
        I4[Nginx Exporter] --> M5[Web Server Metrics]
    end
    
    subgraph "Collection & Storage"
        M1 --> P[Prometheus]
        M2 --> P
        M3 --> P
        M4 --> P
        M5 --> P
        
        L1 --> ELK[ELK Stack]
        T1 --> J[Jaeger]
    end
    
    subgraph "Visualization & Alerting"
        P --> G[Grafana]
        P --> AM[AlertManager]
        ELK --> K[Kibana]
        J --> JUI[Jaeger UI]
        
        AM --> SL[Slack]
        AM --> EM[Email]
        AM --> PD[PagerDuty]
    end
```

### Monitoring Stack Components

| Component | Purpose | Port | Config Location |
|-----------|---------|------|-----------------|
| **Prometheus** | Metrics collection and storage | 9090 | `/etc/prometheus/` |
| **Grafana** | Metrics visualization and dashboards | 3000 | `/etc/grafana/` |
| **AlertManager** | Alert routing and notification | 9093 | `/etc/alertmanager/` |
| **Elasticsearch** | Log storage and indexing | 9200 | `/etc/elasticsearch/` |
| **Logstash** | Log processing and parsing | 5044 | `/etc/logstash/` |
| **Kibana** | Log visualization | 5601 | `/etc/kibana/` |
| **Jaeger** | Distributed tracing | 16686 | `/etc/jaeger/` |

---

## 📊 Application Monitoring

### 1. Django Prometheus Integration

#### Install Django Prometheus

```bash
# Add to requirements/production.txt
django-prometheus==2.2.0
prometheus-client==0.17.1
```

#### Configure Django Settings

```python
# core_config/settings/production.py

INSTALLED_APPS = [
    'django_prometheus',
    # ... other apps
]

MIDDLEWARE = [
    'django_prometheus.middleware.PrometheusBeforeMiddleware',
    # ... other middleware
    'django_prometheus.middleware.PrometheusAfterMiddleware',
]

# Database monitoring
DATABASES = {
    'default': {
        'ENGINE': 'django_prometheus.db.backends.postgresql',
        'NAME': os.getenv('DB_NAME'),
        # ... other database config
    }
}

# Cache monitoring
CACHES = {
    'default': {
        'BACKEND': 'django_prometheus.cache.backends.redis.RedisCache',
        'LOCATION': os.getenv('REDIS_URL'),
        # ... other cache config
    }
}

# Prometheus metrics configuration
PROMETHEUS_METRICS_EXPORT_PORT = 8001
PROMETHEUS_METRICS_EXPORT_ADDRESS = '0.0.0.0'
```

#### Custom Metrics Implementation

```python
# core_config/monitoring.py

from prometheus_client import Counter, Histogram, Gauge, generate_latest
from django.http import HttpResponse
from django.views import View
import time
import logging

logger = logging.getLogger(__name__)

# Custom metrics
REQUEST_COUNT = Counter(
    'prs_http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status_code']
)

REQUEST_DURATION = Histogram(
    'prs_http_request_duration_seconds',
    'HTTP request duration in seconds',
    ['method', 'endpoint']
)

ACTIVE_USERS = Gauge(
    'prs_active_users_total',
    'Number of active users'
)

DATABASE_QUERIES = Counter(
    'prs_database_queries_total',
    'Total database queries',
    ['operation', 'table']
)

BUSINESS_METRICS = Counter(
    'prs_business_events_total',
    'Business-specific events',
    ['event_type', 'status']
)

# Custom middleware for request metrics
class PrometheusMetricsMiddleware:
    """Custom middleware to collect request metrics"""
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        start_time = time.time()
        
        response = self.get_response(request)
        
        # Record metrics
        REQUEST_COUNT.labels(
            method=request.method,
            endpoint=self._get_endpoint_label(request),
            status_code=response.status_code
        ).inc()
        
        REQUEST_DURATION.labels(
            method=request.method,
            endpoint=self._get_endpoint_label(request)
        ).observe(time.time() - start_time)
        
        return response
    
    def _get_endpoint_label(self, request):
        """Get clean endpoint label for metrics"""
        path = request.path
        
        # Normalize paths with IDs
        import re
        path = re.sub(r'/\d+/', '/{id}/', path)
        path = re.sub(r'/[0-9a-f-]{36}/', '/{uuid}/', path)
        
        return path

# Business metrics tracking
class BusinessMetricsTracker:
    """Track business-specific metrics"""
    
    @staticmethod
    def track_user_login(success=True):
        BUSINESS_METRICS.labels(
            event_type='user_login',
            status='success' if success else 'failure'
        ).inc()
    
    @staticmethod
    def track_deal_creation(success=True):
        BUSINESS_METRICS.labels(
            event_type='deal_creation',
            status='success' if success else 'failure'
        ).inc()
    
    @staticmethod
    def track_payment_processing(success=True):
        BUSINESS_METRICS.labels(
            event_type='payment_processing',
            status='success' if success else 'failure'
        ).inc()
    
    @staticmethod
    def track_commission_calculation(success=True):
        BUSINESS_METRICS.labels(
            event_type='commission_calculation',
            status='success' if success else 'failure'
        ).inc()

# Metrics endpoint
class MetricsView(View):
    """Expose Prometheus metrics"""
    
    def get(self, request):
        # Update active users gauge
        from django.contrib.auth import get_user_model
        from django.utils import timezone
        from datetime import timedelta
        
        User = get_user_model()
        active_threshold = timezone.now() - timedelta(minutes=30)
        active_users = User.objects.filter(last_login__gte=active_threshold).count()
        ACTIVE_USERS.set(active_users)
        
        # Generate metrics
        metrics = generate_latest()
        return HttpResponse(metrics, content_type='text/plain')

# Database query tracking
from django.db import connection
from django.db.backends.signals import connection_created

def track_database_queries(sender, connection, **kwargs):
    """Track database queries"""
    original_execute = connection.cursor().__class__.execute
    
    def execute_with_metrics(self, sql, params=None):
        start_time = time.time()
        try:
            result = original_execute(self, sql, params)
            
            # Extract table name from SQL
            table_name = 'unknown'
            operation = 'unknown'
            
            sql_lower = sql.lower().strip()
            if sql_lower.startswith('select'):
                operation = 'select'
                # Extract table name after FROM
                import re
                match = re.search(r'from\s+(\w+)', sql_lower)
                if match:
                    table_name = match.group(1)
            elif sql_lower.startswith('insert'):
                operation = 'insert'
                match = re.search(r'insert\s+into\s+(\w+)', sql_lower)
                if match:
                    table_name = match.group(1)
            elif sql_lower.startswith('update'):
                operation = 'update'
                match = re.search(r'update\s+(\w+)', sql_lower)
                if match:
                    table_name = match.group(1)
            elif sql_lower.startswith('delete'):
                operation = 'delete'
                match = re.search(r'delete\s+from\s+(\w+)', sql_lower)
                if match:
                    table_name = match.group(1)
            
            DATABASE_QUERIES.labels(
                operation=operation,
                table=table_name
            ).inc()
            
            return result
            
        except Exception as e:
            DATABASE_QUERIES.labels(
                operation='error',
                table=table_name
            ).inc()
            raise
    
    connection.cursor().__class__.execute = execute_with_metrics

connection_created.connect(track_database_queries)
```

#### Add Metrics URL

```python
# core_config/urls.py

from .monitoring import MetricsView

urlpatterns = [
    # ... other URLs
    path('metrics/', MetricsView.as_view(), name='metrics'),
    # ... 
]
```

### 2. Application Health Checks

```python
# core_config/health_checks.py

from django.http import JsonResponse
from django.views import View
from django.db import connection
from django.core.cache import cache
from django.conf import settings
import redis
import logging
import time
from datetime import datetime

logger = logging.getLogger(__name__)

class HealthCheckView(View):
    """Comprehensive health check endpoint"""
    
    def get(self, request):
        health_data = {
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'version': getattr(settings, 'VERSION', 'unknown'),
            'checks': {}
        }
        
        overall_status = True
        
        # Database health
        db_status = self._check_database()
        health_data['checks']['database'] = db_status
        if not db_status['healthy']:
            overall_status = False
        
        # Cache health
        cache_status = self._check_cache()
        health_data['checks']['cache'] = cache_status
        if not cache_status['healthy']:
            overall_status = False
        
        # Disk space
        disk_status = self._check_disk_space()
        health_data['checks']['disk'] = disk_status
        if not disk_status['healthy']:
            overall_status = False
        
        # External services
        external_status = self._check_external_services()
        health_data['checks']['external_services'] = external_status
        if not external_status['healthy']:
            overall_status = False
        
        # Application-specific checks
        app_status = self._check_application_health()
        health_data['checks']['application'] = app_status
        if not app_status['healthy']:
            overall_status = False
        
        # Set overall status
        health_data['status'] = 'healthy' if overall_status else 'unhealthy'
        
        # Return appropriate HTTP status
        status_code = 200 if overall_status else 503
        return JsonResponse(health_data, status=status_code)
    
    def _check_database(self):
        """Check database connectivity and performance"""
        try:
            start_time = time.time()
            
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()
            
            response_time = time.time() - start_time
            
            # Check for slow queries
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT COUNT(*) FROM pg_stat_activity 
                    WHERE state = 'active' 
                    AND query_start < NOW() - INTERVAL '30 seconds'
                """)
                slow_queries = cursor.fetchone()[0]
            
            # Check connection count
            with connection.cursor() as cursor:
                cursor.execute("SELECT count(*) FROM pg_stat_activity")
                connection_count = cursor.fetchone()[0]
            
            return {
                'healthy': response_time < 1.0 and slow_queries < 5,
                'response_time': response_time,
                'slow_queries': slow_queries,
                'connections': connection_count,
                'details': 'Database connectivity OK'
            }
            
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return {
                'healthy': False,
                'error': str(e),
                'details': 'Database connectivity failed'
            }
    
    def _check_cache(self):
        """Check cache connectivity and performance"""
        try:
            start_time = time.time()
            
            # Test Redis connectivity
            cache.set('health_check', 'ok', 30)
            value = cache.get('health_check')
            
            response_time = time.time() - start_time
            
            # Get Redis info
            redis_client = cache._cache.get_client()
            info = redis_client.info()
            
            return {
                'healthy': value == 'ok' and response_time < 0.1,
                'response_time': response_time,
                'connected_clients': info.get('connected_clients', 0),
                'used_memory_human': info.get('used_memory_human', '0B'),
                'details': 'Cache connectivity OK'
            }
            
        except Exception as e:
            logger.error(f"Cache health check failed: {e}")
            return {
                'healthy': False,
                'error': str(e),
                'details': 'Cache connectivity failed'
            }
    
    def _check_disk_space(self):
        """Check available disk space"""
        try:
            import shutil
            
            # Check main disk
            total, used, free = shutil.disk_usage('/')
            free_percent = (free / total) * 100
            
            # Check log disk if different
            log_disk = '/var/log' if settings.DEBUG else '/app/logs'
            try:
                log_total, log_used, log_free = shutil.disk_usage(log_disk)
                log_free_percent = (log_free / log_total) * 100
            except:
                log_free_percent = free_percent
            
            return {
                'healthy': free_percent > 10 and log_free_percent > 10,
                'main_disk_free_percent': round(free_percent, 2),
                'log_disk_free_percent': round(log_free_percent, 2),
                'details': f'Disk space: {free_percent:.1f}% free'
            }
            
        except Exception as e:
            logger.error(f"Disk space check failed: {e}")
            return {
                'healthy': True,  # Don't fail health check for disk space issues
                'error': str(e),
                'details': 'Could not check disk space'
            }
    
    def _check_external_services(self):
        """Check external service connectivity"""
        try:
            services = {}
            overall_healthy = True
            
            # Check email service
            if hasattr(settings, 'EMAIL_HOST'):
                email_healthy = self._check_email_service()
                services['email'] = email_healthy
                if not email_healthy:
                    overall_healthy = False
            
            # Check S3/media storage
            if getattr(settings, 'USE_S3', False):
                s3_healthy = self._check_s3_service()
                services['s3'] = s3_healthy
                if not s3_healthy:
                    overall_healthy = False
            
            return {
                'healthy': overall_healthy,
                'services': services,
                'details': f'Checked {len(services)} external services'
            }
            
        except Exception as e:
            logger.error(f"External services check failed: {e}")
            return {
                'healthy': True,  # Don't fail for external service issues
                'error': str(e),
                'details': 'Could not check external services'
            }
    
    def _check_email_service(self):
        """Check email service connectivity"""
        try:
            from django.core.mail import get_connection
            
            connection = get_connection()
            connection.open()
            connection.close()
            return True
            
        except Exception:
            return False
    
    def _check_s3_service(self):
        """Check S3 connectivity"""
        try:
            import boto3
            from botocore.exceptions import ClientError
            
            s3_client = boto3.client('s3',
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                region_name=getattr(settings, 'AWS_S3_REGION_NAME', 'us-east-1')
            )
            
            # Try to list buckets (minimal operation)
            s3_client.list_buckets()
            return True
            
        except Exception:
            return False
    
    def _check_application_health(self):
        """Check application-specific health indicators"""
        try:
            from django.contrib.auth import get_user_model
            
            # Check if we can query users
            User = get_user_model()
            user_count = User.objects.count()
            
            # Check for any critical errors in recent logs
            # This would integrate with your logging system
            
            return {
                'healthy': True,
                'user_count': user_count,
                'details': 'Application health OK'
            }
            
        except Exception as e:
            logger.error(f"Application health check failed: {e}")
            return {
                'healthy': False,
                'error': str(e),
                'details': 'Application health check failed'
            }

class ReadinessCheckView(View):
    """Kubernetes readiness probe endpoint"""
    
    def get(self, request):
        # Quick checks for readiness (faster than full health check)
        try:
            # Test database
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            
            # Test cache
            cache.set('readiness_check', 'ok', 10)
            
            return JsonResponse({'status': 'ready'})
            
        except Exception as e:
            return JsonResponse({'status': 'not ready', 'error': str(e)}, status=503)

class LivenessCheckView(View):
    """Kubernetes liveness probe endpoint"""
    
    def get(self, request):
        # Very basic check - just return OK if Django is running
        return JsonResponse({'status': 'alive'})
```

---

## 🖥️ Infrastructure Monitoring

### 1. Prometheus Configuration

```yaml
# /etc/prometheus/prometheus.yml

global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    cluster: 'prs-production'
    environment: 'production'

rule_files:
  - "/etc/prometheus/rules/*.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

scrape_configs:
  # PRS Application
  - job_name: 'prs-backend'
    static_configs:
      - targets: ['prs-backend:8000']
    metrics_path: '/metrics/'
    scrape_interval: 30s
    scrape_timeout: 10s

  # Node Exporter (System metrics)
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']

  # PostgreSQL Exporter
  - job_name: 'postgres-exporter'
    static_configs:
      - targets: ['postgres-exporter:9187']

  # Redis Exporter
  - job_name: 'redis-exporter'
    static_configs:
      - targets: ['redis-exporter:9121']

  # Nginx Exporter
  - job_name: 'nginx-exporter'
    static_configs:
      - targets: ['nginx-exporter:9113']

  # Celery Exporter
  - job_name: 'celery-exporter'
    static_configs:
      - targets: ['celery-exporter:9540']

  # Blackbox Exporter (URL monitoring)
  - job_name: 'blackbox'
    metrics_path: /probe
    params:
      module: [http_2xx]
    static_configs:
      - targets:
        - https://yourdomain.com/api/health/
        - https://yourdomain.com/
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: blackbox-exporter:9115

# Recording rules for aggregations
recording_rules:
  - record: prs:http_request_rate
    expr: rate(prs_http_requests_total[5m])
  
  - record: prs:http_request_duration_95th
    expr: histogram_quantile(0.95, rate(prs_http_request_duration_seconds_bucket[5m]))
  
  - record: prs:database_query_rate
    expr: rate(prs_database_queries_total[5m])
```

### 2. Docker Compose for Monitoring Stack

```yaml
# docker-compose.monitoring.yml
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - ./rules/:/etc/prometheus/rules/
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=30d'
      - '--web.enable-lifecycle'
      - '--web.enable-admin-api'

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin123
      - GF_USERS_ALLOW_SIGN_UP=false
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana/dashboards:/etc/grafana/provisioning/dashboards
      - ./grafana/datasources:/etc/grafana/provisioning/datasources

  alertmanager:
    image: prom/alertmanager:latest
    container_name: alertmanager
    ports:
      - "9093:9093"
    volumes:
      - ./alertmanager.yml:/etc/alertmanager/alertmanager.yml
      - alertmanager_data:/alertmanager

  node-exporter:
    image: prom/node-exporter:latest
    container_name: node-exporter
    ports:
      - "9100:9100"
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    command:
      - '--path.procfs=/host/proc'
      - '--path.sysfs=/host/sys'
      - '--path.rootfs=/rootfs'
      - '--collector.filesystem.ignored-mount-points=^/(sys|proc|dev|host|etc)($$|/)'

  postgres-exporter:
    image: prometheuscommunity/postgres-exporter:latest
    container_name: postgres-exporter
    ports:
      - "9187:9187"
    environment:
      DATA_SOURCE_NAME: "postgresql://prs_monitor:monitor_password@postgres:5432/prs_production?sslmode=disable"
    depends_on:
      - postgres

  redis-exporter:
    image: oliver006/redis_exporter:latest
    container_name: redis-exporter
    ports:
      - "9121:9121"
    environment:
      REDIS_ADDR: "redis://redis:6379"
    depends_on:
      - redis

  blackbox-exporter:
    image: prom/blackbox-exporter:latest
    container_name: blackbox-exporter
    ports:
      - "9115:9115"
    volumes:
      - ./blackbox.yml:/etc/blackbox_exporter/config.yml

volumes:
  prometheus_data:
  grafana_data:
  alertmanager_data:

networks:
  default:
    external:
      name: prs_network
```

### 3. Alert Rules Configuration

```yaml
# /etc/prometheus/rules/prs-alerts.yml

groups:
  - name: prs-application
    rules:
      # High error rate
      - alert: HighErrorRate
        expr: rate(prs_http_requests_total{status_code=~"5.."}[5m]) > 0.1
        for: 5m
        labels:
          severity: critical
          service: prs-backend
        annotations:
          summary: "High HTTP error rate detected"
          description: "Error rate is {{ $value | humanize }} errors per second for {{ $labels.instance }}"

      # High response time
      - alert: HighResponseTime
        expr: histogram_quantile(0.95, rate(prs_http_request_duration_seconds_bucket[5m])) > 2
        for: 10m
        labels:
          severity: warning
          service: prs-backend
        annotations:
          summary: "High response time detected"
          description: "95th percentile response time is {{ $value | humanize }}s for {{ $labels.instance }}"

      # Service down
      - alert: ServiceDown
        expr: up{job="prs-backend"} == 0
        for: 2m
        labels:
          severity: critical
          service: prs-backend
        annotations:
          summary: "PRS Backend service is down"
          description: "PRS Backend service has been down for more than 2 minutes"

      # High active users
      - alert: HighActiveUsers
        expr: prs_active_users_total > 1000
        for: 5m
        labels:
          severity: warning
          service: prs-backend
        annotations:
          summary: "High number of active users"
          description: "{{ $value }} active users detected"

  - name: prs-database
    rules:
      # Database connection issues
      - alert: DatabaseConnectionHigh
        expr: pg_stat_activity_count > 80
        for: 5m
        labels:
          severity: warning
          service: postgresql
        annotations:
          summary: "High database connection count"
          description: "Database has {{ $value }} active connections"

      # Slow queries
      - alert: SlowQueries
        expr: pg_stat_activity_max_tx_duration > 300
        for: 2m
        labels:
          severity: warning
          service: postgresql
        annotations:
          summary: "Long running database queries"
          description: "Queries running for more than 5 minutes detected"

      # Database disk usage
      - alert: DatabaseDiskUsageHigh
        expr: pg_database_size_bytes / (1024*1024*1024) > 50
        for: 10m
        labels:
          severity: warning
          service: postgresql
        annotations:
          summary: "Database size is growing large"
          description: "Database size is {{ $value | humanize }}GB"

  - name: prs-infrastructure
    rules:
      # High CPU usage
      - alert: HighCPUUsage
        expr: 100 - (avg by(instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
        for: 10m
        labels:
          severity: warning
          service: system
        annotations:
          summary: "High CPU usage detected"
          description: "CPU usage is {{ $value | humanize }}% on {{ $labels.instance }}"

      # High memory usage
      - alert: HighMemoryUsage
        expr: (node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100 > 80
        for: 5m
        labels:
          severity: warning
          service: system
        annotations:
          summary: "High memory usage detected"
          description: "Memory usage is {{ $value | humanize }}% on {{ $labels.instance }}"

      # Low disk space
      - alert: LowDiskSpace
        expr: (node_filesystem_avail_bytes / node_filesystem_size_bytes) * 100 < 10
        for: 5m
        labels:
          severity: critical
          service: system
        annotations:
          summary: "Low disk space"
          description: "Disk usage is {{ $value | humanize }}% on {{ $labels.instance }} {{ $labels.mountpoint }}"

      # Redis down
      - alert: RedisDown
        expr: redis_up == 0
        for: 2m
        labels:
          severity: critical
          service: redis
        annotations:
          summary: "Redis is down"
          description: "Redis service is not responding"

  - name: prs-business-metrics
    rules:
      # High login failure rate
      - alert: HighLoginFailureRate
        expr: rate(prs_business_events_total{event_type="user_login",status="failure"}[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
          service: prs-backend
        annotations:
          summary: "High login failure rate"
          description: "Login failure rate is {{ $value | humanize }} failures per second"

      # No recent transactions
      - alert: NoRecentTransactions
        expr: increase(prs_business_events_total{event_type="payment_processing"}[1h]) == 0
        for: 2h
        labels:
          severity: warning
          service: prs-backend
        annotations:
          summary: "No recent payment transactions"
          description: "No payment transactions processed in the last 2 hours"
```

---

## 📈 Log Aggregation

### 1. ELK Stack Configuration

#### Elasticsearch Configuration

```yaml
# elasticsearch.yml
cluster.name: "prs-logs"
node.name: "es-node-1"
path.data: /usr/share/elasticsearch/data
path.logs: /usr/share/elasticsearch/logs
network.host: 0.0.0.0
http.port: 9200
discovery.type: single-node

# Security
xpack.security.enabled: true
xpack.security.enrollment.enabled: true

# Performance
indices.memory.index_buffer_size: 30%
indices.breaker.total.use_real_memory: true
```

#### Logstash Configuration

```ruby
# logstash.conf
input {
  beats {
    port => 5044
  }
  
  # Direct log files
  file {
    path => "/var/log/prs/django.log"
    codec => "json"
    tags => ["django", "prs-backend"]
    type => "application"
  }
  
  file {
    path => "/var/log/prs/security.log"
    codec => "json"
    tags => ["security", "prs-backend"]
    type => "security"
  }
  
  file {
    path => "/var/log/nginx/access.log"
    tags => ["nginx", "access"]
    type => "nginx-access"
  }
  
  file {
    path => "/var/log/nginx/error.log"
    tags => ["nginx", "error"]
    type => "nginx-error"
  }
}

filter {
  # Parse Django logs
  if "django" in [tags] {
    json {
      source => "message"
    }
    
    date {
      match => [ "timestamp", "ISO8601" ]
    }
    
    mutate {
      add_field => { "service" => "prs-backend" }
    }
    
    # Extract correlation IDs
    if [correlation_id] {
      mutate {
        add_tag => ["has_correlation_id"]
      }
    }
    
    # Categorize log levels
    if [level] == "ERROR" or [level] == "CRITICAL" {
      mutate {
        add_tag => ["high_priority"]
      }
    }
  }
  
  # Parse security logs
  if "security" in [tags] {
    json {
      source => "message"
    }
    
    mutate {
      add_field => { "service" => "prs-security" }
      add_tag => ["security_event"]
    }
    
    # Extract security event types
    if [event_type] {
      mutate {
        add_field => { "security_category" => "%{event_type}" }
      }
    }
  }
  
  # Parse Nginx access logs
  if "nginx" in [tags] and "access" in [tags] {
    grok {
      match => { 
        "message" => "%{COMBINEDAPACHELOG}" 
      }
    }
    
    date {
      match => [ "timestamp", "dd/MMM/yyyy:HH:mm:ss Z" ]
    }
    
    mutate {
      convert => { "response" => "integer" }
      convert => { "bytes" => "integer" }
      add_field => { "service" => "nginx" }
    }
    
    # Categorize response codes
    if [response] >= 400 {
      mutate {
        add_tag => ["http_error"]
      }
    }
    
    if [response] >= 500 {
      mutate {
        add_tag => ["server_error"]
      }
    }
  }
  
  # Add common fields
  mutate {
    add_field => { 
      "environment" => "production"
      "application" => "prs"
    }
  }
  
  # GeoIP lookup for IP addresses
  if [clientip] {
    geoip {
      source => "clientip"
      target => "geoip"
    }
  }
}

output {
  # Main application logs
  if "django" in [tags] or "prs-backend" in [tags] {
    elasticsearch {
      hosts => ["elasticsearch:9200"]
      index => "prs-application-%{+YYYY.MM.dd}"
      template_name => "prs-application"
    }
  }
  
  # Security logs (separate index)
  if "security" in [tags] {
    elasticsearch {
      hosts => ["elasticsearch:9200"]
      index => "prs-security-%{+YYYY.MM.dd}"
      template_name => "prs-security"
    }
  }
  
  # Infrastructure logs
  if "nginx" in [tags] or "system" in [tags] {
    elasticsearch {
      hosts => ["elasticsearch:9200"]
      index => "prs-infrastructure-%{+YYYY.MM.dd}"
      template_name => "prs-infrastructure"
    }
  }
  
  # High priority alerts to Slack
  if "high_priority" in [tags] or "server_error" in [tags] {
    http {
      url => "${SLACK_WEBHOOK_URL}"
      http_method => "post"
      content_type => "application/json"
      format => "message"
      message => '{
        "text": "🚨 High Priority Log Alert",
        "blocks": [
          {
            "type": "section",
            "text": {
              "type": "mrkdwn",
              "text": "*Service:* %{service}\n*Level:* %{level}\n*Message:* %{message}"
            }
          }
        ]
      }'
    }
  }
  
  # Debug output
  stdout {
    codec => rubydebug
  }
}
```

### 2. Structured Logging Configuration

```python
# core_config/logging_config.py

import os
import json
import logging
from datetime import datetime
from django.conf import settings

class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging"""
    
    def format(self, record):
        # Base log entry
        log_entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'process': record.process,
            'thread': record.thread,
        }
        
        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        # Add extra fields
        for key, value in record.__dict__.items():
            if key not in log_entry and not key.startswith('_'):
                log_entry[key] = value
        
        # Add correlation ID if present
        correlation_id = getattr(record, 'correlation_id', None)
        if correlation_id:
            log_entry['correlation_id'] = correlation_id
        
        # Add request info if present
        if hasattr(record, 'request'):
            request = record.request
            log_entry['request'] = {
                'method': request.method,
                'path': request.path,
                'user': str(request.user) if hasattr(request, 'user') else None,
                'ip': self._get_client_ip(request),
                'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            }
        
        return json.dumps(log_entry, default=str)
    
    def _get_client_ip(self, request):
        """Get client IP from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

# Enhanced logging configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    
    'formatters': {
        'json': {
            '()': JSONFormatter,
        },
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse',
        },
        'require_debug_true': {
            '()': 'django.utils.log.RequireDebugTrue',
        },
        'correlation_id': {
            '()': 'core_config.logging_filters.CorrelationIDFilter',
        },
    },
    
    'handlers': {
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
            'filters': ['correlation_id'],
        },
        
        'file_json': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/var/log/prs/django.log',
            'maxBytes': 10485760,  # 10MB
            'backupCount': 10,
            'formatter': 'json',
            'filters': ['correlation_id'],
        },
        
        'security_file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/var/log/prs/security.log',
            'maxBytes': 10485760,  # 10MB
            'backupCount': 10,
            'formatter': 'json',
        },
        
        'error_file': {
            'level': 'ERROR',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/var/log/prs/errors.log',
            'maxBytes': 10485760,  # 10MB
            'backupCount': 10,
            'formatter': 'json',
            'filters': ['correlation_id'],
        },
        
        'syslog': {
            'level': 'INFO',
            'class': 'logging.handlers.SysLogHandler',
            'address': '/dev/log',
            'formatter': 'json',
            'filters': ['correlation_id'],
        },
    },
    
    'loggers': {
        'django': {
            'handlers': ['console', 'file_json'],
            'level': 'INFO',
            'propagate': True,
        },
        
        'django.request': {
            'handlers': ['error_file'],
            'level': 'ERROR',
            'propagate': False,
        },
        
        'django.security': {
            'handlers': ['security_file'],
            'level': 'INFO',
            'propagate': False,
        },
        
        'prs': {
            'handlers': ['console', 'file_json'],
            'level': 'INFO',
            'propagate': True,
        },
        
        'security': {
            'handlers': ['security_file'],
            'level': 'INFO',
            'propagate': False,
        },
        
        'celery': {
            'handlers': ['file_json'],
            'level': 'INFO',
            'propagate': True,
        },
        
        'root': {
            'handlers': ['console'],
            'level': 'WARNING',
        },
    },
}

# Apply logging configuration
import logging.config
logging.config.dictConfig(LOGGING)
```

This comprehensive monitoring setup guide provides all the necessary configurations for application monitoring, infrastructure monitoring, log aggregation, and alerting. The next section will continue with alerting configuration and dashboard setup.
