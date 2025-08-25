# Comprehensive Troubleshooting Guide

## Overview

This guide provides systematic troubleshooting procedures for common issues in the Payment Receiving System (PRS) Backend. It covers application issues, infrastructure problems, performance optimization, and diagnostic techniques.

---

## 📋 Table of Contents

1. [General Troubleshooting Methodology](#general-troubleshooting-methodology)
2. [Application Issues](#application-issues)
3. [Database Problems](#database-problems)
4. [Performance Issues](#performance-issues)
5. [Network and Connectivity](#network-and-connectivity)
6. [Security Issues](#security-issues)
7. [Deployment Problems](#deployment-problems)
8. [Diagnostic Tools and Scripts](#diagnostic-tools-and-scripts)

---

## 🔍 General Troubleshooting Methodology

### The SAFER Approach

1. **🔍 Symptoms**: What is the observable problem?
2. **📊 Analyze**: Gather data and analyze logs
3. **🎯 Focus**: Narrow down to root cause
4. **🛠️ Execute**: Implement solution
5. **✅ Review**: Verify fix and document

### Information Gathering Checklist

```bash
# Quick system overview
echo "=== SYSTEM OVERVIEW ==="
date
uptime
whoami
hostname
uname -a

echo -e "\n=== DISK USAGE ==="
df -h

echo -e "\n=== MEMORY USAGE ==="
free -h

echo -e "\n=== LOAD AVERAGE ==="
cat /proc/loadavg

echo -e "\n=== RECENT KERNEL MESSAGES ==="
dmesg | tail -10

echo -e "\n=== SERVICE STATUS ==="
systemctl is-active prs-backend nginx postgresql redis

echo -e "\n=== RECENT LOG ENTRIES ==="
journalctl -u prs-backend --lines=10 --no-pager
```

### Log Analysis Strategy

```bash
#!/bin/bash
# scripts/troubleshoot/analyze-logs.sh

LOG_DIR=${1:-"/var/log/prs"}
TIME_RANGE=${2:-"1h"}

echo "🔍 Analyzing logs from $LOG_DIR for last $TIME_RANGE"

# Error patterns to search for
ERROR_PATTERNS=(
    "ERROR"
    "CRITICAL" 
    "Exception"
    "Traceback"
    "500"
    "502"
    "503"
    "504"
    "Connection.*refused"
    "Timeout"
    "Database.*error"
    "Memory.*error"
    "Permission.*denied"
)

# Search for error patterns
echo "=== ERROR ANALYSIS ==="
for pattern in "${ERROR_PATTERNS[@]}"; do
    count=$(find "$LOG_DIR" -name "*.log" -exec grep -l "$pattern" {} \; 2>/dev/null | \
           xargs grep -c "$pattern" 2>/dev/null | \
           awk -F: '{sum+=$2} END {print sum+0}')
    
    if [ "$count" -gt 0 ]; then
        echo "[$pattern]: $count occurrences"
        
        # Show recent examples
        find "$LOG_DIR" -name "*.log" -exec grep -l "$pattern" {} \; 2>/dev/null | \
        xargs grep "$pattern" 2>/dev/null | \
        tail -3 | \
        sed 's/^/  ► /'
        echo
    fi
done

# Analyze log volume
echo "=== LOG VOLUME ANALYSIS ==="
find "$LOG_DIR" -name "*.log" -exec wc -l {} \; | \
    sort -nr | \
    head -5 | \
    while read lines file; do
        echo "$file: $lines lines"
    done

# Check for log rotation issues
echo "=== LOG ROTATION STATUS ==="
find "$LOG_DIR" -name "*.log.*" | wc -l | xargs echo "Rotated log files:"
find "$LOG_DIR" -name "*.log" -size +100M | xargs echo "Large log files:"
```

---

## 🐛 Application Issues

### 1. Application Won't Start

#### Symptoms
- Service fails to start
- HTTP 502/503 errors
- Connection refused errors

#### Diagnostic Steps

```bash
# Check service status
systemctl status prs-backend

# Check for port conflicts
netstat -tulpn | grep :8000
lsof -i :8000

# Check application logs
journalctl -u prs-backend -f

# Test Python environment
cd /app && python manage.py check

# Check dependencies
cd /app && pip check
```

#### Common Solutions

1. **Port Already in Use**
```bash
# Find process using port
sudo lsof -i :8000
sudo kill -9 <PID>

# Or change port in configuration
export PORT=8001
```

2. **Missing Dependencies**
```bash
# Reinstall requirements
cd /app
pip install -r requirements/production.txt
```

3. **Database Migration Issues**
```bash
# Check migration status
python manage.py showmigrations

# Apply pending migrations
python manage.py migrate
```

4. **Environment Variables**
```bash
# Check required variables
env | grep -E "(SECRET_KEY|DATABASE_URL|REDIS_URL)"

# Reload environment
source .env.production
```

### 2. Application Running but Not Responding

#### Symptoms
- Long response times
- Timeouts
- 504 Gateway Timeout

#### Diagnostic Steps

```bash
# Check if processes are running
ps aux | grep gunicorn

# Check system resources
top -p $(pgrep -d',' -f gunicorn)

# Check network connections
netstat -an | grep :8000

# Test application directly
curl -v http://localhost:8000/api/health/

# Check for deadlocks
python manage.py shell -c "
from django.db import connection
cursor = connection.cursor()
cursor.execute('SELECT * FROM pg_stat_activity WHERE state = \'active\';')
print(cursor.fetchall())
"
```

#### Solutions

1. **Restart Workers**
```bash
# Graceful reload
kill -HUP $(pgrep -f "gunicorn.*master")

# Hard restart
systemctl restart prs-backend
```

2. **Scale Workers**
```bash
# Temporary scaling
kill -TTIN $(pgrep -f "gunicorn.*master")  # Add worker
kill -TTOU $(pgrep -f "gunicorn.*master")  # Remove worker

# Permanent scaling
export GUNICORN_WORKERS=6
systemctl restart prs-backend
```

3. **Clear Locks**
```bash
# Check for application locks
find /tmp -name "*.lock" -user prs

# Remove stale locks (carefully!)
find /tmp -name "*.lock" -mmin +30 -delete
```

### 3. Memory Leaks

#### Symptoms
- Gradually increasing memory usage
- Out of memory errors
- Application crashes

#### Diagnostic Steps

```bash
# Monitor memory usage over time
watch -n 5 'ps aux | grep gunicorn | grep -v grep'

# Check for memory leaks in Python
python -c "
import psutil
import os
process = psutil.Process()
print(f'Memory usage: {process.memory_info().rss / 1024 / 1024:.2f} MB')
"

# Profile memory usage
python manage.py shell -c "
import tracemalloc
tracemalloc.start()
# Run some operations
current, peak = tracemalloc.get_traced_memory()
print(f'Current: {current / 1024 / 1024:.2f} MB, Peak: {peak / 1024 / 1024:.2f} MB')
tracemalloc.stop()
"
```

#### Solutions

1. **Worker Recycling**
```bash
# Configure max requests per worker
export GUNICORN_MAX_REQUESTS=1000
export GUNICORN_MAX_REQUESTS_JITTER=100
systemctl restart prs-backend
```

2. **Memory Optimization**
```python
# In Django settings
# Reduce query caching
DATABASES['default']['OPTIONS']['MAX_CONNS'] = 20

# Optimize middleware
MIDDLEWARE = [m for m in MIDDLEWARE if 'debug' not in m.lower()]

# Clear caches periodically
from django.core.cache import cache
cache.clear()
```

---

## 🗄️ Database Problems

### 1. Connection Issues

#### Symptoms
- "Connection refused" errors
- "Too many connections" errors
- Slow database queries

#### Diagnostic Steps

```sql
-- Check connection count
SELECT count(*) FROM pg_stat_activity;

-- Check connection states
SELECT state, count(*) FROM pg_stat_activity GROUP BY state;

-- Find long-running connections
SELECT pid, usename, application_name, client_addr, query_start, state, query 
FROM pg_stat_activity 
WHERE query_start < now() - interval '5 minutes'
ORDER BY query_start;

-- Check connection limits
SELECT name, setting FROM pg_settings WHERE name = 'max_connections';
```

#### Solutions

1. **Connection Pool Configuration**
```python
# In Django settings
DATABASES = {
    'default': {
        # ... other settings
        'CONN_MAX_AGE': 300,  # 5 minutes
        'OPTIONS': {
            'MAX_CONNS': 20,
        }
    }
}
```

2. **Kill Idle Connections**
```sql
-- Kill idle connections older than 1 hour
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE state = 'idle'
AND query_start < now() - interval '1 hour';
```

3. **Connection Pooling with PgBouncer**
```ini
# /etc/pgbouncer/pgbouncer.ini
[databases]
prs_production = host=localhost port=5432 dbname=prs_production

[pgbouncer]
pool_mode = transaction
max_client_conn = 100
default_pool_size = 25
reserve_pool_size = 5
```

### 2. Slow Queries

#### Symptoms
- High response times
- Database timeouts
- CPU spikes on database server

#### Diagnostic Steps

```sql
-- Enable slow query logging
ALTER SYSTEM SET log_min_duration_statement = 1000;  -- Log queries > 1s
SELECT pg_reload_conf();

-- Check currently running slow queries
SELECT pid, now() - pg_stat_activity.query_start AS duration, query 
FROM pg_stat_activity 
WHERE (now() - pg_stat_activity.query_start) > interval '5 minutes';

-- Find most expensive queries
SELECT query, mean_exec_time, calls, total_exec_time
FROM pg_stat_statements 
ORDER BY mean_exec_time DESC 
LIMIT 10;

-- Check for missing indexes
SELECT schemaname, tablename, attname, n_distinct, correlation 
FROM pg_stats 
WHERE schemaname = 'public' 
AND n_distinct > 100 
AND correlation < 0.1;
```

#### Solutions

1. **Add Missing Indexes**
```sql
-- Example: Add index for frequently queried fields
CREATE INDEX CONCURRENTLY idx_deals_status_created 
ON deals (status, created_at) 
WHERE status IN ('active', 'pending');

-- Composite indexes for complex queries
CREATE INDEX CONCURRENTLY idx_payments_deal_status_date
ON payments (deal_id, status, payment_date);
```

2. **Query Optimization**
```python
# Use select_related for foreign keys
deals = Deal.objects.select_related('client', 'assigned_to').all()

# Use prefetch_related for reverse foreign keys
users = User.objects.prefetch_related('deals', 'payments').all()

# Add database indexes in models
class Deal(models.Model):
    status = models.CharField(max_length=20, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['status', 'created_at']),
            models.Index(fields=['client', 'status']),
        ]
```

3. **Connection Settings**
```python
# Optimize database settings
DATABASES['default']['OPTIONS'].update({
    'connect_timeout': 10,
    'options': '-c default_statistics_target=100'
})
```

### 3. Database Corruption

#### Symptoms
- Data inconsistencies
- Constraint violations
- Index corruption errors

#### Diagnostic Steps

```sql
-- Check for corruption
SELECT pg_database_size(current_database());
REINDEX DATABASE prs_production;

-- Verify data integrity
SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';

-- Check for orphaned records
SELECT d.id FROM deals d 
LEFT JOIN clients c ON d.client_id = c.id 
WHERE c.id IS NULL;
```

#### Solutions

1. **Repair Corruption**
```sql
-- Reindex specific tables
REINDEX TABLE deals;
REINDEX TABLE payments;

-- Update table statistics
ANALYZE deals;
ANALYZE payments;

-- Vacuum tables
VACUUM FULL deals;
VACUUM FULL payments;
```

2. **Restore from Backup**
```bash
# Stop application
systemctl stop prs-backend

# Restore from backup
pg_restore -h localhost -U postgres -d prs_production \
    --clean --if-exists /path/to/backup.sql

# Restart application
systemctl start prs-backend
```

---

## ⚡ Performance Issues

### 1. High CPU Usage

#### Symptoms
- System load > number of CPU cores
- Slow response times
- High CPU in top/htop

#### Diagnostic Steps

```bash
# Check CPU usage by process
top -bn1 | head -20

# Check system load
uptime
cat /proc/loadavg

# Profile Python application
python -m cProfile -o profile.stats manage.py runserver

# Check for CPU-intensive queries
python manage.py shell -c "
from django.db import connection
print(connection.queries[-10:])  # Last 10 queries
"
```

#### Solutions

1. **Code Optimization**
```python
# Use database aggregation instead of Python loops
from django.db.models import Sum, Count, Avg

# Instead of:
total = sum(deal.value for deal in deals)

# Use:
total = deals.aggregate(Sum('value'))['value__sum']

# Cache expensive operations
from django.core.cache import cache

def expensive_operation():
    result = cache.get('expensive_result')
    if result is None:
        result = calculate_complex_data()
        cache.set('expensive_result', result, 300)  # 5 minutes
    return result
```

2. **Scale Infrastructure**
```bash
# Add more Gunicorn workers
export GUNICORN_WORKERS=$(nproc)
systemctl restart prs-backend

# Use async workers for I/O bound tasks
export GUNICORN_WORKER_CLASS=gevent
```

### 2. Memory Issues

#### Symptoms
- High memory usage
- Out of memory errors
- Swap usage

#### Diagnostic Steps

```bash
# Check memory usage
free -h
cat /proc/meminfo | grep -E "(MemTotal|MemAvailable|SwapTotal|SwapFree)"

# Check memory per process
ps aux --sort=-%mem | head -10

# Check for memory leaks
valgrind --tool=memcheck --leak-check=full python manage.py test
```

#### Solutions

1. **Memory Optimization**
```python
# Use iterators for large datasets
def process_large_dataset():
    for chunk in Deal.objects.all().iterator(chunk_size=1000):
        process_chunk(chunk)

# Clear query cache periodically
from django.db import reset_queries
reset_queries()

# Optimize queryset size
deals = Deal.objects.only('id', 'title', 'value')  # Only load needed fields
```

2. **System Tuning**
```bash
# Increase swap if needed (temporary)
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile

# Tune memory settings
echo 'vm.swappiness=10' >> /etc/sysctl.conf
sysctl -p
```

### 3. Disk I/O Issues

#### Symptoms
- High iowait in top
- Slow database queries
- Application timeouts

#### Diagnostic Steps

```bash
# Check disk usage and I/O
df -h
iostat -x 1 5

# Check disk performance
hdparm -tT /dev/sda

# Find processes causing high I/O
iotop -o

# Check database I/O
python manage.py dbshell -c "
SELECT schemaname, tablename, heap_blks_read, heap_blks_hit,
       heap_blks_hit::float / (heap_blks_hit + heap_blks_read) AS cache_hit_ratio
FROM pg_statio_user_tables 
WHERE heap_blks_read > 0 
ORDER BY heap_blks_read DESC;
"
```

#### Solutions

1. **Database Optimization**
```sql
-- Increase shared buffers
ALTER SYSTEM SET shared_buffers = '256MB';

-- Optimize checkpoint settings
ALTER SYSTEM SET checkpoint_segments = 32;
ALTER SYSTEM SET checkpoint_completion_target = 0.9;

-- Reload configuration
SELECT pg_reload_conf();
```

2. **Application Caching**
```python
# Cache database queries
from django.views.decorators.cache import cache_page

@cache_page(60 * 5)  # Cache for 5 minutes
def expensive_view(request):
    # Expensive database operations
    pass

# Use Django's ORM efficiently
# Avoid N+1 queries
deals = Deal.objects.select_related('client').prefetch_related('payments')
```

---

## 🌐 Network and Connectivity

### 1. DNS Issues

#### Symptoms
- Cannot resolve domain names
- Slow DNS lookups
- Connection timeouts

#### Diagnostic Steps

```bash
# Test DNS resolution
nslookup yourdomain.com
dig yourdomain.com

# Check DNS servers
cat /etc/resolv.conf

# Test connectivity
ping google.com
traceroute google.com

# Check application DNS usage
strace -e trace=network python manage.py check
```

#### Solutions

1. **DNS Configuration**
```bash
# Use reliable DNS servers
echo "nameserver 8.8.8.8" > /etc/resolv.conf
echo "nameserver 8.8.4.4" >> /etc/resolv.conf

# Flush DNS cache
systemctl flush-dns
```

2. **Application Configuration**
```python
# Use IP addresses for critical services
DATABASES = {
    'default': {
        'HOST': '10.0.1.100',  # Use IP instead of hostname
    }
}
```

### 2. SSL/TLS Issues

#### Symptoms
- SSL handshake failures
- Certificate errors
- Mixed content warnings

#### Diagnostic Steps

```bash
# Check certificate
openssl s_client -connect yourdomain.com:443 -servername yourdomain.com

# Check certificate expiry
echo | openssl s_client -servername yourdomain.com -connect yourdomain.com:443 2>/dev/null | \
    openssl x509 -noout -dates

# Test SSL configuration
curl -vI https://yourdomain.com
```

#### Solutions

1. **Certificate Renewal**
```bash
# Renew Let's Encrypt certificate
certbot renew --nginx

# Or manually
certbot certonly --nginx -d yourdomain.com
```

2. **Nginx SSL Configuration**
```nginx
server {
    listen 443 ssl http2;
    server_name yourdomain.com;
    
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
}
```

---

## 🔒 Security Issues

### 1. Authentication Failures

#### Symptoms
- Users cannot log in
- Authentication errors
- Token validation failures

#### Diagnostic Steps

```bash
# Check authentication logs
grep -i "authentication" /var/log/prs/security.log | tail -20

# Check for brute force attempts
awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -nr | head -10

# Test authentication endpoint
curl -X POST -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"testpass"}' \
    http://localhost:8000/api/auth/login/
```

#### Solutions

1. **Reset Authentication**
```python
# Clear sessions
python manage.py clearsessions

# Reset user password
python manage.py shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
user = User.objects.get(email='user@example.com')
user.set_password('newpassword')
user.save()
"
```

2. **Check Token Validity**
```python
# Validate tokens
python manage.py shell -c "
from rest_framework.authtoken.models import Token
from django.utils import timezone
from datetime import timedelta

# Check for expired tokens
old_tokens = Token.objects.filter(
    created__lt=timezone.now() - timedelta(days=30)
)
print(f'Old tokens: {old_tokens.count()}')
"
```

### 2. Permission Issues

#### Symptoms
- 403 Forbidden errors
- Users cannot access resources
- Permission denied messages

#### Diagnostic Steps

```python
# Check user permissions
python manage.py shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
user = User.objects.get(email='user@example.com')
print('Permissions:', user.get_all_permissions())
print('Groups:', user.groups.all())
print('Is staff:', user.is_staff)
print('Is superuser:', user.is_superuser)
"
```

#### Solutions

1. **Fix Permissions**
```python
# Add permissions to user
python manage.py shell -c "
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
User = get_user_model()

user = User.objects.get(email='user@example.com')
permission = Permission.objects.get(codename='view_deal')
user.user_permissions.add(permission)
"
```

---

## 🚀 Deployment Problems

### 1. Migration Failures

#### Symptoms
- Deployment fails during migration
- Database schema inconsistencies
- Migration conflicts

#### Diagnostic Steps

```bash
# Check migration status
python manage.py showmigrations

# Check for migration conflicts
python manage.py check

# Test migrations in isolation
python manage.py migrate --plan
python manage.py sqlmigrate app_name migration_name
```

#### Solutions

1. **Resolve Migration Conflicts**
```bash
# Create merge migration
python manage.py makemigrations --merge

# Or rollback conflicting migrations
python manage.py migrate app_name 0001_initial
```

2. **Manual Migration Fixes**
```python
# Fix migration dependencies
# In migration file:
dependencies = [
    ('app_name', '0001_initial'),
    ('other_app', '0002_some_migration'),
]
```

### 2. Static File Issues

#### Symptoms
- CSS/JS files not loading
- 404 errors for static files
- Broken styling

#### Diagnostic Steps

```bash
# Check static files collection
python manage.py collectstatic --dry-run

# Check static file settings
python manage.py shell -c "
from django.conf import settings
print('STATIC_URL:', settings.STATIC_URL)
print('STATIC_ROOT:', settings.STATIC_ROOT)
print('STATICFILES_DIRS:', settings.STATICFILES_DIRS)
"

# Test static file serving
curl -I http://localhost:8000/static/admin/css/base.css
```

#### Solutions

1. **Recollect Static Files**
```bash
# Clear and recollect static files
rm -rf /app/staticfiles/*
python manage.py collectstatic --clear --noinput
```

2. **Fix Static File Configuration**
```python
# In settings
STATIC_URL = '/static/'
STATIC_ROOT = '/app/staticfiles'
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static'),
]
```

---

## 🛠️ Diagnostic Tools and Scripts

### 1. System Health Check

```bash
#!/bin/bash
# scripts/troubleshoot/health-check.sh

echo "🏥 PRS System Health Check"
echo "========================="

# Check service status
echo "📊 Service Status:"
systemctl is-active --quiet prs-backend && echo "  ✅ PRS Backend: Running" || echo "  ❌ PRS Backend: Stopped"
systemctl is-active --quiet nginx && echo "  ✅ Nginx: Running" || echo "  ❌ Nginx: Stopped"
systemctl is-active --quiet postgresql && echo "  ✅ PostgreSQL: Running" || echo "  ❌ PostgreSQL: Stopped"
systemctl is-active --quiet redis && echo "  ✅ Redis: Running" || echo "  ❌ Redis: Stopped"

# Check system resources
echo -e "\n💾 System Resources:"
echo "  Memory: $(free -h | awk 'NR==2{printf "%.1f%% used\n", $3*100/$2}')"
echo "  Disk: $(df -h / | awk 'NR==2{printf "%s used (%s)\n", $5, $4}')"
echo "  Load: $(uptime | awk -F'load average:' '{print $2}')"

# Check network connectivity
echo -e "\n🌐 Network Connectivity:"
ping -c 1 google.com >/dev/null 2>&1 && echo "  ✅ Internet: Connected" || echo "  ❌ Internet: Failed"

# Check application health
echo -e "\n🔍 Application Health:"
if curl -sf http://localhost:8000/api/health/ >/dev/null; then
    echo "  ✅ Application: Healthy"
else
    echo "  ❌ Application: Unhealthy"
fi

# Check database connectivity
echo -e "\n🗄️ Database Health:"
if python manage.py dbshell --command="SELECT 1;" >/dev/null 2>&1; then
    echo "  ✅ Database: Connected"
else
    echo "  ❌ Database: Connection failed"
fi

# Check recent errors
echo -e "\n📋 Recent Errors (last hour):"
error_count=$(journalctl -u prs-backend --since="1 hour ago" | grep -i error | wc -l)
echo "  Error count: $error_count"

if [ $error_count -gt 0 ]; then
    echo "  Recent errors:"
    journalctl -u prs-backend --since="1 hour ago" | grep -i error | tail -3 | sed 's/^/    /'
fi

echo -e "\n✅ Health check completed"
```

### 2. Performance Profiler

```python
#!/usr/bin/env python3
# scripts/troubleshoot/performance-profiler.py

import os
import sys
import time
import psutil
import django
from django.core.management import execute_from_command_line

# Setup Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core_config.settings")
django.setup()

class PerformanceProfiler:
    def __init__(self):
        self.process = psutil.Process()
        self.start_time = time.time()
        self.start_cpu = self.process.cpu_percent()
        self.start_memory = self.process.memory_info()
    
    def profile_database_queries(self):
        """Profile database query performance"""
        from django.db import connection, reset_queries
        from django.test.utils import override_settings
        
        print("🔍 Database Query Profiling")
        print("=" * 40)
        
        # Enable query logging
        with override_settings(DEBUG=True):
            reset_queries()
            
            # Run some test queries
            from django.contrib.auth import get_user_model
            User = get_user_model()
            
            start_time = time.time()
            users = list(User.objects.all()[:100])
            query_time = time.time() - start_time
            
            queries = connection.queries
            
            print(f"Query count: {len(queries)}")
            print(f"Query time: {query_time:.3f}s")
            print(f"Records fetched: {len(users)}")
            
            # Show slow queries
            slow_queries = [q for q in queries if float(q['time']) > 0.1]
            if slow_queries:
                print(f"\n⚠️ Slow queries ({len(slow_queries)}):")
                for query in slow_queries:
                    print(f"  {query['time']}s: {query['sql'][:100]}...")
            
            return {
                'query_count': len(queries),
                'query_time': query_time,
                'slow_queries': len(slow_queries)
            }
    
    def profile_memory_usage(self):
        """Profile memory usage patterns"""
        print("\n💾 Memory Usage Profiling")
        print("=" * 40)
        
        import tracemalloc
        tracemalloc.start()
        
        # Simulate workload
        from django.contrib.auth import get_user_model
        User = get_user_model()
        
        initial_memory = self.process.memory_info().rss
        
        # Load data
        users = list(User.objects.all())
        
        current, peak = tracemalloc.get_traced_memory()
        final_memory = self.process.memory_info().rss
        
        print(f"Initial memory: {initial_memory / 1024 / 1024:.1f} MB")
        print(f"Final memory: {final_memory / 1024 / 1024:.1f} MB")
        print(f"Memory increase: {(final_memory - initial_memory) / 1024 / 1024:.1f} MB")
        print(f"Tracemalloc current: {current / 1024 / 1024:.1f} MB")
        print(f"Tracemalloc peak: {peak / 1024 / 1024:.1f} MB")
        
        tracemalloc.stop()
        
        return {
            'memory_increase': (final_memory - initial_memory) / 1024 / 1024,
            'peak_memory': peak / 1024 / 1024
        }
    
    def profile_cpu_usage(self):
        """Profile CPU usage"""
        print("\n⚡ CPU Usage Profiling")
        print("=" * 40)
        
        import cProfile
        import pstats
        import io
        
        pr = cProfile.Profile()
        pr.enable()
        
        # Run test workload
        from django.contrib.auth import get_user_model
        User = get_user_model()
        users = User.objects.all()
        for user in users[:50]:
            str(user)  # Force evaluation
        
        pr.disable()
        
        # Analyze results
        s = io.StringIO()
        ps = pstats.Stats(pr, stream=s).sort_stats('cumulative')
        ps.print_stats(10)  # Top 10 functions
        
        profile_output = s.getvalue()
        print("Top CPU consumers:")
        print(profile_output.split('\n')[5:15])  # Skip headers
        
        # System CPU usage
        cpu_percent = self.process.cpu_percent()
        cpu_times = self.process.cpu_times()
        
        print(f"\nSystem CPU usage: {cpu_percent}%")
        print(f"User time: {cpu_times.user:.2f}s")
        print(f"System time: {cpu_times.system:.2f}s")
        
        return {
            'cpu_percent': cpu_percent,
            'user_time': cpu_times.user,
            'system_time': cpu_times.system
        }
    
    def generate_report(self):
        """Generate comprehensive performance report"""
        print("📊 PRS Performance Profile Report")
        print("=" * 50)
        
        db_profile = self.profile_database_queries()
        memory_profile = self.profile_memory_usage()
        cpu_profile = self.profile_cpu_usage()
        
        # Overall system metrics
        print(f"\n🎯 Overall Metrics")
        print("=" * 20)
        print(f"Total runtime: {time.time() - self.start_time:.2f}s")
        print(f"Database queries: {db_profile['query_count']}")
        print(f"Memory usage: {memory_profile['memory_increase']:.1f} MB increase")
        print(f"CPU usage: {cpu_profile['cpu_percent']}%")
        
        # Recommendations
        print(f"\n💡 Recommendations")
        print("=" * 20)
        
        if db_profile['slow_queries'] > 0:
            print("  - Optimize slow database queries")
        if memory_profile['memory_increase'] > 100:
            print("  - Memory usage is high, consider optimization")
        if cpu_profile['cpu_percent'] > 80:
            print("  - High CPU usage detected, review algorithms")
        
        print("\n✅ Performance profiling completed")

def main():
    profiler = PerformanceProfiler()
    profiler.generate_report()

if __name__ == "__main__":
    main()
```

### 3. Log Analyzer

```bash
#!/bin/bash
# scripts/troubleshoot/log-analyzer.sh

LOG_FILE=${1:-"/var/log/prs/django.log"}
TIME_RANGE=${2:-"24h"}

echo "📋 Log Analysis Report"
echo "======================"
echo "File: $LOG_FILE"
echo "Time Range: Last $TIME_RANGE"
echo "Generated: $(date)"

if [ ! -f "$LOG_FILE" ]; then
    echo "❌ Log file not found: $LOG_FILE"
    exit 1
fi

# Calculate time threshold
case $TIME_RANGE in
    "1h") SINCE=$(date -d "1 hour ago" +"%Y-%m-%d %H:%M:%S");;
    "24h") SINCE=$(date -d "1 day ago" +"%Y-%m-%d %H:%M:%S");;
    "7d") SINCE=$(date -d "7 days ago" +"%Y-%m-%d %H:%M:%S");;
    *) SINCE=$(date -d "1 day ago" +"%Y-%m-%d %H:%M:%S");;
esac

# Error analysis
echo -e "\n🚨 Error Analysis"
echo "=================="

ERROR_COUNT=$(grep -c "ERROR\|CRITICAL" "$LOG_FILE" || echo "0")
WARNING_COUNT=$(grep -c "WARNING" "$LOG_FILE" || echo "0")
INFO_COUNT=$(grep -c "INFO" "$LOG_FILE" || echo "0")

echo "Error count: $ERROR_COUNT"
echo "Warning count: $WARNING_COUNT"
echo "Info count: $INFO_COUNT"

if [ "$ERROR_COUNT" -gt 0 ]; then
    echo -e "\nTop error patterns:"
    grep -o "ERROR.*" "$LOG_FILE" | \
        sed 's/ERROR[[:space:]]*//' | \
        sort | uniq -c | sort -nr | head -5
fi

# Request pattern analysis
echo -e "\n🔍 Request Analysis"
echo "===================="

if grep -q "HTTP" "$LOG_FILE"; then
    echo "HTTP status code distribution:"
    grep -o "HTTP/[0-9.]*\" [0-9][0-9][0-9]" "$LOG_FILE" | \
        awk '{print $2}' | sort | uniq -c | sort -nr
    
    echo -e "\nTop requested endpoints:"
    grep -o "\"[A-Z]* /[^\"]*" "$LOG_FILE" | \
        sed 's/"[A-Z]* //' | \
        sort | uniq -c | sort -nr | head -10
fi

# Performance analysis
echo -e "\n⚡ Performance Analysis"
echo "======================="

if grep -q "response_time" "$LOG_FILE"; then
    echo "Response time analysis:"
    grep -o "response_time\":[0-9.]*" "$LOG_FILE" | \
        cut -d':' -f2 | \
        sort -n | \
        awk '{
            sum += $1; 
            count++; 
            if(count == 1) min = $1; 
            max = $1
        } 
        END {
            print "Min: " min "s, Max: " max "s, Avg: " sum/count "s, Count: " count
        }'
fi

# Security analysis
echo -e "\n🔒 Security Analysis"
echo "===================="

FAILED_LOGINS=$(grep -c "authentication.*failed\|login.*failed" "$LOG_FILE" || echo "0")
echo "Failed login attempts: $FAILED_LOGINS"

if [ "$FAILED_LOGINS" -gt 0 ]; then
    echo "Failed login patterns:"
    grep -i "authentication.*failed\|login.*failed" "$LOG_FILE" | \
        tail -5 | \
        sed 's/^/  /'
fi

echo -e "\n✅ Log analysis completed"
```

This comprehensive troubleshooting guide provides systematic approaches to diagnosing and resolving common issues in the PRS backend system, complete with diagnostic scripts and practical solutions.
