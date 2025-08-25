#!/bin/bash
# PRS Backend Maintenance Script
# Regular maintenance tasks for optimal system performance
set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BACKEND_DIR="$PROJECT_ROOT/backend"
VENV_DIR="$PROJECT_ROOT/venv"
LOG_DIR="$PROJECT_ROOT/logs"

# Default values
MAINTENANCE_TYPE=${MAINTENANCE_TYPE:-daily}
BACKUP_RETENTION_DAYS=${BACKUP_RETENTION_DAYS:-30}
LOG_RETENTION_DAYS=${LOG_RETENTION_DAYS:-7}
CLEANUP_TEMP_FILES=${CLEANUP_TEMP_FILES:-true}
OPTIMIZE_DATABASE=${OPTIMIZE_DATABASE:-true}
GENERATE_REPORTS=${GENERATE_REPORTS:-true}

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}[MAINT]${NC} $1"
}

# Function to activate virtual environment
activate_venv() {
    if [ -f "$VENV_DIR/bin/activate" ]; then
        source "$VENV_DIR/bin/activate"
    else
        print_error "Virtual environment not found"
        exit 1
    fi
}

# Function to cleanup old files
cleanup_old_files() {
    print_header "Cleaning Up Old Files"
    
    # Clean up old log files
    if [ -d "$LOG_DIR" ]; then
        print_status "Cleaning log files older than $LOG_RETENTION_DAYS days..."
        find "$LOG_DIR" -name "*.log" -mtime +$LOG_RETENTION_DAYS -delete 2>/dev/null || true
        find "$LOG_DIR" -name "*.log.*" -mtime +$LOG_RETENTION_DAYS -delete 2>/dev/null || true
    fi
    
    # Clean up old backup files
    if [ -d "$PROJECT_ROOT/backups" ]; then
        print_status "Cleaning backup files older than $BACKUP_RETENTION_DAYS days..."
        find "$PROJECT_ROOT/backups" -name "*.sql" -mtime +$BACKUP_RETENTION_DAYS -delete 2>/dev/null || true
        find "$PROJECT_ROOT/backups" -name "*.gz" -mtime +$BACKUP_RETENTION_DAYS -delete 2>/dev/null || true
    fi
    
    # Clean up temporary files
    if [ "$CLEANUP_TEMP_FILES" = "true" ]; then
        print_status "Cleaning temporary files..."
        
        # Clean Django temporary files
        if [ -d "$BACKEND_DIR/media/temp" ]; then
            find "$BACKEND_DIR/media/temp" -type f -mtime +1 -delete 2>/dev/null || true
        fi
        
        # Clean Python cache files
        find "$BACKEND_DIR" -name "*.pyc" -delete 2>/dev/null || true
        find "$BACKEND_DIR" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
        
        # Clean session files
        find /tmp -name "django_session_*" -mtime +1 -delete 2>/dev/null || true
    fi
    
    print_status "File cleanup completed"
}

# Function to perform database maintenance
database_maintenance() {
    if [ "$OPTIMIZE_DATABASE" = "false" ]; then
        print_warning "Skipping database maintenance"
        return
    fi
    
    print_header "Database Maintenance"
    cd "$BACKEND_DIR"
    
    # Clear expired sessions
    print_status "Clearing expired sessions..."
    python manage.py clearsessions
    
    # Clean up duplicate commissions
    print_status "Cleaning up duplicate commissions..."
    python manage.py cleanup_duplicate_commissions --dry-run || print_warning "Commission cleanup check failed"
    
    # Optimize database queries
    print_status "Analyzing database performance..."
    python manage.py optimize_database --action analyze || print_warning "Database analysis failed"
    
    # Optimize commission calculations
    print_status "Optimizing commission calculations..."
    python manage.py optimize_commissions --action analytics || print_warning "Commission optimization failed"
    
    # Validate financial fields
    print_status "Validating financial fields..."
    python manage.py optimize_financial_fields --action validate || print_warning "Financial field validation failed"
    
    # Workflow maintenance
    print_status "Running workflow maintenance..."
    python manage.py workflow_maintenance --action cleanup || print_warning "Workflow maintenance failed"
    
    print_status "Database maintenance completed"
}

# Function to perform cache maintenance
cache_maintenance() {
    print_header "Cache Maintenance"
    cd "$BACKEND_DIR"
    
    # Warm up role cache
    print_status "Warming up role cache..."
    python manage.py manage_role_cache --action warm || print_warning "Role cache warmup failed"
    
    # Warm up commission cache
    print_status "Warming up commission cache..."
    python manage.py optimize_commissions --action cache-warmup || print_warning "Commission cache warmup failed"
    
    # Clear old monitoring metrics
    print_status "Cleaning up old monitoring metrics..."
    python manage.py manage_monitoring cleanup || print_warning "Monitoring cleanup failed"
    
    print_status "Cache maintenance completed"
}

# Function to perform security maintenance
security_maintenance() {
    print_header "Security Maintenance"
    cd "$BACKEND_DIR"
    
    # Check password expiration
    print_status "Checking password expiration policies..."
    python manage.py check_password_expiration || print_warning "Password expiration check failed"
    
    # Analyze organization queries for security
    print_status "Analyzing organization queries..."
    python manage.py analyze_org_queries || print_warning "Organization query analysis failed"
    
    # Run security checks
    print_status "Running security checks..."
    python manage.py check --deploy || print_warning "Security checks found issues"
    
    print_status "Security maintenance completed"
}

# Function to perform monitoring maintenance
monitoring_maintenance() {
    print_header "Monitoring Maintenance"
    cd "$BACKEND_DIR"
    
    # Check monitoring system status
    print_status "Checking monitoring system status..."
    python manage.py manage_monitoring status || print_warning "Monitoring status check failed"
    
    # Perform health check
    print_status "Running system health check..."
    python manage.py manage_monitoring health-check || print_warning "Health check failed"
    
    # Check background tasks
    print_status "Checking background task status..."
    python manage.py manage_background_tasks --action status || print_warning "Background task check failed"
    
    print_status "Monitoring maintenance completed"
}

# Function to generate maintenance reports
generate_reports() {
    if [ "$GENERATE_REPORTS" = "false" ]; then
        print_warning "Skipping report generation"
        return
    fi
    
    print_header "Generating Maintenance Reports"
    cd "$BACKEND_DIR"
    
    local report_dir="$PROJECT_ROOT/reports"
    local report_date=$(date +%Y%m%d_%H%M%S)
    mkdir -p "$report_dir"
    
    # Generate performance report
    print_status "Generating performance report..."
    python manage.py manage_monitoring export-metrics --hours 24 --output-file "$report_dir/performance_report_$report_date.json" || print_warning "Performance report generation failed"
    
    # Generate deal performance report
    print_status "Generating deal performance report..."
    python manage.py analyze_deal_performance --action report --output-file "$report_dir/deal_performance_$report_date.txt" || print_warning "Deal performance report generation failed"
    
    # Generate commission analytics report
    print_status "Generating commission analytics report..."
    python manage.py optimize_commissions --action analytics > "$report_dir/commission_analytics_$report_date.txt" 2>/dev/null || print_warning "Commission analytics report generation failed"
    
    print_status "Reports generated in $report_dir"
}

# Function to perform system health check
system_health_check() {
    print_header "System Health Check"
    cd "$BACKEND_DIR"
    
    local health_issues=0
    
    # Check Django system
    print_status "Checking Django system..."
    if ! python manage.py check >/dev/null 2>&1; then
        print_warning "Django system check found issues"
        ((health_issues++))
    fi
    
    # Check database connectivity
    print_status "Checking database connectivity..."
    if ! python manage.py check --database default >/dev/null 2>&1; then
        print_warning "Database connectivity issues detected"
        ((health_issues++))
    fi
    
    # Check cache connectivity
    print_status "Checking cache connectivity..."
    if ! python manage.py shell -c "
from django.core.cache import cache
cache.set('health_check', 'ok', 10)
result = cache.get('health_check')
exit(0 if result == 'ok' else 1)
" >/dev/null 2>&1; then
        print_warning "Cache connectivity issues detected"
        ((health_issues++))
    fi
    
    # Check Celery services
    print_status "Checking Celery services..."
    if [ -f "$LOG_DIR/celery/worker.pid" ]; then
        local worker_pid=$(cat "$LOG_DIR/celery/worker.pid")
        if ! kill -0 "$worker_pid" 2>/dev/null; then
            print_warning "Celery worker is not running"
            ((health_issues++))
        fi
    else
        print_warning "Celery worker PID file not found"
        ((health_issues++))
    fi
    
    # Check disk space
    print_status "Checking disk space..."
    local disk_usage=$(df "$PROJECT_ROOT" | awk 'NR==2 {print $5}' | sed 's/%//')
    if [ "$disk_usage" -gt 90 ]; then
        print_warning "Disk usage is high: ${disk_usage}%"
        ((health_issues++))
    fi
    
    # Summary
    if [ $health_issues -eq 0 ]; then
        print_status "System health check: PASSED"
    else
        print_warning "System health check: $health_issues issues found"
    fi
    
    return $health_issues
}

# Function to display maintenance summary
display_summary() {
    print_header "Maintenance Summary"
    
    echo -e "${GREEN}✅ PRS Backend Maintenance Completed${NC}"
    echo ""
    echo "Maintenance Type: $MAINTENANCE_TYPE"
    echo "Completed Tasks:"
    echo "  • File cleanup (logs, backups, temp files)"
    echo "  • Database maintenance and optimization"
    echo "  • Cache warming and cleanup"
    echo "  • Security checks and updates"
    echo "  • Monitoring system maintenance"
    echo "  • System health verification"
    if [ "$GENERATE_REPORTS" = "true" ]; then
        echo "  • Performance and analytics reports"
    fi
    echo ""
    echo "Next maintenance recommended: $(date -d '+1 day' '+%Y-%m-%d %H:%M')"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --type TYPE              Maintenance type (daily|weekly|monthly) [default: daily]"
    echo "  --backup-retention DAYS  Backup retention in days [default: 30]"
    echo "  --log-retention DAYS     Log retention in days [default: 7]"
    echo "  --skip-cleanup           Skip file cleanup"
    echo "  --skip-database          Skip database maintenance"
    echo "  --skip-reports           Skip report generation"
    echo "  --help                   Show this help message"
    echo ""
    echo "Maintenance Types:"
    echo "  daily    - Basic cleanup and health checks"
    echo "  weekly   - Includes database optimization"
    echo "  monthly  - Full maintenance with reports"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --type)
            MAINTENANCE_TYPE="$2"
            shift 2
            ;;
        --backup-retention)
            BACKUP_RETENTION_DAYS="$2"
            shift 2
            ;;
        --log-retention)
            LOG_RETENTION_DAYS="$2"
            shift 2
            ;;
        --skip-cleanup)
            CLEANUP_TEMP_FILES=false
            shift
            ;;
        --skip-database)
            OPTIMIZE_DATABASE=false
            shift
            ;;
        --skip-reports)
            GENERATE_REPORTS=false
            shift
            ;;
        --help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Adjust maintenance tasks based on type
case $MAINTENANCE_TYPE in
    daily)
        GENERATE_REPORTS=false
        ;;
    weekly)
        GENERATE_REPORTS=false
        ;;
    monthly)
        GENERATE_REPORTS=true
        ;;
    *)
        print_error "Invalid maintenance type: $MAINTENANCE_TYPE"
        exit 1
        ;;
esac

# Main execution
main() {
    echo -e "${BLUE}🔧 PRS Backend Maintenance ($MAINTENANCE_TYPE)${NC}"
    echo -e "${BLUE}================================${NC}"
    echo ""
    
    activate_venv
    cleanup_old_files
    database_maintenance
    cache_maintenance
    security_maintenance
    monitoring_maintenance
    generate_reports
    system_health_check
    display_summary
    
    echo ""
    echo -e "${GREEN}🎉 Maintenance completed successfully!${NC}"
}

# Run main function
main "$@"