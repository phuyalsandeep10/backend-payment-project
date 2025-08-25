#!/bin/bash
# PRS Backend Script Manager
# Central management script for all backend operations
set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

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
    echo -e "${BLUE}[MANAGE]${NC} $1"
}

print_command() {
    echo -e "${CYAN}$1${NC}"
}

# Function to show main menu
show_main_menu() {
    echo -e "${BLUE}🚀 PRS Backend Management System${NC}"
    echo -e "${BLUE}=================================${NC}"
    echo ""
    echo "Available Commands:"
    echo ""
    echo -e "${CYAN}Development:${NC}"
    echo "  dev          - Start development server with hot reload"
    echo "  start        - Full backend startup with all services"
    echo "  stop         - Stop all backend services"
    echo "  restart      - Restart all backend services"
    echo ""
    echo -e "${CYAN}Database:${NC}"
    echo "  migrate      - Run database migrations"
    echo "  reset-db     - Reset database (WARNING: destructive)"
    echo "  backup-db    - Create database backup"
    echo "  optimize-db  - Optimize database performance"
    echo ""
    echo -e "${CYAN}Maintenance:${NC}"
    echo "  maintenance  - Run system maintenance tasks"
    echo "  cleanup      - Clean temporary files and logs"
    echo "  health       - Check system health"
    echo "  logs         - View system logs"
    echo ""
    echo -e "${CYAN}Testing:${NC}"
    echo "  test         - Run test suite"
    echo "  test-fast    - Run fast tests only"
    echo "  coverage     - Run tests with coverage report"
    echo ""
    echo -e "${CYAN}Production:${NC}"
    echo "  deploy       - Deploy to production"
    echo "  status       - Check production status"
    echo "  monitor      - View monitoring dashboard"
    echo ""
    echo -e "${CYAN}Utilities:${NC}"
    echo "  shell        - Open Django shell"
    echo "  superuser    - Create superuser"
    echo "  collectstatic - Collect static files"
    echo ""
    echo "Usage: $0 <command> [options]"
    echo "       $0 --help for detailed help"
}

# Function to start development server
start_dev() {
    print_header "Starting Development Server"
    "$SCRIPT_DIR/dev_start.sh" "$@"
}

# Function to start full backend
start_backend() {
    print_header "Starting Full Backend"
    "$SCRIPT_DIR/start_backend.sh" "$@"
}

# Function to stop backend
stop_backend() {
    print_header "Stopping Backend Services"
    "$SCRIPT_DIR/stop_backend.sh" "$@"
}

# Function to restart backend
restart_backend() {
    print_header "Restarting Backend Services"
    "$SCRIPT_DIR/stop_backend.sh" --skip-maintenance
    sleep 2
    "$SCRIPT_DIR/start_backend.sh" "$@"
}

# Function to run migrations
run_migrations() {
    print_header "Running Database Migrations"
    cd "$PROJECT_ROOT/backend"
    
    # Activate virtual environment
    if [ -f "$PROJECT_ROOT/venv/bin/activate" ]; then
        source "$PROJECT_ROOT/venv/bin/activate"
    fi
    
    python manage.py migrate "$@"
    print_status "Migrations completed"
}

# Function to reset database
reset_database() {
    print_header "Resetting Database"
    
    echo -e "${RED}WARNING: This will delete all data in the database!${NC}"
    read -p "Are you sure you want to continue? (yes/no): " confirm
    
    if [ "$confirm" != "yes" ]; then
        print_status "Database reset cancelled"
        return
    fi
    
    cd "$PROJECT_ROOT/backend"
    
    # Activate virtual environment
    if [ -f "$PROJECT_ROOT/venv/bin/activate" ]; then
        source "$PROJECT_ROOT/venv/bin/activate"
    fi
    
    # Drop and recreate database
    python manage.py flush --noinput
    python manage.py migrate
    
    print_status "Database reset completed"
}

# Function to backup database
backup_database() {
    print_header "Creating Database Backup"
    cd "$PROJECT_ROOT/backend"
    
    # Activate virtual environment
    if [ -f "$PROJECT_ROOT/venv/bin/activate" ]; then
        source "$PROJECT_ROOT/venv/bin/activate"
    fi
    
    local backup_dir="$PROJECT_ROOT/backups"
    mkdir -p "$backup_dir"
    
    local backup_file="$backup_dir/db_backup_$(date +%Y%m%d_%H%M%S).json"
    
    python manage.py dumpdata --natural-foreign --natural-primary > "$backup_file"
    
    print_status "Database backup created: $backup_file"
}

# Function to optimize database
optimize_database() {
    print_header "Optimizing Database"
    cd "$PROJECT_ROOT/backend"
    
    # Activate virtual environment
    if [ -f "$PROJECT_ROOT/venv/bin/activate" ]; then
        source "$PROJECT_ROOT/venv/bin/activate"
    fi
    
    python manage.py optimize_database --action analyze "$@"
    print_status "Database optimization completed"
}

# Function to run maintenance
run_maintenance() {
    print_header "Running System Maintenance"
    "$SCRIPT_DIR/maintenance.sh" "$@"
}

# Function to cleanup system
cleanup_system() {
    print_header "Cleaning Up System"
    cd "$PROJECT_ROOT/backend"
    
    # Clean Python cache
    find . -name "*.pyc" -delete
    find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
    
    # Clean temporary files
    if [ -d "media/temp" ]; then
        rm -rf media/temp/*
    fi
    
    # Clean old logs
    if [ -d "$PROJECT_ROOT/logs" ]; then
        find "$PROJECT_ROOT/logs" -name "*.log" -mtime +7 -delete 2>/dev/null || true
    fi
    
    print_status "System cleanup completed"
}

# Function to check system health
check_health() {
    print_header "Checking System Health"
    cd "$PROJECT_ROOT/backend"
    
    # Activate virtual environment
    if [ -f "$PROJECT_ROOT/venv/bin/activate" ]; then
        source "$PROJECT_ROOT/venv/bin/activate"
    fi
    
    # Django system check
    print_status "Running Django system checks..."
    python manage.py check
    
    # Database connectivity
    print_status "Checking database connectivity..."
    python manage.py check --database default
    
    # Monitoring health check
    print_status "Running monitoring health check..."
    python manage.py manage_monitoring health-check || print_warning "Monitoring health check failed"
    
    print_status "System health check completed"
}

# Function to view logs
view_logs() {
    print_header "Viewing System Logs"
    
    local log_type=${1:-django}
    local log_dir="$PROJECT_ROOT/logs"
    
    case $log_type in
        django)
            if [ -f "$log_dir/django/django.log" ]; then
                tail -f "$log_dir/django/django.log"
            else
                print_warning "Django log file not found"
            fi
            ;;
        celery)
            if [ -f "$log_dir/celery/worker.log" ]; then
                tail -f "$log_dir/celery/worker.log"
            else
                print_warning "Celery log file not found"
            fi
            ;;
        monitoring)
            if [ -f "$log_dir/monitoring/monitoring.log" ]; then
                tail -f "$log_dir/monitoring/monitoring.log"
            else
                print_warning "Monitoring log file not found"
            fi
            ;;
        *)
            echo "Available log types: django, celery, monitoring"
            ;;
    esac
}

# Function to run tests
run_tests() {
    print_header "Running Test Suite"
    cd "$PROJECT_ROOT/backend"
    
    # Activate virtual environment
    if [ -f "$PROJECT_ROOT/venv/bin/activate" ]; then
        source "$PROJECT_ROOT/venv/bin/activate"
    fi
    
    python manage.py test "$@"
    print_status "Tests completed"
}

# Function to run fast tests
run_fast_tests() {
    print_header "Running Fast Tests"
    cd "$PROJECT_ROOT/backend"
    
    # Activate virtual environment
    if [ -f "$PROJECT_ROOT/venv/bin/activate" ]; then
        source "$PROJECT_ROOT/venv/bin/activate"
    fi
    
    python manage.py test --parallel --keepdb "$@"
    print_status "Fast tests completed"
}

# Function to run coverage
run_coverage() {
    print_header "Running Coverage Report"
    cd "$PROJECT_ROOT/backend"
    
    # Activate virtual environment
    if [ -f "$PROJECT_ROOT/venv/bin/activate" ]; then
        source "$PROJECT_ROOT/venv/bin/activate"
    fi
    
    if command -v coverage >/dev/null 2>&1; then
        coverage run --source='.' manage.py test "$@"
        coverage report
        coverage html
        print_status "Coverage report generated in htmlcov/"
    else
        print_warning "Coverage not installed. Install with: pip install coverage"
    fi
}

# Function to open Django shell
open_shell() {
    print_header "Opening Django Shell"
    cd "$PROJECT_ROOT/backend"
    
    # Activate virtual environment
    if [ -f "$PROJECT_ROOT/venv/bin/activate" ]; then
        source "$PROJECT_ROOT/venv/bin/activate"
    fi
    
    python manage.py shell_plus 2>/dev/null || python manage.py shell
}

# Function to create superuser
create_superuser() {
    print_header "Creating Superuser"
    cd "$PROJECT_ROOT/backend"
    
    # Activate virtual environment
    if [ -f "$PROJECT_ROOT/venv/bin/activate" ]; then
        source "$PROJECT_ROOT/venv/bin/activate"
    fi
    
    python manage.py createsuperuser "$@"
}

# Function to collect static files
collect_static() {
    print_header "Collecting Static Files"
    cd "$PROJECT_ROOT/backend"
    
    # Activate virtual environment
    if [ -f "$PROJECT_ROOT/venv/bin/activate" ]; then
        source "$PROJECT_ROOT/venv/bin/activate"
    fi
    
    python manage.py collectstatic "$@"
    print_status "Static files collected"
}

# Function to show help
show_help() {
    show_main_menu
    echo ""
    echo "Command Details:"
    echo ""
    echo "dev [--port PORT] [--no-debug] [--skip-checks]"
    echo "  Start development server with hot reload"
    echo ""
    echo "start [--environment ENV] [--skip-migrations] [--skip-optimization]"
    echo "  Full backend startup with all services"
    echo ""
    echo "stop [--skip-maintenance] [--skip-cleanup]"
    echo "  Stop all backend services"
    echo ""
    echo "maintenance [--type TYPE] [--skip-cleanup] [--skip-database]"
    echo "  Run system maintenance (daily|weekly|monthly)"
    echo ""
    echo "logs [django|celery|monitoring]"
    echo "  View system logs (default: django)"
    echo ""
    echo "test [test_args...]"
    echo "  Run Django test suite with optional arguments"
}

# Main command dispatcher
case "${1:-help}" in
    dev)
        shift
        start_dev "$@"
        ;;
    start)
        shift
        start_backend "$@"
        ;;
    stop)
        shift
        stop_backend "$@"
        ;;
    restart)
        shift
        restart_backend "$@"
        ;;
    migrate)
        shift
        run_migrations "$@"
        ;;
    reset-db)
        reset_database
        ;;
    backup-db)
        backup_database
        ;;
    optimize-db)
        shift
        optimize_database "$@"
        ;;
    maintenance)
        shift
        run_maintenance "$@"
        ;;
    cleanup)
        cleanup_system
        ;;
    health)
        check_health
        ;;
    logs)
        shift
        view_logs "$@"
        ;;
    test)
        shift
        run_tests "$@"
        ;;
    test-fast)
        shift
        run_fast_tests "$@"
        ;;
    coverage)
        shift
        run_coverage "$@"
        ;;
    shell)
        open_shell
        ;;
    superuser)
        shift
        create_superuser "$@"
        ;;
    collectstatic)
        shift
        collect_static "$@"
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        print_error "Unknown command: $1"
        echo ""
        show_main_menu
        exit 1
        ;;
esac