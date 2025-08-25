#!/bin/bash
# PRS Backend Startup Script
# Comprehensive startup script for the Payment Receiving System backend
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
ENVIRONMENT=${ENVIRONMENT:-development}
SKIP_MIGRATIONS=${SKIP_MIGRATIONS:-false}
SKIP_COLLECTSTATIC=${SKIP_COLLECTSTATIC:-false}
SKIP_OPTIMIZATION=${SKIP_OPTIMIZATION:-false}
SKIP_MONITORING=${SKIP_MONITORING:-false}
RUN_TESTS=${RUN_TESTS:-false}
VERBOSE=${VERBOSE:-false}

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
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to activate virtual environment
activate_venv() {
    if [ -f "$VENV_DIR/bin/activate" ]; then
        print_status "Activating virtual environment..."
        source "$VENV_DIR/bin/activate"
    else
        print_error "Virtual environment not found at $VENV_DIR"
        print_status "Creating virtual environment..."
        python3 -m venv "$VENV_DIR"
        source "$VENV_DIR/bin/activate"
        pip install --upgrade pip
        pip install -r "$PROJECT_ROOT/requirements.txt"
    fi
}

# Function to check system dependencies
check_dependencies() {
    print_header "Checking System Dependencies"
    
    local missing_deps=()
    
    if ! command_exists python3; then
        missing_deps+=("python3")
    fi
    
    if ! command_exists redis-server; then
        print_warning "Redis server not found. Some caching features may not work optimally."
    fi
    
    if ! command_exists postgresql; then
        print_warning "PostgreSQL not found. Make sure database is accessible."
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_error "Missing dependencies: ${missing_deps[*]}"
        exit 1
    fi
    
    print_status "All required dependencies are available"
}

# Function to setup directories
setup_directories() {
    print_header "Setting Up Directories"
    
    # Create logs directory
    mkdir -p "$LOG_DIR"
    mkdir -p "$LOG_DIR/django"
    mkdir -p "$LOG_DIR/celery"
    mkdir -p "$LOG_DIR/monitoring"
    mkdir -p "$LOG_DIR/security"
    
    # Create media directories
    mkdir -p "$BACKEND_DIR/media"
    mkdir -p "$BACKEND_DIR/media/uploads"
    mkdir -p "$BACKEND_DIR/media/temp"
    
    # Create static directories
    mkdir -p "$BACKEND_DIR/staticfiles"
    
    print_status "Directories created successfully"
}

# Function to run database migrations
run_migrations() {
    if [ "$SKIP_MIGRATIONS" = "true" ]; then
        print_warning "Skipping database migrations"
        return
    fi
    
    print_header "Running Database Migrations"
    cd "$BACKEND_DIR"
    
    # Check database connection
    python manage.py check --database default
    
    # Show migration status
    if [ "$VERBOSE" = "true" ]; then
        python manage.py showmigrations
    fi
    
    # Run migrations
    python manage.py migrate --noinput
    
    print_status "Database migrations completed"
}

# Function to collect static files
collect_static() {
    if [ "$SKIP_COLLECTSTATIC" = "true" ]; then
        print_warning "Skipping static file collection"
        return
    fi
    
    print_header "Collecting Static Files"
    cd "$BACKEND_DIR"
    python manage.py collectstatic --noinput --clear
    print_status "Static files collected"
}

# Function to create superuser if needed
create_superuser() {
    print_header "Checking Superuser"
    cd "$BACKEND_DIR"
    
    # Check if superuser exists
    if python manage.py shell -c "from django.contrib.auth import get_user_model; User = get_user_model(); print('exists' if User.objects.filter(is_superuser=True).exists() else 'none')" | grep -q "exists"; then
        print_status "Superuser already exists"
    else
        print_warning "No superuser found"
        if [ "$ENVIRONMENT" = "development" ]; then
            print_status "Creating development superuser..."
            python manage.py shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(email='admin@prs.local').exists():
    User.objects.create_superuser('admin@prs.local', 'admin123')
    print('Development superuser created: admin@prs.local / admin123')
"
        else
            print_warning "Please create a superuser manually: python manage.py createsuperuser"
        fi
    fi
}

# Function to run system optimizations
run_optimizations() {
    if [ "$SKIP_OPTIMIZATION" = "true" ]; then
        print_warning "Skipping system optimizations"
        return
    fi
    
    print_header "Running System Optimizations"
    cd "$BACKEND_DIR"
    
    # Database optimizations
    print_status "Running database optimizations..."
    python manage.py optimize_database --action recommend || print_warning "Database optimization failed"
    
    # Commission optimizations
    print_status "Running commission optimizations..."
    python manage.py optimize_commissions --action cache-warmup || print_warning "Commission cache warmup failed"
    
    # Financial field optimizations
    print_status "Validating financial fields..."
    python manage.py optimize_financial_fields --action validate || print_warning "Financial field validation failed"
    
    # Role cache management
    print_status "Warming up role cache..."
    python manage.py manage_role_cache --action warm || print_warning "Role cache warmup failed"
    
    print_status "System optimizations completed"
}

# Function to setup monitoring
setup_monitoring() {
    if [ "$SKIP_MONITORING" = "true" ]; then
        print_warning "Skipping monitoring setup"
        return
    fi
    
    print_header "Setting Up Monitoring System"
    cd "$BACKEND_DIR"
    
    # Check monitoring system status
    print_status "Checking monitoring system..."
    python manage.py manage_monitoring status || print_warning "Monitoring system check failed"
    
    # Perform health check
    print_status "Running system health check..."
    python manage.py manage_monitoring health-check || print_warning "Health check failed"
    
    # Setup background tasks monitoring
    print_status "Setting up background task monitoring..."
    python manage.py manage_background_tasks --action status || print_warning "Background task monitoring failed"
    
    print_status "Monitoring system setup completed"
}

# Function to run security checks
run_security_checks() {
    print_header "Running Security Checks"
    cd "$BACKEND_DIR"
    
    # Django security check
    python manage.py check --deploy || print_warning "Security checks found issues"
    
    # Check password expiration
    print_status "Checking password expiration policies..."
    python manage.py check_password_expiration || print_warning "Password expiration check failed"
    
    print_status "Security checks completed"
}

# Function to start services
start_services() {
    print_header "Starting Services"
    cd "$BACKEND_DIR"
    
    # Check if Redis is running
    if command_exists redis-cli; then
        if redis-cli ping >/dev/null 2>&1; then
            print_status "Redis is running"
        else
            print_warning "Redis is not running. Starting Redis..."
            if command_exists brew; then
                brew services start redis
            elif command_exists systemctl; then
                sudo systemctl start redis
            else
                print_warning "Please start Redis manually"
            fi
        fi
    fi
    
    # Start Celery worker in background (development only)
    if [ "$ENVIRONMENT" = "development" ]; then
        print_status "Starting Celery worker for development..."
        celery -A core_config worker --loglevel=info --detach --pidfile="$LOG_DIR/celery/worker.pid" --logfile="$LOG_DIR/celery/worker.log" || print_warning "Failed to start Celery worker"
        
        print_status "Starting Celery beat scheduler..."
        celery -A core_config beat --loglevel=info --detach --pidfile="$LOG_DIR/celery/beat.pid" --logfile="$LOG_DIR/celery/beat.log" || print_warning "Failed to start Celery beat"
    fi
}

# Function to display startup summary
display_summary() {
    print_header "Startup Summary"
    cd "$BACKEND_DIR"
    
    echo -e "${GREEN}✅ PRS Backend System Ready${NC}"
    echo ""
    echo "Environment: $ENVIRONMENT"
    echo "Backend Directory: $BACKEND_DIR"
    echo "Logs Directory: $LOG_DIR"
    echo ""
    echo "Available Management Commands:"
    echo "  • python manage.py manage_monitoring status"
    echo "  • python manage.py manage_background_tasks --action status"
    echo "  • python manage.py optimize_database --action analyze"
    echo "  • python manage.py optimize_commissions --action analytics"
    echo "  • python manage.py workflow_maintenance --action status"
    echo ""
    echo "API Endpoints:"
    echo "  • Health Check: http://localhost:8000/api/health/"
    echo "  • Monitoring: http://localhost:8000/api/monitoring/system/health/"
    echo "  • API Documentation: http://localhost:8000/swagger/"
    echo ""
    echo "To start the development server:"
    echo "  cd $BACKEND_DIR && python manage.py runserver"
    echo ""
    echo "To stop background services:"
    echo "  $SCRIPT_DIR/stop_backend.sh"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --environment ENV     Set environment (development|staging|production) [default: development]"
    echo "  --skip-migrations     Skip database migrations"
    echo "  --skip-collectstatic  Skip static file collection"
    echo "  --skip-optimization   Skip system optimizations"
    echo "  --skip-monitoring     Skip monitoring setup"
    echo "  --run-tests          Run tests during startup"
    echo "  --verbose            Enable verbose output"
    echo "  --help               Show this help message"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --skip-migrations)
            SKIP_MIGRATIONS=true
            shift
            ;;
        --skip-collectstatic)
            SKIP_COLLECTSTATIC=true
            shift
            ;;
        --skip-optimization)
            SKIP_OPTIMIZATION=true
            shift
            ;;
        --skip-monitoring)
            SKIP_MONITORING=true
            shift
            ;;
        --run-tests)
            RUN_TESTS=true
            shift
            ;;
        --verbose)
            VERBOSE=true
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

# Main execution
main() {
    echo -e "${BLUE}🚀 PRS Backend Startup Script${NC}"
    echo -e "${BLUE}================================${NC}"
    echo ""
    
    check_dependencies
    activate_venv
    setup_directories
    run_migrations
    collect_static
    create_superuser
    run_security_checks
    run_optimizations
    setup_monitoring
    start_services
    display_summary
    
    echo ""
    echo -e "${GREEN}🎉 Backend startup completed successfully!${NC}"
}

# Run main function
main "$@"