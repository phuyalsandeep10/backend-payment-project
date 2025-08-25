#!/bin/bash
# PRS Backend Development Quick Start Script
# Optimized for development environment with hot reloading and debugging
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

# Default values
PORT=${PORT:-8000}
DEBUG=${DEBUG:-true}
SKIP_CHECKS=${SKIP_CHECKS:-false}
WATCH_FILES=${WATCH_FILES:-true}

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
    echo -e "${BLUE}[DEV]${NC} $1"
}

# Function to activate virtual environment
activate_venv() {
    if [ -f "$VENV_DIR/bin/activate" ]; then
        source "$VENV_DIR/bin/activate"
    else
        print_error "Virtual environment not found. Run start_backend.sh first."
        exit 1
    fi
}

# Function to quick setup for development
quick_setup() {
    print_header "Quick Development Setup"
    cd "$BACKEND_DIR"
    
    # Quick database check and migrate if needed
    if ! python manage.py check --database default >/dev/null 2>&1; then
        print_status "Running quick migrations..."
        python manage.py migrate --run-syncdb
    fi
    
    # Create development superuser if needed
    python manage.py shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(email='dev@prs.local').exists():
    User.objects.create_superuser('dev@prs.local', 'dev123')
    print('Development user created: dev@prs.local / dev123')
" 2>/dev/null || true
    
    print_status "Development setup completed"
}

# Function to start development services
start_dev_services() {
    print_header "Starting Development Services"
    
    # Start Redis if not running
    if command -v redis-cli >/dev/null 2>&1; then
        if ! redis-cli ping >/dev/null 2>&1; then
            print_status "Starting Redis for development..."
            if command -v brew >/dev/null 2>&1; then
                brew services start redis
            else
                print_warning "Please start Redis manually: redis-server"
            fi
        fi
    fi
    
    # Start Celery worker for development
    print_status "Starting Celery worker for development..."
    celery -A core_config worker --loglevel=info --concurrency=2 &
    CELERY_PID=$!
    
    # Start Celery beat for development
    print_status "Starting Celery beat for development..."
    celery -A core_config beat --loglevel=info &
    BEAT_PID=$!
    
    # Store PIDs for cleanup
    echo $CELERY_PID > /tmp/prs_celery_dev.pid
    echo $BEAT_PID > /tmp/prs_beat_dev.pid
}

# Function to start Django development server
start_django_dev() {
    print_header "Starting Django Development Server"
    cd "$BACKEND_DIR"
    
    local runserver_args="--verbosity=2"
    
    if [ "$WATCH_FILES" = "true" ]; then
        runserver_args="$runserver_args --noreload=false"
    fi
    
    if [ "$SKIP_CHECKS" = "false" ]; then
        print_status "Running system checks..."
        python manage.py check
    fi
    
    print_status "Starting development server on port $PORT..."
    print_status "Debug mode: $DEBUG"
    print_status "API Documentation: http://localhost:$PORT/swagger/"
    print_status "Admin Panel: http://localhost:$PORT/admin/"
    print_status "Health Check: http://localhost:$PORT/api/health/"
    print_status "Monitoring: http://localhost:$PORT/api/monitoring/system/health/"
    echo ""
    print_status "Press Ctrl+C to stop the server"
    echo ""
    
    # Set development environment variables
    export DJANGO_DEBUG=$DEBUG
    export DJANGO_DEVELOPMENT=true
    
    # Start the development server
    python manage.py runserver "0.0.0.0:$PORT" $runserver_args
}

# Function to cleanup on exit
cleanup() {
    print_header "Cleaning Up Development Services"
    
    # Kill Celery processes
    if [ -f /tmp/prs_celery_dev.pid ]; then
        local celery_pid=$(cat /tmp/prs_celery_dev.pid)
        kill $celery_pid 2>/dev/null || true
        rm -f /tmp/prs_celery_dev.pid
    fi
    
    if [ -f /tmp/prs_beat_dev.pid ]; then
        local beat_pid=$(cat /tmp/prs_beat_dev.pid)
        kill $beat_pid 2>/dev/null || true
        rm -f /tmp/prs_beat_dev.pid
    fi
    
    # Kill any remaining Celery processes
    pkill -f "celery.*core_config" 2>/dev/null || true
    
    print_status "Development services stopped"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --port PORT          Set server port [default: 8000]"
    echo "  --no-debug           Disable debug mode"
    echo "  --skip-checks        Skip Django system checks"
    echo "  --no-watch           Disable file watching"
    echo "  --help               Show this help message"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --port)
            PORT="$2"
            shift 2
            ;;
        --no-debug)
            DEBUG=false
            shift
            ;;
        --skip-checks)
            SKIP_CHECKS=true
            shift
            ;;
        --no-watch)
            WATCH_FILES=false
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

# Set up signal handlers for cleanup
trap cleanup EXIT INT TERM

# Main execution
main() {
    echo -e "${BLUE}🚀 PRS Backend Development Server${NC}"
    echo -e "${BLUE}==================================${NC}"
    echo ""
    
    activate_venv
    quick_setup
    start_dev_services
    start_django_dev
}

# Run main function
main "$@"