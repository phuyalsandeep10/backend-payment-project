#!/bin/bash
# PRS Backend Stop Script
# Properly stops all backend services and background processes
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
LOG_DIR="$PROJECT_ROOT/logs"

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

# Function to stop Celery services
stop_celery() {
    print_header "Stopping Celery Services"
    
    # Stop Celery worker
    if [ -f "$LOG_DIR/celery/worker.pid" ]; then
        local worker_pid=$(cat "$LOG_DIR/celery/worker.pid")
        if kill -0 "$worker_pid" 2>/dev/null; then
            print_status "Stopping Celery worker (PID: $worker_pid)..."
            kill -TERM "$worker_pid"
            sleep 2
            if kill -0 "$worker_pid" 2>/dev/null; then
                print_warning "Celery worker didn't stop gracefully, forcing..."
                kill -KILL "$worker_pid"
            fi
        fi
        rm -f "$LOG_DIR/celery/worker.pid"
    fi
    
    # Stop Celery beat
    if [ -f "$LOG_DIR/celery/beat.pid" ]; then
        local beat_pid=$(cat "$LOG_DIR/celery/beat.pid")
        if kill -0 "$beat_pid" 2>/dev/null; then
            print_status "Stopping Celery beat scheduler (PID: $beat_pid)..."
            kill -TERM "$beat_pid"
            sleep 2
            if kill -0 "$beat_pid" 2>/dev/null; then
                print_warning "Celery beat didn't stop gracefully, forcing..."
                kill -KILL "$beat_pid"
            fi
        fi
        rm -f "$LOG_DIR/celery/beat.pid"
    fi
    
    # Kill any remaining Celery processes
    pkill -f "celery.*core_config" 2>/dev/null || true
    
    print_status "Celery services stopped"
}

# Function to stop Django development server
stop_django() {
    print_header "Stopping Django Development Server"
    
    # Kill Django runserver processes
    pkill -f "python.*manage.py.*runserver" 2>/dev/null || true
    
    print_status "Django development server stopped"
}

# Function to cleanup temporary files
cleanup_temp_files() {
    print_header "Cleaning Up Temporary Files"
    
    # Clean up temporary upload files
    if [ -d "$BACKEND_DIR/media/temp" ]; then
        find "$BACKEND_DIR/media/temp" -type f -mtime +1 -delete 2>/dev/null || true
        print_status "Cleaned temporary upload files"
    fi
    
    # Clean up old log files (older than 7 days)
    if [ -d "$LOG_DIR" ]; then
        find "$LOG_DIR" -name "*.log" -mtime +7 -delete 2>/dev/null || true
        print_status "Cleaned old log files"
    fi
    
    # Clean up Python cache files
    find "$BACKEND_DIR" -name "*.pyc" -delete 2>/dev/null || true
    find "$BACKEND_DIR" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
    
    print_status "Temporary files cleaned up"
}

# Function to run maintenance tasks
run_maintenance() {
    print_header "Running Maintenance Tasks"
    cd "$BACKEND_DIR"
    
    # Activate virtual environment if available
    if [ -f "$PROJECT_ROOT/venv/bin/activate" ]; then
        source "$PROJECT_ROOT/venv/bin/activate"
    fi
    
    # Clear expired sessions
    python manage.py clearsessions 2>/dev/null || print_warning "Failed to clear expired sessions"
    
    # Clean up duplicate commissions
    python manage.py cleanup_duplicate_commissions --dry-run 2>/dev/null || print_warning "Failed to check duplicate commissions"
    
    # Clear old monitoring metrics
    python manage.py manage_monitoring cleanup 2>/dev/null || print_warning "Failed to cleanup monitoring metrics"
    
    print_status "Maintenance tasks completed"
}

# Function to display stop summary
display_summary() {
    print_header "Stop Summary"
    
    echo -e "${GREEN}✅ PRS Backend Services Stopped${NC}"
    echo ""
    echo "Services stopped:"
    echo "  • Celery worker and beat scheduler"
    echo "  • Django development server"
    echo ""
    echo "Maintenance completed:"
    echo "  • Temporary files cleaned"
    echo "  • Old log files removed"
    echo "  • Python cache cleared"
    echo "  • Expired sessions cleared"
    echo ""
    echo "To restart the backend:"
    echo "  $SCRIPT_DIR/start_backend.sh"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --skip-maintenance    Skip maintenance tasks"
    echo "  --skip-cleanup        Skip temporary file cleanup"
    echo "  --help               Show this help message"
}

# Default values
SKIP_MAINTENANCE=false
SKIP_CLEANUP=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-maintenance)
            SKIP_MAINTENANCE=true
            shift
            ;;
        --skip-cleanup)
            SKIP_CLEANUP=true
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
    echo -e "${BLUE}🛑 PRS Backend Stop Script${NC}"
    echo -e "${BLUE}===========================${NC}"
    echo ""
    
    stop_celery
    stop_django
    
    if [ "$SKIP_CLEANUP" = "false" ]; then
        cleanup_temp_files
    fi
    
    if [ "$SKIP_MAINTENANCE" = "false" ]; then
        run_maintenance
    fi
    
    display_summary
    
    echo ""
    echo -e "${GREEN}🎉 Backend shutdown completed successfully!${NC}"
}

# Run main function
main "$@"