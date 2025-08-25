#!/usr/bin/env python
"""
PRS Backend Development Startup Script
=====================================

This script provides a comprehensive development environment setup for the PRS backend,
with debugging features, hot-reload, and development-specific optimizations.

Features:
- Development database setup with demo data
- Debug mode configuration
- Hot-reload development server
- Celery development setup
- Performance monitoring in debug mode
- Development tools and utilities

Usage:
    python start_development.py [--with-demo-data] [--reset-db] [--debug-level=INFO]
"""

import os
import sys
import subprocess
import time
import signal
import threading
from pathlib import Path
from datetime import datetime
import argparse

class DevelopmentStarter:
    """Development-specific startup manager for PRS Backend"""
    
    def __init__(self, with_demo_data=False, reset_db=False, debug_level='INFO'):
        self.with_demo_data = with_demo_data
        self.reset_db = reset_db
        self.debug_level = debug_level
        self.start_time = datetime.now()
        self.processes = []
        self.running = True
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        self.log("Shutdown signal received", 'WARNING')
        self.running = False
        self.cleanup_processes()
        sys.exit(0)
    
    def log(self, message, level='INFO'):
        """Development logging with enhanced debugging"""
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        
        colors = {
            'SUCCESS': '\033[92m',
            'WARNING': '\033[93m',
            'ERROR': '\033[91m',
            'INFO': '\033[94m',
            'DEBUG': '\033[96m',
            'ENDC': '\033[0m',
            'BOLD': '\033[1m'
        }
        
        icons = {
            'SUCCESS': '✅',
            'WARNING': '⚠️ ',
            'ERROR': '❌',
            'INFO': '🔄',
            'DEBUG': '🐛'
        }
        
        color = colors.get(level, colors['ENDC'])
        icon = icons.get(level, 'ℹ️ ')
        
        print(f"{color}[{timestamp}] {icon} {message}{colors['ENDC']}")
    
    def run_command(self, command, description, background=False, critical=True):
        """Execute command with development-friendly error handling"""
        self.log(f"Executing: {description}", 'INFO')
        
        try:
            if background:
                # Start process in background
                process = subprocess.Popen(
                    command,
                    shell=True,
                    cwd=Path(__file__).parent,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                self.processes.append((process, description))
                self.log(f"Started in background: {description} (PID: {process.pid})", 'SUCCESS')
                return True
            else:
                # Run synchronously
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    cwd=Path(__file__).parent
                )
                
                if result.returncode == 0:
                    self.log(f"Completed: {description}", 'SUCCESS')
                    if self.debug_level == 'DEBUG' and result.stdout.strip():
                        print(f"Output: {result.stdout.strip()}")
                    return True
                else:
                    error_msg = f"Failed: {description}"
                    if result.stderr.strip():
                        error_msg += f" - {result.stderr.strip()}"
                    
                    self.log(error_msg, 'ERROR' if critical else 'WARNING')
                    return not critical  # Return True for non-critical failures
                    
        except Exception as e:
            self.log(f"Exception in {description}: {str(e)}", 'ERROR')
            return not critical
    
    def setup_development_environment(self):
        """Setup development environment"""
        self.log("Setting up Development Environment", 'INFO')
        
        # Set development environment variables
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
        os.environ.setdefault('DEBUG', 'True')
        os.environ.setdefault('DEVELOPMENT_MODE', 'True')
        
        # Create development directories
        dev_dirs = ['logs', 'media', 'media/receipts', 'media/profile_pics', 'media/quarantine', 'staticfiles']
        for dir_path in dev_dirs:
            full_path = Path(__file__).parent / dir_path
            if not full_path.exists():
                full_path.mkdir(parents=True, exist_ok=True)
                self.log(f"Created directory: {dir_path}", 'SUCCESS')
        
        return True
    
    def setup_development_database(self):
        """Setup development database with optimizations"""
        self.log("Development Database Setup", 'INFO')
        
        if self.reset_db:
            self.log("Resetting database (development mode)", 'WARNING')
            reset_commands = [
                ("python manage.py flush --noinput", "Flushing database", False),
                ("python manage.py migrate", "Re-applying migrations", True),
            ]
            
            for command, description, critical in reset_commands:
                if not self.run_command(command, description, critical=critical):
                    if critical:
                        return False
        
        commands = [
            # Basic database setup
            ("python manage.py makemigrations", "Creating new migrations", False),
            ("python manage.py migrate", "Applying migrations", True),
            
            # Development data setup
            ("python manage.py create_default_roles", "Creating default roles", False),
            ("python manage.py setup_permissions", "Setting up permissions", False),
            ("python manage.py create_all_permissions", "Creating all permissions", False),
            ("python manage.py assign_role_permissions", "Assigning role permissions", False),
            
            # Create development superuser
            ("python manage.py setup_superadmin", "Setting up development admin", False),
        ]
        
        for command, description, critical in commands:
            if not self.run_command(command, description, critical=critical):
                if critical:
                    return False
        
        return True
    
    def setup_demo_data(self):
        """Setup demo data for development"""
        if not self.with_demo_data:
            self.log("Skipping demo data setup", 'INFO')
            return True
        
        self.log("Setting up Demo Data", 'INFO')
        
        commands = [
            ("python manage.py seed_demo_data", "Seeding demo data", False),
            ("python manage.py seed_deals_data", "Seeding deals data", False),
            ("python manage.py generate_dashboard_data", "Generating dashboard data", False),
        ]
        
        for command, description, critical in commands:
            self.run_command(command, description, critical=critical)
        
        return True
    
    def setup_development_monitoring(self):
        """Setup monitoring for development"""
        self.log("Development Monitoring Setup", 'INFO')
        
        commands = [
            # Initialize monitoring
            ("python manage.py manage_monitoring status", "Checking monitoring status", False),
            ("python manage.py manage_monitoring health-check", "Running health check", False),
            
            # Background tasks
            ("python manage.py manage_background_tasks --action status", "Checking background tasks", False),
        ]
        
        for command, description, critical in commands:
            self.run_command(command, description, critical=critical)
        
        return True
    
    def setup_development_cache(self):
        """Setup cache for development"""
        self.log("Development Cache Setup", 'INFO')
        
        commands = [
            ("python manage.py manage_cache --action status", "Checking cache status", False),
            ("python manage.py manage_role_cache --action status", "Checking role cache", False),
        ]
        
        for command, description, critical in commands:
            self.run_command(command, description, critical=critical)
        
        return True
    
    def start_development_services(self):
        """Start development services"""
        self.log("Starting Development Services", 'INFO')
        
        # Start Django development server
        self.log("Starting Django development server on port 8000", 'INFO')
        django_success = self.run_command(
            "python manage.py runserver 8000",
            "Django Development Server",
            background=True,
            critical=False
        )
        
        # Give Django server time to start
        time.sleep(3)
        
        # Start Celery worker
        self.log("Starting Celery worker", 'INFO')
        celery_worker_success = self.run_command(
            "celery -A core_config worker -l info --concurrency=2",
            "Celery Worker",
            background=True,
            critical=False
        )
        
        # Start Celery beat scheduler
        self.log("Starting Celery beat scheduler", 'INFO')
        celery_beat_success = self.run_command(
            "celery -A core_config beat -l info",
            "Celery Beat Scheduler",
            background=True,
            critical=False
        )
        
        if django_success:
            self.log("🌐 Django server: http://127.0.0.1:8000/", 'SUCCESS')
            self.log("📚 API docs: http://127.0.0.1:8000/swagger/", 'SUCCESS')
            self.log("🔧 Admin panel: http://127.0.0.1:8000/admin/", 'SUCCESS')
            self.log("📊 Health check: http://127.0.0.1:8000/api/monitoring/system/health/", 'SUCCESS')
        
        return django_success
    
    def monitor_services(self):
        """Monitor running services and handle restarts"""
        self.log("Monitoring development services", 'INFO')
        self.log("Press Ctrl+C to stop all services", 'INFO')
        
        try:
            while self.running:
                # Check if processes are still running
                for process, description in self.processes:
                    if process.poll() is not None:
                        self.log(f"Service stopped: {description}", 'WARNING')
                        # Could implement auto-restart here if needed
                
                time.sleep(5)  # Check every 5 seconds
                
        except KeyboardInterrupt:
            self.log("Shutdown requested", 'INFO')
            self.cleanup_processes()
    
    def cleanup_processes(self):
        """Clean up background processes"""
        self.log("Cleaning up background processes", 'INFO')
        
        for process, description in self.processes:
            if process.poll() is None:  # Process is still running
                self.log(f"Terminating: {description}", 'INFO')
                process.terminate()
                
                # Wait for graceful shutdown
                try:
                    process.wait(timeout=10)
                    self.log(f"Gracefully stopped: {description}", 'SUCCESS')
                except subprocess.TimeoutExpired:
                    self.log(f"Force killing: {description}", 'WARNING')
                    process.kill()
        
        self.processes.clear()
    
    def run(self):
        """Main development startup sequence"""
        self.log("PRS Backend Development Startup", 'INFO')
        self.log(f"Debug level: {self.debug_level}", 'INFO')
        self.log(f"Demo data: {'Yes' if self.with_demo_data else 'No'}", 'INFO')
        self.log(f"Reset DB: {'Yes' if self.reset_db else 'No'}", 'INFO')
        
        steps = [
            ("Environment Setup", self.setup_development_environment),
            ("Database Setup", self.setup_development_database),
            ("Demo Data", self.setup_demo_data),
            ("Monitoring Setup", self.setup_development_monitoring),
            ("Cache Setup", self.setup_development_cache),
            ("Services", self.start_development_services),
        ]
        
        for step_name, step_func in steps:
            try:
                if not step_func():
                    self.log(f"Development startup failed at: {step_name}", 'ERROR')
                    return False
            except KeyboardInterrupt:
                self.log("Development startup interrupted", 'WARNING')
                return False
            except Exception as e:
                self.log(f"Unexpected error in {step_name}: {str(e)}", 'ERROR')
                return False
        
        # Monitor services
        self.monitor_services()
        
        return True

def main():
    """Main entry point for development startup"""
    parser = argparse.ArgumentParser(
        description='PRS Backend Development Startup Script',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python start_development.py                        # Basic development startup
  python start_development.py --with-demo-data       # Include demo data
  python start_development.py --reset-db             # Reset database first
  python start_development.py --debug-level=DEBUG    # Verbose debugging
        """
    )
    
    parser.add_argument(
        '--with-demo-data',
        action='store_true',
        help='Include demo data setup'
    )
    
    parser.add_argument(
        '--reset-db',
        action='store_true',
        help='Reset database before startup'
    )
    
    parser.add_argument(
        '--debug-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Debug logging level'
    )
    
    args = parser.parse_args()
    
    # Initialize development starter
    starter = DevelopmentStarter(
        with_demo_data=args.with_demo_data,
        reset_db=args.reset_db,
        debug_level=args.debug_level
    )
    
    success = starter.run()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()