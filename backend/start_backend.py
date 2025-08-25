#!/usr/bin/env python
"""
PRS Backend Comprehensive Startup Script
========================================

This script provides a complete startup sequence for the PRS backend system,
including all management commands needed for proper functioning based on the
comprehensive security and performance overhaul implementation.

Features:
- Database setup and optimization
- Security initialization
- Performance monitoring setup
- Background task system initialization
- Cache warming and optimization
- Health checks and validation
- Development and production modes

Usage:
    python start_backend.py [--mode=dev|prod] [--skip-checks] [--verbose]
"""

import os
import sys
import subprocess
import time
import argparse
from pathlib import Path
from datetime import datetime

class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class PRSBackendStarter:
    """Main class for PRS Backend startup operations"""
    
    def __init__(self, mode='dev', skip_checks=False, verbose=False):
        self.mode = mode
        self.skip_checks = skip_checks
        self.verbose = verbose
        self.start_time = datetime.now()
        self.failed_commands = []
        self.warnings = []
        
    def log(self, message, level='INFO'):
        """Enhanced logging with colors and timestamps"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        if level == 'SUCCESS':
            color = Colors.OKGREEN
            icon = '✅'
        elif level == 'WARNING':
            color = Colors.WARNING
            icon = '⚠️ '
        elif level == 'ERROR':
            color = Colors.FAIL
            icon = '❌'
        elif level == 'INFO':
            color = Colors.OKBLUE
            icon = '🔄'
        elif level == 'HEADER':
            color = Colors.HEADER
            icon = '🚀'
        else:
            color = Colors.ENDC
            icon = 'ℹ️ '
        
        print(f"{color}[{timestamp}] {icon} {message}{Colors.ENDC}")
        
        if level == 'WARNING':
            self.warnings.append(message)
    
    def run_command(self, command, description, critical=True, timeout=300):
        """Execute a management command with proper error handling"""
        self.log(f"Executing: {description}", 'INFO')
        
        if self.verbose:
            self.log(f"Command: {command}", 'INFO')
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=Path(__file__).parent
            )
            
            if result.returncode == 0:
                self.log(f"Completed: {description}", 'SUCCESS')
                if self.verbose and result.stdout.strip():
                    print(f"{Colors.OKCYAN}Output:{Colors.ENDC}")
                    print(result.stdout.strip())
                return True
            else:
                error_msg = f"Failed: {description}"
                if result.stderr.strip():
                    error_msg += f" - {result.stderr.strip()}"
                
                self.log(error_msg, 'ERROR')
                self.failed_commands.append((command, description, result.stderr))
                
                if critical and not self.skip_checks:
                    self.log("Critical command failed. Use --skip-checks to continue.", 'ERROR')
                    return False
                
                return False
                
        except subprocess.TimeoutExpired:
            self.log(f"Timeout: {description} (>{timeout}s)", 'ERROR')
            self.failed_commands.append((command, description, "Timeout"))
            return False
        except Exception as e:
            self.log(f"Exception in {description}: {str(e)}", 'ERROR')
            self.failed_commands.append((command, description, str(e)))
            return False
    
    def check_prerequisites(self):
        """Check system prerequisites"""
        self.log("Checking Prerequisites", 'HEADER')
        
        # Check Python version
        python_version = sys.version_info
        if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 8):
            self.log("Python 3.8+ is required", 'ERROR')
            return False
        
        self.log(f"Python {python_version.major}.{python_version.minor}.{python_version.micro} ✓", 'SUCCESS')
        
        # Check virtual environment
        if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
            self.log("Virtual environment detected ✓", 'SUCCESS')
        else:
            self.log("No virtual environment detected", 'WARNING')
        
        # Check Django installation
        try:
            import django
            self.log(f"Django {django.get_version()} ✓", 'SUCCESS')
        except ImportError:
            self.log("Django not installed", 'ERROR')
            return False
        
        # Check required directories
        required_dirs = ['logs', 'media', 'media/receipts', 'media/profile_pics', 'media/quarantine']
        for dir_path in required_dirs:
            full_path = Path(__file__).parent / dir_path
            if not full_path.exists():
                full_path.mkdir(parents=True, exist_ok=True)
                self.log(f"Created directory: {dir_path}", 'SUCCESS')
        
        return True
    
    def setup_database(self):
        """Complete database setup and optimization"""
        self.log("Database Setup & Optimization", 'HEADER')
        
        commands = [
            # Basic database setup
            ("python manage.py makemigrations", "Creating new migrations", True),
            ("python manage.py migrate", "Applying database migrations", True),
            
            # Initialize core data
            ("python manage.py create_default_roles", "Creating default roles", False),
            ("python manage.py setup_permissions", "Setting up permissions", False),
            ("python manage.py create_all_permissions", "Creating all permissions", False),
            
            # Database optimization
            ("python manage.py optimize_database --action analyze", "Analyzing database performance", False),
            ("python manage.py optimize_financial_fields --action validate", "Validating financial fields", False),
            ("python manage.py cleanup_duplicate_commissions", "Cleaning up duplicate commissions", False),
        ]
        
        success = True
        for command, description, critical in commands:
            if not self.run_command(command, description, critical):
                if critical:
                    success = False
                    break
        
        return success
    
    def setup_security(self):
        """Initialize security systems"""
        self.log("Security System Initialization", 'HEADER')
        
        commands = [
            # Authentication and permissions
            ("python manage.py setup_superadmin", "Setting up super admin", False),
            ("python manage.py assign_role_permissions", "Assigning role permissions", False),
            ("python manage.py check_password_expiration", "Checking password expiration", False),
            
            # Security validation
            ("python manage.py test_secure_token_manager", "Testing secure token manager", False),
        ]
        
        for command, description, critical in commands:
            self.run_command(command, description, critical)
        
        return True
    
    def setup_performance_monitoring(self):
        """Initialize performance monitoring and alerting"""
        self.log("Performance Monitoring Setup", 'HEADER')
        
        commands = [
            # Monitoring system
            ("python manage.py manage_monitoring status", "Checking monitoring system status", False),
            ("python manage.py manage_monitoring health-check", "Running system health check", False),
            
            # Background tasks
            ("python manage.py manage_background_tasks --action status", "Checking background task status", False),
        ]
        
        for command, description, critical in commands:
            self.run_command(command, description, critical)
        
        return True
    
    def setup_cache_optimization(self):
        """Initialize and warm up caches"""
        self.log("Cache Optimization", 'HEADER')
        
        commands = [
            # Cache management
            ("python manage.py manage_cache --action status", "Checking cache status", False),
            ("python manage.py manage_cache --action warm", "Warming up caches", False),
            ("python manage.py manage_role_cache --action warm", "Warming role cache", False),
        ]
        
        for command, description, critical in commands:
            self.run_command(command, description, critical)
        
        return True
    
    def setup_business_logic(self):
        """Initialize business logic optimizations"""
        self.log("Business Logic Optimization", 'HEADER')
        
        commands = [
            # Deal optimization
            ("python manage.py analyze_deal_performance", "Analyzing deal performance", False),
            ("python manage.py workflow_maintenance --action status", "Checking workflow status", False),
            ("python manage.py optimize_business_logic --action analyze", "Analyzing business logic", False),
            
            # Commission optimization
            ("python manage.py optimize_commissions --action analytics", "Running commission analytics", False),
            
            # Query optimization
            ("python manage.py analyze_org_queries", "Analyzing organization queries", False),
        ]
        
        for command, description, critical in commands:
            self.run_command(command, description, critical)
        
        return True
    
    def run_system_validation(self):
        """Run comprehensive system validation"""
        self.log("System Validation", 'HEADER')
        
        commands = [
            # Django system checks
            ("python manage.py check", "Django system check", True),
            ("python manage.py check --deploy", "Deployment readiness check", False),
            
            # Custom validation
            ("python manage.py test_atomic_operations", "Testing atomic operations", False),
            
            # Collect static files for production
        ]
        
        if self.mode == 'prod':
            commands.append(("python manage.py collectstatic --noinput", "Collecting static files", True))
        
        success = True
        for command, description, critical in commands:
            if not self.run_command(command, description, critical):
                if critical:
                    success = False
        
        return success
    
    def setup_demo_data(self):
        """Setup demo data for development"""
        if self.mode != 'dev':
            return True
        
        self.log("Demo Data Setup (Development Mode)", 'HEADER')
        
        commands = [
            ("python manage.py seed_demo_data", "Seeding demo data", False),
            ("python manage.py seed_deals_data", "Seeding deals data", False),
            ("python manage.py generate_dashboard_data", "Generating dashboard data", False),
        ]
        
        for command, description, critical in commands:
            self.run_command(command, description, critical)
        
        return True
    
    def start_services(self):
        """Start required services"""
        self.log("Starting Services", 'HEADER')
        
        if self.mode == 'dev':
            self.log("Development mode - services will be started manually", 'INFO')
            self.log("To start the server: python manage.py runserver", 'INFO')
            self.log("To start Celery worker: celery -A core_config worker -l info", 'INFO')
            self.log("To start Celery beat: celery -A core_config beat -l info", 'INFO')
        else:
            self.log("Production mode - configure your process manager (gunicorn, supervisor, etc.)", 'INFO')
        
        return True
    
    def print_summary(self):
        """Print startup summary"""
        duration = datetime.now() - self.start_time
        
        print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
        print(f"{Colors.HEADER}🎉 PRS BACKEND STARTUP COMPLETE{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
        
        print(f"{Colors.OKGREEN}✅ Startup completed in {duration.total_seconds():.1f} seconds{Colors.ENDC}")
        print(f"{Colors.OKGREEN}✅ Mode: {self.mode.upper()}{Colors.ENDC}")
        
        if self.warnings:
            print(f"{Colors.WARNING}⚠️  Warnings: {len(self.warnings)}{Colors.ENDC}")
            for warning in self.warnings[:5]:  # Show first 5 warnings
                print(f"   • {warning}")
            if len(self.warnings) > 5:
                print(f"   ... and {len(self.warnings) - 5} more")
        
        if self.failed_commands:
            print(f"{Colors.FAIL}❌ Failed commands: {len(self.failed_commands)}{Colors.ENDC}")
            for command, description, error in self.failed_commands[:3]:  # Show first 3 failures
                print(f"   • {description}: {error}")
            if len(self.failed_commands) > 3:
                print(f"   ... and {len(self.failed_commands) - 3} more")
        
        print(f"\n{Colors.OKCYAN}🔗 Next Steps:{Colors.ENDC}")
        if self.mode == 'dev':
            print(f"   1. Start development server: {Colors.BOLD}python manage.py runserver{Colors.ENDC}")
            print(f"   2. Start Celery worker: {Colors.BOLD}celery -A core_config worker -l info{Colors.ENDC}")
            print(f"   3. Start Celery beat: {Colors.BOLD}celery -A core_config beat -l info{Colors.ENDC}")
            print(f"   4. Visit admin panel: {Colors.BOLD}http://127.0.0.1:8000/admin/{Colors.ENDC}")
            print(f"   5. Check API docs: {Colors.BOLD}http://127.0.0.1:8000/swagger/{Colors.ENDC}")
            print(f"   6. Monitor system: {Colors.BOLD}http://127.0.0.1:8000/api/monitoring/system/health/{Colors.ENDC}")
        else:
            print(f"   1. Configure your web server (nginx, apache)")
            print(f"   2. Configure your WSGI server (gunicorn, uwsgi)")
            print(f"   3. Configure your process manager (supervisor, systemd)")
            print(f"   4. Configure your reverse proxy")
            print(f"   5. Set up SSL certificates")
        
        print(f"\n{Colors.OKCYAN}📊 System Features Ready:{Colors.ENDC}")
        print(f"   • {Colors.OKGREEN}Security Hardening{Colors.ENDC} - Input validation, file security, authentication")
        print(f"   • {Colors.OKGREEN}Performance Monitoring{Colors.ENDC} - Real-time metrics and alerting")
        print(f"   • {Colors.OKGREEN}Background Tasks{Colors.ENDC} - Celery-based async processing")
        print(f"   • {Colors.OKGREEN}Database Optimization{Colors.ENDC} - Query optimization and indexing")
        print(f"   • {Colors.OKGREEN}Business Logic{Colors.ENDC} - Deal workflows and commission processing")
        print(f"   • {Colors.OKGREEN}Caching System{Colors.ENDC} - Strategic caching for performance")
        
        print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
    
    def run(self):
        """Main startup sequence"""
        self.log("PRS Backend Comprehensive Startup", 'HEADER')
        self.log(f"Mode: {self.mode.upper()}", 'INFO')
        self.log(f"Skip checks: {self.skip_checks}", 'INFO')
        self.log(f"Verbose: {self.verbose}", 'INFO')
        
        steps = [
            ("Prerequisites", self.check_prerequisites),
            ("Database Setup", self.setup_database),
            ("Security Initialization", self.setup_security),
            ("Performance Monitoring", self.setup_performance_monitoring),
            ("Cache Optimization", self.setup_cache_optimization),
            ("Business Logic", self.setup_business_logic),
            ("System Validation", self.run_system_validation),
            ("Demo Data", self.setup_demo_data),
            ("Services", self.start_services),
        ]
        
        for step_name, step_func in steps:
            try:
                if not step_func():
                    if not self.skip_checks:
                        self.log(f"Startup failed at: {step_name}", 'ERROR')
                        return False
                    else:
                        self.log(f"Continuing despite failure in: {step_name}", 'WARNING')
            except KeyboardInterrupt:
                self.log("Startup interrupted by user", 'ERROR')
                return False
            except Exception as e:
                self.log(f"Unexpected error in {step_name}: {str(e)}", 'ERROR')
                if not self.skip_checks:
                    return False
        
        self.print_summary()
        return True

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='PRS Backend Comprehensive Startup Script',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python start_backend.py                    # Development mode with checks
  python start_backend.py --mode=prod       # Production mode
  python start_backend.py --skip-checks     # Skip critical checks
  python start_backend.py --verbose         # Verbose output
        """
    )
    
    parser.add_argument(
        '--mode',
        choices=['dev', 'prod'],
        default='dev',
        help='Startup mode (default: dev)'
    )
    
    parser.add_argument(
        '--skip-checks',
        action='store_true',
        help='Skip critical checks and continue on errors'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Initialize and run startup
    starter = PRSBackendStarter(
        mode=args.mode,
        skip_checks=args.skip_checks,
        verbose=args.verbose
    )
    
    success = starter.run()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()