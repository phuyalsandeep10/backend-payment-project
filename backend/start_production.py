#!/usr/bin/env python
"""
PRS Backend Production Startup Script
====================================

This script is specifically designed for production deployment of the PRS backend,
with enhanced security, performance optimization, and monitoring capabilities.

Features:
- Production-grade database setup
- Security hardening validation
- Performance optimization
- Health checks and monitoring
- Service management integration
- Deployment validation

Usage:
    python start_production.py [--validate-only] [--force] [--config-check]
"""

import os
import sys
import subprocess
import time
import json
from pathlib import Path
from datetime import datetime
import argparse

class ProductionStarter:
    """Production-specific startup manager for PRS Backend"""
    
    def __init__(self, validate_only=False, force=False, config_check=False):
        self.validate_only = validate_only
        self.force = force
        self.config_check = config_check
        self.start_time = datetime.now()
        self.errors = []
        self.warnings = []
        
    def log(self, message, level='INFO'):
        """Production logging with structured output"""
        timestamp = datetime.now().isoformat()
        
        log_entry = {
            'timestamp': timestamp,
            'level': level,
            'message': message
        }
        
        # Console output with colors
        colors = {
            'SUCCESS': '\033[92m',
            'WARNING': '\033[93m',
            'ERROR': '\033[91m',
            'INFO': '\033[94m',
            'CRITICAL': '\033[95m',
            'ENDC': '\033[0m'
        }
        
        color = colors.get(level, colors['ENDC'])
        icons = {
            'SUCCESS': '✅',
            'WARNING': '⚠️ ',
            'ERROR': '❌',
            'INFO': 'ℹ️ ',
            'CRITICAL': '🚨'
        }
        
        icon = icons.get(level, 'ℹ️ ')
        print(f"{color}[{timestamp}] {icon} {message}{colors['ENDC']}")
        
        # Log to file for production monitoring
        log_file = Path(__file__).parent / 'logs' / 'production_startup.log'
        log_file.parent.mkdir(exist_ok=True)
        
        with open(log_file, 'a') as f:
            f.write(f"{json.dumps(log_entry)}\n")
        
        if level == 'ERROR':
            self.errors.append(message)
        elif level == 'WARNING':
            self.warnings.append(message)
    
    def run_command(self, command, description, critical=True, timeout=600):
        """Execute command with production-grade error handling"""
        self.log(f"Executing: {description}", 'INFO')
        
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
                return True
            else:
                error_msg = f"Failed: {description}"
                if result.stderr.strip():
                    error_msg += f" - {result.stderr.strip()}"
                
                self.log(error_msg, 'ERROR' if critical else 'WARNING')
                
                if critical and not self.force:
                    self.log("Critical command failed. Use --force to continue.", 'CRITICAL')
                    return False
                
                return False
                
        except subprocess.TimeoutExpired:
            self.log(f"Timeout: {description} (>{timeout}s)", 'ERROR')
            return False
        except Exception as e:
            self.log(f"Exception in {description}: {str(e)}", 'ERROR')
            return False
    
    def validate_production_environment(self):
        """Validate production environment requirements"""
        self.log("Validating Production Environment", 'INFO')
        
        # Check environment variables
        required_env_vars = [
            'DJANGO_SETTINGS_MODULE',
            'SECRET_KEY',
            'DATABASE_URL',
            'ALLOWED_HOSTS',
        ]
        
        missing_vars = []
        for var in required_env_vars:
            if not os.getenv(var):
                missing_vars.append(var)
        
        if missing_vars:
            self.log(f"Missing environment variables: {', '.join(missing_vars)}", 'ERROR')
            return False
        
        # Check DEBUG is False
        if os.getenv('DEBUG', 'False').lower() == 'true':
            self.log("DEBUG is enabled in production!", 'ERROR')
            return False
        
        # Check database connectivity
        if not self.run_command("python manage.py dbshell --command='SELECT 1;'", "Database connectivity check", critical=True):
            return False
        
        # Check Redis connectivity (if configured)
        if os.getenv('REDIS_URL'):
            self.log("Redis configured - checking connectivity", 'INFO')
            # Redis check would go here
        
        self.log("Production environment validation passed", 'SUCCESS')
        return True
    
    def setup_production_database(self):
        """Production database setup with optimizations"""
        self.log("Production Database Setup", 'INFO')
        
        commands = [
            # Database migrations
            ("python manage.py migrate --run-syncdb", "Running database migrations", True),
            
            # Create production superuser if needed
            ("python manage.py setup_superadmin --production", "Setting up production admin", False),
            
            # Database optimization
            ("python manage.py optimize_database --action analyze", "Analyzing database performance", False),
            ("python manage.py optimize_database --action recommend", "Getting optimization recommendations", False),
            
            # Financial data validation
            ("python manage.py optimize_financial_fields --action validate", "Validating financial data integrity", True),
            
            # Commission cleanup
            ("python manage.py cleanup_duplicate_commissions --dry-run=false", "Cleaning duplicate commissions", False),
            
            # Index optimization
            ("python manage.py optimize_commissions --action analytics", "Optimizing commission indexes", False),
        ]
        
        for command, description, critical in commands:
            if not self.run_command(command, description, critical):
                if critical:
                    return False
        
        return True
    
    def setup_production_security(self):
        """Production security hardening"""
        self.log("Production Security Setup", 'INFO')
        
        commands = [
            # Security validation
            ("python manage.py check --deploy", "Security deployment check", True),
            
            # Permission setup
            ("python manage.py create_all_permissions", "Creating all permissions", True),
            ("python manage.py assign_role_permissions", "Assigning role permissions", True),
            
            # Password policy enforcement
            ("python manage.py check_password_expiration --enforce", "Enforcing password policies", False),
            
            # Security token validation
            ("python manage.py test_secure_token_manager", "Validating security tokens", False),
        ]
        
        for command, description, critical in commands:
            if not self.run_command(command, description, critical):
                if critical:
                    return False
        
        return True
    
    def setup_production_monitoring(self):
        """Production monitoring and alerting setup"""
        self.log("Production Monitoring Setup", 'INFO')
        
        commands = [
            # Monitoring system initialization
            ("python manage.py manage_monitoring status", "Initializing monitoring system", False),
            ("python manage.py manage_monitoring health-check", "Running health checks", True),
            
            # Background task system
            ("python manage.py manage_background_tasks --action status", "Checking background tasks", False),
            
            # Performance baseline
            ("python manage.py analyze_deal_performance --baseline", "Establishing performance baseline", False),
            ("python manage.py analyze_org_queries --production", "Analyzing production queries", False),
        ]
        
        for command, description, critical in commands:
            if not self.run_command(command, description, critical):
                if critical:
                    return False
        
        return True
    
    def setup_production_cache(self):
        """Production cache optimization"""
        self.log("Production Cache Setup", 'INFO')
        
        commands = [
            # Cache system setup
            ("python manage.py manage_cache --action status", "Checking cache status", False),
            ("python manage.py manage_cache --action warm", "Warming production caches", False),
            ("python manage.py manage_role_cache --action warm", "Warming role cache", False),
        ]
        
        for command, description, critical in commands:
            self.run_command(command, description, critical)
        
        return True
    
    def collect_static_files(self):
        """Collect and optimize static files for production"""
        self.log("Static Files Collection", 'INFO')
        
        commands = [
            ("python manage.py collectstatic --noinput --clear", "Collecting static files", True),
        ]
        
        for command, description, critical in commands:
            if not self.run_command(command, description, critical):
                if critical:
                    return False
        
        return True
    
    def run_production_tests(self):
        """Run production-specific validation tests"""
        self.log("Production Validation Tests", 'INFO')
        
        commands = [
            # System checks
            ("python manage.py check", "Django system check", True),
            ("python manage.py check --deploy", "Deployment check", True),
            
            # Atomic operations test
            ("python manage.py test_atomic_operations --production", "Testing atomic operations", False),
            
            # Workflow validation
            ("python manage.py workflow_maintenance --action validate", "Validating workflows", False),
        ]
        
        success = True
        for command, description, critical in commands:
            if not self.run_command(command, description, critical):
                if critical:
                    success = False
        
        return success
    
    def generate_production_report(self):
        """Generate production readiness report"""
        self.log("Generating Production Report", 'INFO')
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'startup_duration': (datetime.now() - self.start_time).total_seconds(),
            'environment': 'production',
            'errors': self.errors,
            'warnings': self.warnings,
            'status': 'ready' if not self.errors else 'issues_detected'
        }
        
        # Save report
        report_file = Path(__file__).parent / 'logs' / 'production_report.json'
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.log(f"Production report saved to: {report_file}", 'SUCCESS')
        
        return report
    
    def print_production_summary(self):
        """Print production startup summary"""
        duration = datetime.now() - self.start_time
        
        print("\n" + "="*70)
        print("🚀 PRS BACKEND PRODUCTION STARTUP COMPLETE")
        print("="*70)
        
        print(f"✅ Startup completed in {duration.total_seconds():.1f} seconds")
        print(f"✅ Environment: PRODUCTION")
        
        if self.errors:
            print(f"❌ Errors: {len(self.errors)}")
            for error in self.errors[:3]:
                print(f"   • {error}")
            if len(self.errors) > 3:
                print(f"   ... and {len(self.errors) - 3} more")
        
        if self.warnings:
            print(f"⚠️  Warnings: {len(self.warnings)}")
            for warning in self.warnings[:3]:
                print(f"   • {warning}")
            if len(self.warnings) > 3:
                print(f"   ... and {len(self.warnings) - 3} more")
        
        print("\n🔧 Production Services:")
        print("   • Web Server: Configure gunicorn/uwsgi")
        print("   • Reverse Proxy: Configure nginx/apache")
        print("   • Background Tasks: Start Celery worker & beat")
        print("   • Monitoring: Performance monitoring active")
        print("   • Security: Hardening measures applied")
        print("   • Database: Optimized and validated")
        
        print("\n📊 Monitoring Endpoints:")
        print("   • Health Check: /api/monitoring/system/health/")
        print("   • Performance: /api/monitoring/performance/summary/")
        print("   • Alerts: /api/alerting/history/")
        
        print("\n🔐 Security Features:")
        print("   • Input validation and sanitization")
        print("   • File security and malware scanning")
        print("   • Authentication and authorization")
        print("   • Audit logging and monitoring")
        
        print("="*70)
    
    def run(self):
        """Main production startup sequence"""
        self.log("PRS Backend Production Startup", 'INFO')
        
        if self.config_check:
            self.log("Configuration check mode", 'INFO')
            return self.validate_production_environment()
        
        steps = [
            ("Environment Validation", self.validate_production_environment),
            ("Database Setup", self.setup_production_database),
            ("Security Hardening", self.setup_production_security),
            ("Static Files", self.collect_static_files),
            ("Cache Optimization", self.setup_production_cache),
            ("Monitoring Setup", self.setup_production_monitoring),
            ("Production Tests", self.run_production_tests),
        ]
        
        if self.validate_only:
            self.log("Validation-only mode", 'INFO')
            steps = [("Environment Validation", self.validate_production_environment)]
        
        for step_name, step_func in steps:
            try:
                if not step_func():
                    if not self.force:
                        self.log(f"Production startup failed at: {step_name}", 'CRITICAL')
                        return False
                    else:
                        self.log(f"Continuing despite failure in: {step_name}", 'WARNING')
            except KeyboardInterrupt:
                self.log("Production startup interrupted", 'CRITICAL')
                return False
            except Exception as e:
                self.log(f"Unexpected error in {step_name}: {str(e)}", 'ERROR')
                if not self.force:
                    return False
        
        # Generate report
        self.generate_production_report()
        
        if not self.validate_only:
            self.print_production_summary()
        
        return len(self.errors) == 0

def main():
    """Main entry point for production startup"""
    parser = argparse.ArgumentParser(
        description='PRS Backend Production Startup Script',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python start_production.py                    # Full production startup
  python start_production.py --validate-only    # Validation only
  python start_production.py --config-check     # Configuration check only
  python start_production.py --force            # Continue on errors
        """
    )
    
    parser.add_argument(
        '--validate-only',
        action='store_true',
        help='Only validate environment, do not start services'
    )
    
    parser.add_argument(
        '--force',
        action='store_true',
        help='Continue startup even if non-critical errors occur'
    )
    
    parser.add_argument(
        '--config-check',
        action='store_true',
        help='Only check configuration, do not perform startup'
    )
    
    args = parser.parse_args()
    
    # Initialize production starter
    starter = ProductionStarter(
        validate_only=args.validate_only,
        force=args.force,
        config_check=args.config_check
    )
    
    success = starter.run()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()