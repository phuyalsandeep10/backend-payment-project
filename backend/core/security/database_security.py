"""
Database Security Configuration and Validation
Ensures secure database connections and monitors connection security
"""
import logging
import ssl
from django.db import connection
from django.core.management.base import BaseCommand
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

logger = logging.getLogger('security')


class DatabaseSecurityValidator:
    """
    Validates and enforces database security settings
    """
    
    def __init__(self):
        self.security_checks = []
        self.warnings = []
        self.errors = []
    
    def validate_connection_security(self):
        """
        Validate database connection security settings
        """
        logger.info("🔒 Validating database connection security...")
        
        try:
            # Check SSL configuration
            self._check_ssl_configuration()
            
            # Check connection parameters
            self._check_connection_parameters()
            
            # Test actual connection security
            self._test_connection_security()
            
            # Check database permissions
            self._check_database_permissions()
            
            # Generate security report
            return self._generate_security_report()
            
        except Exception as e:
            logger.error(f"Database security validation failed: {str(e)}")
            self.errors.append(f"Security validation error: {str(e)}")
            return False
    
    def _check_ssl_configuration(self):
        """Check SSL configuration in database settings"""
        db_config = settings.DATABASES['default']
        options = db_config.get('OPTIONS', {})
        
        # Check SSL mode
        sslmode = options.get('sslmode', 'disable')
        if sslmode == 'disable':
            self.warnings.append("SSL is disabled - not recommended for production")
        elif sslmode == 'allow':
            self.warnings.append("SSL mode 'allow' provides minimal security")
        elif sslmode == 'prefer':
            self.security_checks.append("SSL mode 'prefer' - will use SSL if available")
        elif sslmode == 'require':
            self.security_checks.append("SSL mode 'require' - enforces SSL connections")
        elif sslmode in ['verify-ca', 'verify-full']:
            self.security_checks.append(f"SSL mode '{sslmode}' - highest security level")
        
        # Check SSL certificates
        if options.get('sslcert'):
            self.security_checks.append("SSL client certificate configured")
        if options.get('sslkey'):
            self.security_checks.append("SSL client key configured")
        if options.get('sslrootcert'):
            self.security_checks.append("SSL root certificate configured")
        
        # Production SSL enforcement
        if not settings.DEBUG:
            if sslmode not in ['require', 'verify-ca', 'verify-full']:
                self.errors.append("Production environment must enforce SSL connections")
    
    def _check_connection_parameters(self):
        """Check connection security parameters"""
        db_config = settings.DATABASES['default']
        options = db_config.get('OPTIONS', {})
        
        # Check connection timeout
        connect_timeout = options.get('connect_timeout', 0)
        if connect_timeout > 0:
            self.security_checks.append(f"Connection timeout set to {connect_timeout}s")
        else:
            self.warnings.append("No connection timeout configured")
        
        # Check connection pooling
        if options.get('conn_max_age', 0) > 0:
            self.security_checks.append("Connection pooling enabled")
        
        # Check health checks
        if options.get('conn_health_checks'):
            self.security_checks.append("Connection health checks enabled")
        
        # Check application name
        if options.get('application_name'):
            self.security_checks.append("Application name configured for connection tracking")
        
        # Check transaction isolation
        db_options = options.get('options', '')
        if 'default_transaction_isolation=serializable' in db_options:
            self.security_checks.append("Serializable transaction isolation configured")
        elif 'default_transaction_isolation' in db_options:
            self.security_checks.append("Custom transaction isolation configured")
        else:
            self.warnings.append("Default transaction isolation level in use")
    
    def _test_connection_security(self):
        """Test actual database connection security"""
        try:
            with connection.cursor() as cursor:
                # Check SSL status
                cursor.execute("SELECT ssl_is_used();")
                ssl_used = cursor.fetchone()[0]
                
                if ssl_used:
                    self.security_checks.append("✅ Active connection is using SSL")
                    
                    # Get SSL details
                    try:
                        cursor.execute("""
                            SELECT 
                                ssl_version,
                                ssl_cipher,
                                ssl_client_cert_present
                            FROM pg_stat_ssl 
                            WHERE pid = pg_backend_pid();
                        """)
                        ssl_info = cursor.fetchone()
                        if ssl_info:
                            version, cipher, cert_present = ssl_info
                            self.security_checks.append(f"SSL Version: {version}")
                            self.security_checks.append(f"SSL Cipher: {cipher}")
                            if cert_present:
                                self.security_checks.append("Client certificate present")
                    except Exception:
                        # SSL details not available in all PostgreSQL versions
                        pass
                else:
                    self.warnings.append("⚠️ Active connection is NOT using SSL")
                
                # Check connection info
                cursor.execute("""
                    SELECT 
                        application_name,
                        client_addr,
                        state,
                        backend_start
                    FROM pg_stat_activity 
                    WHERE pid = pg_backend_pid();
                """)
                conn_info = cursor.fetchone()
                if conn_info:
                    app_name, client_addr, state, backend_start = conn_info
                    self.security_checks.append(f"Application: {app_name}")
                    self.security_checks.append(f"Client Address: {client_addr}")
                    self.security_checks.append(f"Connection State: {state}")
                
        except Exception as e:
            self.warnings.append(f"Could not verify connection security: {str(e)}")
    
    def _check_database_permissions(self):
        """Check database user permissions and security"""
        try:
            with connection.cursor() as cursor:
                # Check current user privileges
                cursor.execute("SELECT current_user, session_user;")
                current_user, session_user = cursor.fetchone()
                self.security_checks.append(f"Database User: {current_user}")
                
                # Check if user is superuser (should not be in production)
                cursor.execute("""
                    SELECT rolsuper, rolcreaterole, rolcreatedb 
                    FROM pg_roles 
                    WHERE rolname = current_user;
                """)
                privileges = cursor.fetchone()
                if privileges:
                    is_super, can_create_role, can_create_db = privileges
                    if is_super:
                        self.warnings.append("⚠️ Database user has superuser privileges")
                    if can_create_role:
                        self.warnings.append("Database user can create roles")
                    if can_create_db:
                        self.warnings.append("Database user can create databases")
                    
                    if not any([is_super, can_create_role, can_create_db]):
                        self.security_checks.append("✅ Database user has limited privileges")
                
                # Check database version
                cursor.execute("SELECT version();")
                version = cursor.fetchone()[0]
                self.security_checks.append(f"PostgreSQL Version: {version.split(',')[0]}")
                
        except Exception as e:
            self.warnings.append(f"Could not check database permissions: {str(e)}")
    
    def _generate_security_report(self):
        """Generate comprehensive security report"""
        logger.info("📊 Database Security Report:")
        
        if self.security_checks:
            logger.info("✅ Security Checks Passed:")
            for check in self.security_checks:
                logger.info(f"  • {check}")
        
        if self.warnings:
            logger.warning("⚠️ Security Warnings:")
            for warning in self.warnings:
                logger.warning(f"  • {warning}")
        
        if self.errors:
            logger.error("❌ Security Errors:")
            for error in self.errors:
                logger.error(f"  • {error}")
            return False
        
        # Overall security score
        total_checks = len(self.security_checks) + len(self.warnings) + len(self.errors)
        passed_checks = len(self.security_checks)
        
        if total_checks > 0:
            security_score = (passed_checks / total_checks) * 100
            logger.info(f"🔒 Database Security Score: {security_score:.1f}%")
            
            if security_score >= 80:
                logger.info("✅ Database security configuration is GOOD")
                return True
            elif security_score >= 60:
                logger.warning("⚠️ Database security configuration needs IMPROVEMENT")
                return True
            else:
                logger.error("❌ Database security configuration is POOR")
                return False
        
        return True


def validate_database_security():
    """
    Convenience function to validate database security
    """
    validator = DatabaseSecurityValidator()
    return validator.validate_connection_security()


class DatabaseSecurityMiddleware:
    """
    Middleware to monitor database connection security in real-time
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.security_checked = False
    
    def __call__(self, request):
        # Perform security check on first request
        if not self.security_checked:
            try:
                validate_database_security()
                self.security_checked = True
            except Exception as e:
                logger.error(f"Database security check failed: {str(e)}")
        
        response = self.get_response(request)
        return response


# Management command for database security validation
class Command(BaseCommand):
    """
    Django management command to validate database security
    Usage: python manage.py validate_db_security
    """
    help = 'Validate database connection security settings'
    
    def handle(self, *args, **options):
        self.stdout.write("🔒 Validating Database Security Configuration...")
        
        validator = DatabaseSecurityValidator()
        success = validator.validate_connection_security()
        
        if success:
            self.stdout.write(
                self.style.SUCCESS("✅ Database security validation completed successfully!")
            )
        else:
            self.stdout.write(
                self.style.ERROR("❌ Database security validation failed!")
            )
            return 1
        
        return 0