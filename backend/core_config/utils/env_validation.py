import os
import sys
from typing import Dict, Any, Optional

class EnvironmentValidator:
    """Validate required environment variables on startup"""
    
    REQUIRED_VARS = {
        'SECRET_KEY': 'Django secret key',
        'DB_NAME': 'Database name',
        'DB_USER': 'Database user',
        'DB_PASSWORD': 'Database password',
        'DB_HOST': 'Database host',
        'DB_PORT': 'Database port',
    }
    
    OPTIONAL_VARS = {
        'DEBUG': 'Debug mode (default: False)',
        'REDIS_URL': 'Redis URL for caching',
        'EMAIL_HOST': 'SMTP host for emails',
        'EMAIL_PORT': 'SMTP port',
        'EMAIL_HOST_USER': 'SMTP username',
        'EMAIL_HOST_PASSWORD': 'SMTP password',
    }
    
    @classmethod
    def validate(cls) -> Dict[str, Any]:
        """Validate all environment variables"""
        errors = []
        warnings = []
        
        # Check required variables
        for var, description in cls.REQUIRED_VARS.items():
            value = os.getenv(var)
            if not value:
                errors.append(f"Missing required environment variable: {var} ({description})")
        
        # Check optional variables
        for var, description in cls.OPTIONAL_VARS.items():
            value = os.getenv(var)
            if not value:
                warnings.append(f"Optional environment variable not set: {var} ({description})")
        
        # Validate specific formats
        if os.getenv('DB_PORT'):
            try:
                port = int(os.getenv('DB_PORT'))
                if not (1 <= port <= 65535):
                    errors.append("DB_PORT must be between 1 and 65535")
            except ValueError:
                errors.append("DB_PORT must be a valid integer")
        
        if os.getenv('DEBUG'):
            debug_val = os.getenv('DEBUG').lower()
            if debug_val not in ['true', 'false', '1', '0']:
                warnings.append("DEBUG should be 'true' or 'false'")
        
        # Print results
        if errors:
            print("❌ Environment Validation Errors:")
            for error in errors:
                print(f"   {error}")
            sys.exit(1)
        
        if warnings:
            print("⚠️  Environment Validation Warnings:")
            for warning in warnings:
                print(f"   {warning}")
        
        print("✅ Environment validation passed")
        return {
            'errors': errors,
            'warnings': warnings,
            'valid': len(errors) == 0
        }

# Validate on import
if __name__ != '__main__':
    EnvironmentValidator.validate()