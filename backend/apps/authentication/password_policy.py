"""
Enhanced Password Policy Management System
Provides organization-specific password policies and validation
"""

import re
import logging
from datetime import datetime, timedelta
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.conf import settings
from django.core.cache import cache
from apps.organization.models import Organization

# Security logger
security_logger = logging.getLogger('security')

class PasswordPolicy:
    """
    Password policy configuration for organizations
    """
    
    # Default policy settings
    DEFAULT_POLICY = {
        'min_length': 8,
        'max_length': 128,
        'require_uppercase': True,
        'require_lowercase': True,
        'require_numbers': True,
        'require_special_chars': True,
        'min_special_chars': 1,
        'forbidden_patterns': [
            'password', '123456', 'qwerty', 'admin', 'user',
            'login', 'welcome', 'default', 'temp'
        ],
        'max_repeated_chars': 3,
        'prevent_common_passwords': True,
        'password_history_count': 5,  # Remember last 5 passwords
        'expiration_days': 90,  # Password expires after 90 days
        'warning_days': 7,  # Warn user 7 days before expiration
        'max_failed_attempts': 5,
        'lockout_duration_minutes': 30,
        'allow_username_in_password': False,
        'allow_email_in_password': False,
    }
    
    # Organization-specific policies (can be stored in database later)
    ORGANIZATION_POLICIES = {}
    
    @classmethod
    def get_policy_for_organization(cls, organization_id):
        """
        Get password policy for a specific organization
        Uses caching for better performance
        """
        if not organization_id:
            return cls.DEFAULT_POLICY.copy()
        
        cache_key = f"password_policy_{organization_id}"
        policy = cache.get(cache_key)
        
        if policy is None:
            # For now, use default policy for all organizations
            # In the future, this could be stored in database
            policy = cls.DEFAULT_POLICY.copy()
            
            # Cache for 1 hour
            cache.set(cache_key, policy, 3600)
            
        return policy
    
    @classmethod
    def validate_password(cls, password, user=None, organization_id=None):
        """
        Validate password against organization policy
        
        Args:
            password: Password to validate
            user: User object (optional, for additional checks)
            organization_id: Organization ID (optional)
            
        Returns:
            dict: Validation result with success status and errors
        """
        if user and hasattr(user, 'organization') and user.organization:
            organization_id = user.organization.id
        
        policy = cls.get_policy_for_organization(organization_id)
        errors = []
        
        # Length validation
        if len(password) < policy['min_length']:
            errors.append(f"Password must be at least {policy['min_length']} characters long")
        
        if len(password) > policy['max_length']:
            errors.append(f"Password must not exceed {policy['max_length']} characters")
        
        # Character requirements
        if policy['require_uppercase'] and not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        if policy['require_lowercase'] and not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        if policy['require_numbers'] and not re.search(r'\d', password):
            errors.append("Password must contain at least one number")
        
        if policy['require_special_chars']:
            special_chars = re.findall(r'[!@#$%^&*(),.?":{}|<>]', password)
            if len(special_chars) < policy['min_special_chars']:
                errors.append(f"Password must contain at least {policy['min_special_chars']} special character(s)")
        
        # Forbidden patterns
        password_lower = password.lower()
        for pattern in policy['forbidden_patterns']:
            if pattern.lower() in password_lower:
                errors.append(f"Password cannot contain common words like '{pattern}'")
        
        # Repeated characters
        if policy['max_repeated_chars'] > 0:
            for i in range(len(password) - policy['max_repeated_chars']):
                if len(set(password[i:i+policy['max_repeated_chars']+1])) == 1:
                    errors.append(f"Password cannot have more than {policy['max_repeated_chars']} repeated characters")
                    break
        
        # User-specific validations
        if user:
            if not policy['allow_username_in_password'] and user.username:
                if user.username.lower() in password_lower:
                    errors.append("Password cannot contain your username")
            
            if not policy['allow_email_in_password'] and user.email:
                email_parts = user.email.split('@')[0].lower()
                if email_parts in password_lower:
                    errors.append("Password cannot contain parts of your email address")
        
        # Common passwords check
        if policy['prevent_common_passwords']:
            if cls._is_common_password(password):
                errors.append("This password is too common. Please choose a more unique password")
        
        return {
            'is_valid': len(errors) == 0,
            'errors': errors,
            'policy': policy
        }
    
    @classmethod
    def _is_common_password(cls, password):
        """
        Check if password is in common passwords list
        """
        common_passwords = [
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', 'monkey',
            'dragon', 'master', 'shadow', 'qwerty123', 'password1'
        ]
        return password.lower() in common_passwords
    
    @classmethod
    def check_password_expiration(cls, user):
        """
        Check if user's password is expired or expiring soon
        
        Returns:
            dict: Expiration status information
        """
        if not user or not hasattr(user, 'organization'):
            return {'expired': False, 'expires_soon': False}
        
        organization_id = user.organization.id if user.organization else None
        policy = cls.get_policy_for_organization(organization_id)
        
        if not policy['expiration_days'] or policy['expiration_days'] <= 0:
            return {'expired': False, 'expires_soon': False}
        
        # Get last password change date
        last_password_change = getattr(user, 'password_changed_at', user.date_joined)
        if not last_password_change:
            last_password_change = user.date_joined
        
        # Calculate expiration date
        expiration_date = last_password_change + timedelta(days=policy['expiration_days'])
        warning_date = expiration_date - timedelta(days=policy['warning_days'])
        
        now = timezone.now()
        
        return {
            'expired': now > expiration_date,
            'expires_soon': now > warning_date and now <= expiration_date,
            'expiration_date': expiration_date,
            'days_until_expiration': (expiration_date - now).days,
            'last_password_change': last_password_change
        }
    
    @classmethod
    def generate_secure_password(cls, organization_id=None, length=12):
        """
        Generate a secure password that meets organization policy
        """
        import secrets
        import string
        
        policy = cls.get_policy_for_organization(organization_id)
        
        # Ensure minimum length
        length = max(length, policy['min_length'])
        
        # Character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = "!@#$%^&*(),.?\":{}|<>"
        
        # Ensure required character types are included
        password_chars = []
        
        if policy['require_lowercase']:
            password_chars.append(secrets.choice(lowercase))
        
        if policy['require_uppercase']:
            password_chars.append(secrets.choice(uppercase))
        
        if policy['require_numbers']:
            password_chars.append(secrets.choice(digits))
        
        if policy['require_special_chars']:
            for _ in range(policy['min_special_chars']):
                password_chars.append(secrets.choice(special))
        
        # Fill remaining length with random characters
        all_chars = lowercase + uppercase + digits + special
        remaining_length = length - len(password_chars)
        
        for _ in range(remaining_length):
            password_chars.append(secrets.choice(all_chars))
        
        # Shuffle the password
        secrets.SystemRandom().shuffle(password_chars)
        password = ''.join(password_chars)
        
        # Validate the generated password
        validation = cls.validate_password(password, organization_id=organization_id)
        
        if not validation['is_valid']:
            # If somehow the generated password doesn't meet policy, try again
            return cls.generate_secure_password(organization_id, length)
        
        return password
    
    @classmethod
    def get_password_strength_score(cls, password, user=None, organization_id=None):
        """
        Calculate password strength score (0-100)
        """
        score = 0
        
        # Length scoring
        if len(password) >= 8:
            score += 20
        if len(password) >= 12:
            score += 10
        if len(password) >= 16:
            score += 10
        
        # Character variety scoring
        if re.search(r'[a-z]', password):
            score += 10
        if re.search(r'[A-Z]', password):
            score += 10
        if re.search(r'\d', password):
            score += 10
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 15
        
        # Complexity scoring
        unique_chars = len(set(password))
        if unique_chars >= len(password) * 0.7:
            score += 10
        
        # Penalty for common patterns
        if cls._is_common_password(password):
            score -= 30
        
        # Penalty for repeated characters
        max_repeated = max([password.count(c) for c in set(password)])
        if max_repeated > 2:
            score -= (max_repeated - 2) * 5
        
        return max(0, min(100, score))


class PasswordHistoryManager:
    """
    Manages password history for users to prevent reuse
    """
    
    @classmethod
    def add_password_to_history(cls, user, password_hash):
        """
        Add password hash to user's history
        """
        from .models import PasswordHistory
        
        # Get organization policy
        organization_id = user.organization.id if user.organization else None
        policy = PasswordPolicy.get_policy_for_organization(organization_id)
        
        if policy['password_history_count'] <= 0:
            return
        
        # Add new password to history
        PasswordHistory.objects.create(
            user=user,
            password_hash=password_hash,
            created_at=timezone.now()
        )
        
        # Remove old passwords beyond history limit
        old_passwords = PasswordHistory.objects.filter(
            user=user
        ).order_by('-created_at')[policy['password_history_count']:]
        
        for old_password in old_passwords:
            old_password.delete()
    
    @classmethod
    def check_password_reuse(cls, user, new_password):
        """
        Check if password was used recently
        """
        from .models import PasswordHistory
        from django.contrib.auth.hashers import check_password
        
        organization_id = user.organization.id if user.organization else None
        policy = PasswordPolicy.get_policy_for_organization(organization_id)
        
        if policy['password_history_count'] <= 0:
            return False
        
        # Check against recent passwords
        recent_passwords = PasswordHistory.objects.filter(
            user=user
        ).order_by('-created_at')[:policy['password_history_count']]
        
        for password_record in recent_passwords:
            if check_password(new_password, password_record.password_hash):
                return True
        
        return False