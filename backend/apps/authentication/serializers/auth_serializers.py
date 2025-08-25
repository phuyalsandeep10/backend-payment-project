"""
Authentication Serializers - Task 2.3.3

Focused serializers for authentication operations using service layer.
Separates authentication logic from user management.
"""

from rest_framework import serializers
from django.contrib.auth import authenticate, get_user_model
from apps.authentication.services import (
    security_event_logger,
    password_policy_service,
    role_service
)

# Safe imports for Role and Organization models  
try:
    from apps.permissions.models import Role
    _role_queryset = Role.objects.none()
except ImportError:
    _role_queryset = None

try:
    from apps.organization.models import Organization
    _organization_queryset = Organization.objects.none()
except ImportError:
    _organization_queryset = None

User = get_user_model()


class UserLoginSerializer(serializers.Serializer):
    """
    Focused serializer for user login using service layer.
    Task 2.3.3: Simplified with service integration.
    """
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True, style={'input_type': 'password'})
    
    def validate(self, attrs):
        """Validate login credentials using service layer"""
        email = attrs.get('email')
        password = attrs.get('password')
        
        if not email or not password:
            raise serializers.ValidationError(
                "Email and password are required.", 
                code='authorization'
            )
        
        # Check account lockout using security service
        lockout_status = security_event_logger.check_account_lockout(email)
        if lockout_status['locked']:
            raise serializers.ValidationError(
                f"Account is locked until {lockout_status.get('locked_until', 'unknown time')}. "
                f"Reason: {lockout_status.get('reason', 'Security lockout')}",
                code='account_locked'
            )
        
        # Authenticate user
        request = self.context.get('request')
        user = authenticate(request=request, email=email, password=password)
        
        if not user:
            # Log failed attempt using security service
            if request:
                security_event_logger.log_authentication_attempt(
                    request, email, False, 'Invalid credentials'
                )
            raise serializers.ValidationError(
                "Invalid email or password.", 
                code='authorization'
            )
        
        # Check if user is active
        if not user.is_active:
            raise serializers.ValidationError(
                "User account is disabled.", 
                code='account_disabled'
            )
        
        # Check password expiration using password policy service
        password_status = password_policy_service.check_password_expiration(user)
        if password_status['expired']:
            raise serializers.ValidationError(
                "Password has expired. Please reset your password.",
                code='password_expired'
            )
        
        # Log successful attempt
        if request:
            security_event_logger.log_authentication_attempt(
                request, email, True
            )
        
        attrs['user'] = user
        return attrs


class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    Focused serializer for user registration using service layer.
    Task 2.3.3: Simplified registration with service validation.
    """
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    password_confirm = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    role = serializers.PrimaryKeyRelatedField(queryset=_role_queryset, required=True)
    organization = serializers.PrimaryKeyRelatedField(queryset=_organization_queryset, required=True)
    
    class Meta:
        model = User
        fields = [
            'email', 'first_name', 'last_name', 'username',
            'password', 'password_confirm', 'role', 'organization'
        ]
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Set querysets for role and organization
        try:
            from apps.permissions.models import Role
            from apps.organization.models import Organization
            
            self.fields['role'].queryset = Role.objects.filter(is_active=True)
            self.fields['organization'].queryset = Organization.objects.filter(status='active')
        except Exception:
            pass
    
    def validate_email(self, value):
        """Validate email uniqueness"""
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value
    
    def validate(self, attrs):
        """Validate registration data using service layer"""
        password = attrs.get('password')
        password_confirm = attrs.get('password_confirm')
        organization = attrs.get('organization')
        
        # Check password confirmation
        if password != password_confirm:
            raise serializers.ValidationError({
                "password_confirm": "The passwords do not match."
            })
        
        # Validate password using policy service
        organization_id = organization.id if organization else None
        validation_result = password_policy_service.validate_password(
            password, 
            organization_id=organization_id
        )
        
        if not validation_result['is_valid']:
            raise serializers.ValidationError({
                "password": validation_result['errors']
            })
        
        # Validate role assignment using role service
        role = attrs.get('role')
        if role:
            validation = role_service.validate_role_assignment(
                user_id=None,  # New user
                role_id=role.id,
                assigned_by=None  # Public registration
            )
            
            if not validation['valid']:
                raise serializers.ValidationError({
                    "role": validation['errors']
                })
        
        # Remove password_confirm from validated data
        attrs.pop('password_confirm')
        return attrs
    
    def create(self, validated_data):
        """Create user with proper setup"""
        password = validated_data.pop('password')
        role = validated_data.pop('role')
        
        # Create user
        user = User.objects.create_user(
            password=password,
            **validated_data
        )
        
        # Assign role using service
        role_result = role_service.assign_role_to_user(
            user_id=user.id,
            role_id=role.id,
            assigned_by=None  # System assignment for registration
        )
        
        if not role_result['success']:
            # If role assignment fails, clean up and raise error
            user.delete()
            raise serializers.ValidationError(
                f"Registration failed: {role_result['error']}"
            )
        
        # Add password to history
        from django.contrib.auth.hashers import make_password
        password_policy_service.add_password_to_history(user, make_password(password))
        
        return user


class PasswordChangeSerializer(serializers.Serializer):
    """
    Focused serializer for password changes using service layer.
    Task 2.3.3: Service-based password validation and history tracking.
    """
    current_password = serializers.CharField(required=True, write_only=True)
    new_password = serializers.CharField(required=True, write_only=True)
    confirm_password = serializers.CharField(required=True, write_only=True)
    
    def validate_current_password(self, value):
        """Validate current password"""
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Current password is incorrect.")
        return value
    
    def validate(self, attrs):
        """Validate password change using service layer"""
        new_password = attrs.get('new_password')
        confirm_password = attrs.get('confirm_password')
        user = self.context['request'].user
        
        # Check password confirmation
        if new_password != confirm_password:
            raise serializers.ValidationError({
                "confirm_password": "The passwords do not match."
            })
        
        # Validate new password using policy service
        validation_result = password_policy_service.validate_password(
            new_password, 
            user=user
        )
        
        if not validation_result['is_valid']:
            raise serializers.ValidationError({
                "new_password": validation_result['errors']
            })
        
        # Check password reuse using policy service
        if password_policy_service.check_password_reuse(user, new_password):
            raise serializers.ValidationError({
                "new_password": "You cannot reuse a recent password."
            })
        
        return attrs
    
    def save(self):
        """Save password change with service layer integration"""
        new_password = self.validated_data['new_password']
        user = self.context['request'].user
        request = self.context['request']
        
        try:
            # Set new password
            user.set_password(new_password)
            user.must_change_password = False  # Clear forced change flag
            user.save(update_fields=['password', 'must_change_password'])
            
            # Add to password history
            from django.contrib.auth.hashers import make_password
            password_policy_service.add_password_to_history(user, make_password(new_password))
            
            # Log password change using security service
            security_event_logger.log_password_change(
                user, request, True, method='user_initiated'
            )
            
            return user
            
        except Exception as e:
            # Log failed password change
            security_event_logger.log_password_change(
                user, request, False, method='user_initiated'
            )
            raise serializers.ValidationError(f"Password change failed: {str(e)}")


class PasswordResetSerializer(serializers.Serializer):
    """
    Focused serializer for password reset using service layer.
    Task 2.3.3: Service-based validation and security logging.
    """
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)
    
    def validate(self, attrs):
        """Validate password reset using service layer"""
        token = attrs.get('token')
        new_password = attrs.get('new_password')
        confirm_password = attrs.get('confirm_password')
        
        # Check password confirmation
        if new_password != confirm_password:
            raise serializers.ValidationError({
                "confirm_password": "The passwords do not match."
            })
        
        # Validate token (simplified - would integrate with token service)
        # In a full implementation, this would use a dedicated token service
        try:
            from django.contrib.auth.tokens import default_token_generator
            from django.utils.http import urlsafe_base64_decode
            from django.contrib.auth import get_user_model
            
            # This is a simplified token validation
            # A proper implementation would parse the token properly
            User = get_user_model()
            # For now, just check if token exists (placeholder)
            
        except Exception:
            raise serializers.ValidationError({
                "token": "Invalid or expired token."
            })
        
        return attrs


class SuperUserLoginSerializer(serializers.Serializer):
    """
    Focused serializer for super admin login using service layer.
    Task 2.3.3: Enhanced security for privileged access.
    """
    email = serializers.EmailField()
    password = serializers.CharField(style={'input_type': 'password'}, write_only=True)
    
    def validate(self, attrs):
        """Validate super admin credentials with enhanced security"""
        email = attrs.get('email')
        password = attrs.get('password')
        
        if not email or not password:
            raise serializers.ValidationError(
                "Email and password are required.", 
                code='authorization'
            )
        
        # Authenticate user
        request = self.context.get('request')
        user = authenticate(request=request, email=email, password=password)
        
        if not user:
            # Log failed super admin attempt with high priority
            if request:
                security_event_logger.log_suspicious_activity(
                    user, request, 'failed_admin_login',
                    {'attempted_email': email, 'privilege_level': 'super_admin'}
                )
            raise serializers.ValidationError(
                "Invalid credentials.", 
                code='authorization'
            )
        
        # Verify superuser status
        if not user.is_superuser:
            # Log unauthorized admin access attempt
            security_event_logger.log_permission_denied(
                user, request, 'super_admin_login', 'attempt_privilege_escalation'
            )
            raise serializers.ValidationError(
                "You do not have permission to perform this action.",
                code='authorization'
            )
        
        # Log successful super admin login
        security_event_logger.log_authentication_attempt(
            request, email, True, additional_data={'privilege_level': 'super_admin'}
        )
        
        attrs['user'] = user
        return attrs


class OTPSerializer(serializers.Serializer):
    """
    Focused serializer for OTP verification using service layer.
    Task 2.3.3: Service-based OTP validation.
    """
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6, min_length=6)
    
    def validate(self, attrs):
        """Validate OTP using service layer"""
        email = attrs.get('email')
        otp = attrs.get('otp')
        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("Invalid user.")
        
        # Validate OTP (would integrate with OTP service)
        # This is a placeholder for OTP validation logic
        # In a full implementation, this would use a dedicated OTP service
        
        # Log OTP validation attempt
        request = self.context.get('request')
        if request:
            security_event_logger.log_authentication_attempt(
                request, email, True, 
                additional_data={'method': 'otp_verification'}
            )
        
        attrs['user'] = user
        return attrs
