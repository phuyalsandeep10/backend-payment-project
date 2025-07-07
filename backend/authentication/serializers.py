from rest_framework import serializers, exceptions
from django.contrib.auth import authenticate
from .models import User, UserSession, Notification, Activity, UserNotificationPreferences
from user_agents import parse
from permissions.models import Role
from permissions.serializers import RoleSerializer
# from team.serializers import TeamSerializer # This is moved to prevent circular import
from django.utils.crypto import get_random_string
from django.contrib.auth.password_validation import validate_password

class UserLiteSerializer(serializers.ModelSerializer):
    """
    A lightweight serializer for User model, showing only essential info.
    """
    class Meta:
        model = User
        fields = ['id', 'username']

class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for the User model to match frontend expectations.
    """
    # Frontend expects explicit first_name / last_name / organization_name keys
    organization_name = serializers.CharField(source='organization.name', read_only=True)
    name = serializers.ReadOnlyField()
    phoneNumber = serializers.CharField(source='contact_number', allow_blank=True, required=False)
    assignedTeam = serializers.SerializerMethodField()
    permissions = serializers.SerializerMethodField()
    role = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            'id', 'name', 'first_name', 'last_name', 'email', 'phoneNumber', 'role', 'assignedTeam',
            'status', 'avatar', 'permissions', 'organization_name', 'is_active', 'address', 'createdAt', 'updatedAt'
        ]

    # Explicitly declare serializer-only fields not present on the model so DRF
    # doesn't raise a FieldError during serialization.
    createdAt = serializers.SerializerMethodField()
    updatedAt = serializers.SerializerMethodField()

    def get_assignedTeam(self, obj):
        """Return team name as string to match frontend expectations"""
        return obj.team.name if obj.team else None

    def get_permissions(self, obj):
        """Get user permissions from role"""
        if obj.role:
            from permissions.serializers import PermissionSerializer
            return PermissionSerializer(obj.role.permissions.all(), many=True).data
        return []

    def get_role(self, obj):
        """Return role name as string to match frontend expectations"""
        if obj.role:
            # Map backend roles to frontend role expectations
            role_mapping = {
                'Super Admin': 'super-admin',
                'Org Admin': 'org-admin',
                'Admin': 'org-admin',  # Support both "Org Admin" and "Admin" role names
                'Salesperson': 'salesperson',
                'Supervisor': 'supervisor',
                'Verifier': 'verifier',
                'Team Member': 'team-member',
            }
            return role_mapping.get(obj.role.name, 'team-member')
        return 'team-member'

    def get_createdAt(self, obj):
        return obj.date_joined.isoformat() if obj.date_joined else None

    def get_updatedAt(self, obj):
        return obj.last_login.isoformat() if obj.last_login else None

    def to_representation(self, instance):
        return super().to_representation(instance)

class UserCreateSerializer(serializers.ModelSerializer):
    """
    Serializer for creating a new user.
    """
    org_role = serializers.PrimaryKeyRelatedField(queryset=Role.objects.all(), required=False, allow_null=True)
    phoneNumber = serializers.CharField(source='contact_number', allow_blank=True, required=False)
    
    class Meta:
        model = User
        fields = ('username', 'password', 'first_name', 'last_name', 'email', 'organization', 'org_role', 'team', 'phoneNumber', 'is_active', 'status', 'avatar')
        extra_kwargs = {'password': {'write_only': True, 'required': False}}

    def create(self, validated_data):
        """Create a new user while handling role assignment, password generation,
        welcome email delivery and must_change_password flag."""

        from permissions.models import Role  # Local import to avoid circular deps
        from django.core.mail import send_mail
        from django.conf import settings

        request_data = self.context.get('request').data if self.context.get('request') else {}

        # --- Handle role mapping ------------------------------------------------
        role = validated_data.pop('org_role', None)
        role_name = request_data.get('role_name')

        if not role and role_name:
            role = Role.objects.filter(name__iexact=role_name.strip()).first()

        if role is not None:
            validated_data['role'] = role

        # --- Password handling --------------------------------------------------
        password = validated_data.get('password') or get_random_string(length=12)
        validated_data['password'] = password

        # Ensure username is set (fallback to email prefix)
        if not validated_data.get('username'):
            validated_data['username'] = validated_data['email'].split('@')[0]

        # Create user instance via custom manager (hashes password internally)
        user = User.objects.create_user(**validated_data)

        # --- Post-creation flags -------------------------------------------------
        def _norm(name: str | None) -> str:
            return name.lower().replace(' ', '').replace('-', '') if name else ''

        if role and _norm(role.name) in ['orgadmin', 'admin']:
            user.must_change_password = True  # Org admins forced to change pwd
            user.save(update_fields=['must_change_password'])

        # --- Send welcome email --------------------------------------------------
        subject = 'Welcome to Payment Receiving System'
        message = (
            f"Hello {user.first_name or user.username},\n\n"
            f"Your PRS account has been created successfully.\n\n"
            f"Email: {user.email}\n"
            f"Password: {password}\n\n"
            "You can log in using the link below and start using the platform right away.\n"
            f"{getattr(settings, 'FRONTEND_LOGIN_URL', 'http://localhost:3000/login')}\n\n"
            "For security, please keep this information confidential."
        )

        # Fail silently so that user creation succeeds even if email mis-configured.
        send_mail(
            subject,
            message,
            getattr(settings, 'DEFAULT_FROM_EMAIL', 'no-reply@prs.local'),
            [user.email],
            fail_silently=True,
        )

        return user

class UserSessionSerializer(serializers.ModelSerializer):
    """
    Serializer for the UserSession model.
    Parses the user agent string into a readable format.
    """
    device = serializers.SerializerMethodField()

    class Meta:
        model = UserSession
        fields = ['id', 'ip_address', 'created_at', 'device']
        read_only_fields = fields

    def get_device(self, obj):
        if not obj.user_agent:
            return "Unknown Device"
        ua = parse(obj.user_agent)
        return f"{ua.browser.family} on {ua.os.family}"
    
    def to_representation(self, instance):
        """
        Add a flag to indicate if the session is the current one.
        """
        representation = super().to_representation(instance)
        current_session_key = self.context['request'].session.session_key
        # Note: DRF Token Auth is stateless, so we check against the token key
        auth_header = self.context['request'].headers.get('Authorization')
        if auth_header:
            try:
                current_token_key = auth_header.split(' ')[1]
                representation['is_current_session'] = (instance.session_key == current_token_key)
            except IndexError:
                representation['is_current_session'] = False
        else:
            representation['is_current_session'] = False
        return representation


class NotificationSerializer(serializers.ModelSerializer):
    """
    Serializer for notifications to match frontend expectations
    """
    timestamp = serializers.DateTimeField(source='created_at', read_only=True)
    isRead = serializers.BooleanField(source='is_read')
    userId = serializers.CharField(source='user.id', read_only=True)
    actionUrl = serializers.URLField(source='action_url', allow_blank=True, required=False)

    class Meta:
        model = Notification
        fields = ['id', 'title', 'message', 'type', 'timestamp', 'isRead', 'userId', 'actionUrl', 'createdAt', 'updatedAt']

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['createdAt'] = instance.created_at.isoformat()
        representation['updatedAt'] = instance.updated_at.isoformat()
        return representation


class ActivitySerializer(serializers.ModelSerializer):
    """
    Serializer for activities to match frontend expectations
    """
    class Meta:
        model = Activity
        fields = ['timestamp', 'description', 'type']


class LoginSerializer(serializers.Serializer):
    """
    Serializer for the login endpoint.
    """
    email = serializers.EmailField(required=True)
    password = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'}
    )

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        if email and password:
            # Since the custom User model sets `USERNAME_FIELD = "email"`,
            # Django's default `ModelBackend` still expects the credential to be
            # passed via the `username` keyword argument. Passing `email=`
            # will always return `None`, resulting in 401 responses even for valid
            # users. Therefore, forward the email value using the `username`
            # kw-arg so that authentication succeeds.
            user = authenticate(
                request=self.context.get('request'),
                username=email,  # `username` refers to the field defined by `USERNAME_FIELD`
                password=password
            )
            if not user:
                msg = 'Unable to log in with provided credentials.'
                raise exceptions.AuthenticationFailed(msg, code='authorization')
        else:
            msg = 'Must include "email" and "password".'
            raise exceptions.AuthenticationFailed(msg, code='authorization')

        attrs['user'] = user
        return attrs


class DashboardStatsSerializer(serializers.Serializer):
    """
    Serializer for dashboard statistics
    """
    totalUsers = serializers.IntegerField()
    totalClients = serializers.IntegerField()
    totalTeams = serializers.IntegerField()
    totalCommission = serializers.DecimalField(max_digits=12, decimal_places=2)
    recentActivities = ActivitySerializer(many=True)
    notifications = NotificationSerializer(many=True)

class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for user profile management (account settings).
    """
    name = serializers.ReadOnlyField()
    phoneNumber = serializers.CharField(source='contact_number', allow_blank=True, required=False)
    role = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = ['id', 'name', 'first_name', 'last_name', 'email', 'phoneNumber', 'address', 'avatar', 'role']
        read_only_fields = ['id', 'email', 'role']  # Email and role cannot be changed by user
    
    def get_role(self, obj):
        """Return role name as string to match frontend expectations"""
        if obj.role:
            # Map backend roles to frontend role expectations
            role_mapping = {
                'Super Admin': 'super-admin',
                'Org Admin': 'org-admin',
                'Admin': 'org-admin',  # Support both "Org Admin" and "Admin" role names
                'Salesperson': 'salesperson',
                'Supervisor': 'supervisor',
                'Verifier': 'verifier',
                'Team Member': 'team-member',
            }
            return role_mapping.get(obj.role.name, 'team-member')
        return 'team-member'
    
    def update(self, instance, validated_data):
        """Update user profile fields"""
        # Handle contact_number mapping
        if 'contact_number' in validated_data:
            instance.contact_number = validated_data.pop('contact_number')
        
        # Update other fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        
        instance.save()
        return instance

class ChangePasswordSerializer(serializers.Serializer):
    """
    Serializer for changing password for authenticated users.
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
    
    def validate_new_password(self, value):
        """Validate new password using Django's password validators"""
        user = self.context['request'].user
        validate_password(value, user)
        return value
    
    def validate(self, attrs):
        """Validate that new password and confirm password match"""
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError("New password and confirm password do not match.")
        return attrs
    
    def save(self):
        """Change the user's password"""
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()
        return user

class UserNotificationPreferencesSerializer(serializers.ModelSerializer):
    """
    Serializer for user notification preferences.
    """
    # Map backend field names to frontend expectations
    desktopNotification = serializers.BooleanField(source='desktop_notifications')
    unreadNotificationBadge = serializers.BooleanField(source='unread_badge')
    pushNotificationTimeout = serializers.CharField(source='push_timeout')
    communicationEmails = serializers.BooleanField(source='communication_emails')
    announcementsUpdates = serializers.BooleanField(source='announcements_updates')
    allNotificationSounds = serializers.BooleanField(source='notification_sounds')
    
    class Meta:
        model = UserNotificationPreferences
        fields = [
            'desktopNotification', 'unreadNotificationBadge', 'pushNotificationTimeout',
            'communicationEmails', 'announcementsUpdates', 'allNotificationSounds'
        ]
    
    def update(self, instance, validated_data):
        """Update notification preferences"""
        # Handle field mapping
        field_mapping = {
            'desktop_notifications': validated_data.get('desktop_notifications'),
            'unread_badge': validated_data.get('unread_badge'),
            'push_timeout': validated_data.get('push_timeout'),
            'communication_emails': validated_data.get('communication_emails'),
            'announcements_updates': validated_data.get('announcements_updates'),
            'notification_sounds': validated_data.get('notification_sounds'),
        }
        
        for field, value in field_mapping.items():
            if value is not None:
                setattr(instance, field, value)
        
        instance.save()
        return instance