from django.shortcuts import render
from rest_framework import viewsets, generics, status, permissions
from rest_framework.response import Response
from rest_framework.permissions import IsAdminUser
from .models import Organization
from .serializers import OrganizationSerializer, OrganizationRegistrationSerializer
from django.db import transaction
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from authentication.models import User
from authentication.serializers import AuthSuccessResponseSerializer
from permissions.models import Role
from .permissions import IsOrganizationMember

# Create your views here.

class OrganizationViewSet(viewsets.ModelViewSet):
    """
    A viewset for super admins to manage organizations.
    Regular users can view their own organization.
    """
    queryset = Organization.objects.all().prefetch_related('roles')
    serializer_class = OrganizationSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]

    def get_queryset(self):
        """
        Admins can see all organizations.
        Regular users can only see their own organization in the list view.
        """
        # Short-circuit for schema generation
        if getattr(self, 'swagger_fake_view', False):
            return Organization.objects.none()

        user = self.request.user
        if user.is_staff:
            return Organization.objects.all().prefetch_related('roles')
        if user.organization:
            return Organization.objects.filter(pk=user.organization.pk).prefetch_related('roles')
        return Organization.objects.none()

class OrganizationRegistrationView(APIView):
    """
    A public endpoint for registering a new organization and its first admin user.
    """
    authentication_classes = []
    permission_classes = [permissions.AllowAny]

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        serializer = OrganizationRegistrationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        validated_data = serializer.validated_data
        
        try:
            # Step 1: Get the system-wide 'Org_admin' role.
            org_admin_role = Role.objects.get(name='Org_admin', organization__isnull=True)
        except Role.DoesNotExist:
            return Response(
                {"error": "The default 'Org_admin' role has not been created. Please run migrations."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        # Step 2: Create the Organization.
        organization = Organization.objects.create(
            name=validated_data['name'],
            description=validated_data.get('description', ''),
            created_by=None  # A super-admin can be assigned this later if needed
        )

        # Step 3: Create the admin User for the Organization.
        admin_user = User.objects.create_user(
            email=validated_data['admin_email'],
            username=validated_data['admin_email'], # Default username to email
            first_name=validated_data['admin_first_name'],
            last_name=validated_data['admin_last_name'],
            password=validated_data['admin_password'],
            organization=organization,
            role=org_admin_role
        )

        # Step 4: Generate a token for the new admin user.
        token, _ = Token.objects.get_or_create(user=admin_user)

        # Step 5: Return a standard success response.
        response_serializer = AuthSuccessResponseSerializer({'token': token, 'user': admin_user})
        return Response(response_serializer.data, status=status.HTTP_201_CREATED)
