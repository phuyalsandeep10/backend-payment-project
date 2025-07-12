from django.shortcuts import render
from rest_framework import viewsets, generics, status, permissions
from rest_framework.response import Response
from rest_framework.permissions import IsAdminUser
from .models import Organization
from .serializers import OrganizationSerializer, OrganizationRegistrationSerializer, OrganizationWithAdminSerializer
from django.db import transaction
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from authentication.models import User
from authentication.serializers import AuthSuccessResponseSerializer
from permissions.models import Role
from .permissions import IsOrganizationMember
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from permissions.permissions import IsSuperAdmin

# Create your views here.

class OrganizationViewSet(viewsets.ModelViewSet):
    """
    A viewset for super admins to manage organizations.
    Regular users can view their own organization.
    """
    queryset = Organization.objects.all().prefetch_related('roles')
    serializer_class = OrganizationSerializer
    permission_classes = [IsSuperAdmin]

    def get_queryset(self):
        """
        Admins can see all organizations.
        Regular users can only see their own organization in the list view.
        """
        # Short-circuit for schema generation
        if getattr(self, 'swagger_fake_view', False):
            return Organization.objects.none()

        user = self.request.user
        if user.is_staff or user.is_superuser:
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
            # Step 1: Get the system-wide 'Org Admin' role.
            org_admin_role = Role.objects.get(name='Org Admin', organization__isnull=True)
        except Role.DoesNotExist:
            return Response(
                {"error": "The default 'Org Admin' role has not been created. Please run migrations."},
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

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_innovate_organization_id(request):
    """
    Returns the ID of the 'Innovate Inc.' organization.
    """
    try:
        org = Organization.objects.get(name="Innovate Inc.")
        return Response({"id": org.id})
    except Organization.DoesNotExist:
        return Response({"error": "Organization not found"}, status=status.HTTP_404_NOT_FOUND)

class OrganizationWithAdminCreateView(APIView):
    permission_classes = [IsSuperAdmin]

    def post(self, request):
        serializer = OrganizationWithAdminSerializer(data=request.data)
        if serializer.is_valid():
            result = serializer.save()
            org = result['organization']
            admin_user = result['admin_user']
            from django.conf import settings
            resp_data = {
                'organization': OrganizationSerializer(org).data,
                'admin_user': {
                    'id': admin_user.id,
                    'email': admin_user.email,
                    'first_name': admin_user.first_name,
                    'last_name': admin_user.last_name,
                }
            }

            # In development/testing surface the password so the frontend can display it
            if getattr(settings, 'DEBUG', False):
                resp_data['admin_credentials'] = {
                    'email': admin_user.email,
                    'password': serializer.validated_data.get('admin_password')
                }
                import logging
                logging.getLogger('security').info(
                    f"[DEV] Created Org Admin creds -> Email: {admin_user.email} Password: {serializer.validated_data.get('admin_password')}"
                )

            return Response(resp_data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# ==================== Frontend top-level alias ====================

@api_view(['GET', 'POST'])
@permission_classes([IsSuperAdmin])
def organizations_alias(request):
    """Compatibility endpoint for /api/organizations/

    GET -> delegates to OrganizationViewSet.list (list all orgs)
    POST -> delegates to OrganizationWithAdminCreateView (create org + admin)
    """
    if request.method == 'GET':
        list_view = OrganizationViewSet.as_view({'get': 'list'})
        return list_view(request._request)

    # Decide which creation flow based on payload keys
    data_keys = set(request.data.keys())
    if {'admin_email', 'admin_first_name', 'admin_password'} & data_keys:
        # Full create with admin
        create_view = OrganizationWithAdminCreateView.as_view()
        return create_view(request._request)

    # Simple organization create (name, is_active)
    name = request.data.get('name')
    if not name:
        return Response({'name': ['This field is required.']}, status=status.HTTP_400_BAD_REQUEST)

    is_active = bool(request.data.get('is_active', True))
    description = request.data.get('description', '')

    org = Organization.objects.create(
        name=name,
        description=description,
        is_active=is_active,
        created_by=request.user if request.user.is_authenticated else None
    )

    return Response(OrganizationSerializer(org).data, status=status.HTTP_201_CREATED)
