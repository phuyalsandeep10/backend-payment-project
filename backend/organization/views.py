from django.shortcuts import render
from rest_framework import viewsets, generics, status
from rest_framework.response import Response
from .models import Organization
from authentication.models import User
from .serializers import OrganizationSerializer, OrgAdminSerializer, OrganizationRegistrationSerializer
from .permissions import IsSuperAdmin

# Create your views here.

class OrganizationViewSet(viewsets.ModelViewSet):
    """
    A viewset for viewing and editing organization instances.
    """
    queryset = Organization.objects.all()
    serializer_class = OrganizationSerializer
    permission_classes = [IsSuperAdmin]

class OrgAdminViewSet(viewsets.ModelViewSet):
    """
    A viewset for viewing and editing organization admin instances.
    """
    queryset = User.objects.filter(role=User.Role.ORG_ADMIN)
    serializer_class = OrgAdminSerializer
    permission_classes = [IsSuperAdmin]

class OrganizationRegistrationView(generics.CreateAPIView):
    """
    A view for registering a new organization and its first admin.
    """
    serializer_class = OrganizationRegistrationSerializer
    permission_classes = [IsSuperAdmin]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        organization = serializer.save()
        # Return the created organization's data
        response_serializer = OrganizationSerializer(organization)
        headers = self.get_success_headers(response_serializer.data)
        return Response(response_serializer.data, status=status.HTTP_201_CREATED, headers=headers)
