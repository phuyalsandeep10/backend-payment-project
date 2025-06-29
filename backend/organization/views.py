from django.shortcuts import render
from rest_framework import viewsets, generics, status, permissions
from rest_framework.response import Response
from rest_framework.permissions import IsAdminUser
from .models import Organization
from .serializers import OrganizationSerializer, OrganizationDetailSerializer, OrganizationRegistrationSerializer

# Create your views here.

class OrganizationViewSet(viewsets.ModelViewSet):
    """
    This viewset automatically provides `list`, `create`, 'retrieve',
    'update' and 'destroy' actions for Organizations.
    """
    queryset = Organization.objects.all()
    permission_classes = [IsAdminUser] # Only SuperAdmins can manage organizations directly

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return OrganizationDetailSerializer
        return OrganizationSerializer

class OrganizationRegistrationView(generics.CreateAPIView):
    """
    A view for registering a new organization and its first admin.
    This is a public endpoint.
    """
    serializer_class = OrganizationRegistrationSerializer
    authentication_classes = []
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
