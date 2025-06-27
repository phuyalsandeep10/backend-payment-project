from django.shortcuts import render
from rest_framework import viewsets
from .models import Commission
from .serializers import CommissionSerializer
from permissions.views import IsOrgAdmin # Re-using the IsOrgAdmin permission

# Create your views here.

class CommissionViewSet(viewsets.ModelViewSet):
    """
    A viewset for an Org Admin to manage commissions within their own organization.
    """
    serializer_class = CommissionSerializer
    permission_classes = [IsOrgAdmin]

    def get_queryset(self):
        """
        This view should return a list of all the commissions
        for the currently authenticated user's organization.
        """
        # Short-circuit for schema generation to avoid AnonymousUser errors
        if getattr(self, 'swagger_fake_view', False):
            return Commission.objects.none()
            
        user = self.request.user
        return Commission.objects.filter(organization=user.organization)

    def get_serializer_context(self):
        """
        Pass the request to the serializer context.
        """
        return {'request': self.request}
