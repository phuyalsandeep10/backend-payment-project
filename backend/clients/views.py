from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.decorators import action
from .models import Client, ClientActivity
from .serializers import ClientSerializer, ClientActivitySerializer
from .permissions import CanAccessClient
from django.db import models
import logging, traceback

class ClientViewSet(viewsets.ModelViewSet):
    """
    A viewset for viewing and editing Client instances.
    """
    serializer_class = ClientSerializer
    permission_classes = [CanAccessClient]

    def get_queryset(self):
        """
        This view should return a list of all the clients
        created by the currently authenticated user.
        Superusers can see all clients.
        """
        user = self.request.user
        if user.is_superuser:
            return Client.objects.all()
        
        if user.role and user.role.name.replace(' ', '').lower() in ['orgadmin', 'admin']:
            return Client.objects.filter(organization=user.organization)
        
        if user.role and user.role.name.replace(' ', '').lower() == 'salesperson':
            # Salesperson can see clients assigned to them or in their team
            return Client.objects.filter(
                models.Q(salesperson=user) | models.Q(teams__in=user.teams.all())
            ).distinct()
            
        return Client.objects.none()

    def perform_create(self, serializer):
        """
        Associate the client with the creator and their organization.
        For salespersons, also assign them as the salesperson.
        """
        try:
            user = self.request.user
            save_kwargs = {
                'created_by': user,
                'organization': user.organization
            }
            
            # If the user is a salesperson, assign them as the salesperson
            if user.role and user.role.name.replace(' ', '').lower() == 'salesperson':
                save_kwargs['salesperson'] = user
            
            serializer.save(**save_kwargs)
        except Exception as exc:
            logging.error("Client create failed: %s", exc)
            logging.error(traceback.format_exc())
            raise

    @action(detail=True, methods=['post'])
    def add_activity(self, request, pk=None):
        """
        Add an activity to a client.
        Frontend expects: POST /clients/{clientId}/activities
        """
        client = self.get_object()
        
        # Create activity data
        activity_data = request.data.copy()
        activity_data['client'] = client.id
        activity_data['created_by'] = request.user.id
        
        serializer = ClientActivitySerializer(data=activity_data)
        if serializer.is_valid():
            serializer.save()
            # Return updated client with activities
            return Response(ClientSerializer(client).data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get_activities(self, request, pk=None):
        """
        Get all activities for a client.
        """
        client = self.get_object()
        activities = client.activities.all()
        return Response(ClientActivitySerializer(activities, many=True).data)