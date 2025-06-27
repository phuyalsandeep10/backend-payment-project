from rest_framework import generics, permissions
from .models import Clients
from .serializers import ClientsSerializers

# Create your views here.
class ClientListCreateView(generics.ListCreateAPIView):
    queryset = Clients.objects.all()
    serializer_class = ClientsSerializers
    permission_classes = [permissions.AllowAny] # for now allow any for testing later change it to is authenticated
    
class ClientDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Clients.objects.all()
    serializer_class = ClientsSerializers
    permission_classes = [permissions.AllowAny]