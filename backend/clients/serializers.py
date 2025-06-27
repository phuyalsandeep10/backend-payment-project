from rest_framework import serializers
from .models import Clients


class ClientsSerializers(serializers.ModelSerializer):
    class Meta:
        model = Clients
        fields = '__all__'
        read_only_fields =  ('created_at','updated_at')
        
        