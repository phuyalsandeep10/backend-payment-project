from rest_framework import serializers
from .models import Client
from project.models import Project


class ProjectNameSerializer(serializers.ModelSerializer):
    class Meta:
        model = Project
        fields = ['id', 'name']


class ClientSerializer(serializers.ModelSerializer):
    """
    Serializer for the Client model.
    """
    project_count = serializers.IntegerField(read_only=True)
    projects = ProjectNameSerializer(many=True, read_only=True)
    created_by_name = serializers.CharField(source='created_by.get_full_name', read_only=True)
    updated_by_username = serializers.CharField(source='updated_by.username', read_only=True)
    nationality = serializers.CharField(required=False, allow_null=True)
    
    class Meta:
        model = Client
        fields = [
            'id', 'client_name', 'email', 'phone_number', 'nationality',
            'remarks', 'satisfaction', 'status',
            'organization', 'created_at', 'created_by', 'created_by_name',
            'updated_at', 'updated_by', 'updated_by_username',
            'project_count', 'projects'
        ]
        read_only_fields = ['created_by', 'updated_by', 'organization', 'created_at', 'updated_at']
        

class ClientLiteSerializer(serializers.ModelSerializer):
    """
    A lightweight serializer for basic client information.
    """
    class Meta:
        model = Client
        fields = ['id', 'client_name']
        
        