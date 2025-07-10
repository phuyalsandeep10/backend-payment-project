from rest_framework import serializers
from .models import Project

class ProjectSerializer(serializers.ModelSerializer):
    """Serializer for the Project model."""
    class Meta:
        model = Project
        fields = '__all__' 