from rest_framework import serializers
from .models import Team
from authentication.serializers import UserLiteSerializer
from project.models import Project
from authentication.models import User

class TeamSerializer(serializers.ModelSerializer):
    """Serializer for the Team model."""
    class Meta:
        model = Team
        fields = '__all__'
