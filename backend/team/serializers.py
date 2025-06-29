from rest_framework import serializers
from .models import Team
from authentication.serializers import UserLiteSerializer
from project.models import Project
from authentication.models import User

class TeamLiteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Team
        fields = ['id', 'name', 'organization']

class TeamSerializer(serializers.ModelSerializer):
    """
    Serializer for the Team model.
    """
    team_lead = UserLiteSerializer(read_only=True)
    members = serializers.PrimaryKeyRelatedField(queryset=User.objects.all(), many=True, required=False)
    projects = serializers.PrimaryKeyRelatedField(queryset=Project.objects.all(), many=True, required=False)

    class Meta:
        model = Team
        fields = ['id', 'name', 'organization', 'team_lead', 'members', 'projects', 'created_at']
        read_only_fields = [] 