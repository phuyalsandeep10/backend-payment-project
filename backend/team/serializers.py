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
    team_lead_details = UserLiteSerializer(source='team_lead', read_only=True)
    team_lead = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(), write_only=True, required=False, allow_null=True
    )
    members = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(), many=True, required=False
    )
    projects = serializers.PrimaryKeyRelatedField(
        queryset=Project.objects.all(), many=True, required=False
    )
    created_by_username = serializers.CharField(source='created_by.username', read_only=True)
    updated_by_username = serializers.CharField(source='updated_by.username', read_only=True)

    class Meta:
        model = Team
        fields = [
            'id', 'name', 'description', 'contact_number', 'organization',
            'team_lead', 'team_lead_details', 'members', 'projects',
            'created_at', 'created_by', 'created_by_username',
            'updated_at', 'updated_by', 'updated_by_username'
        ]
        read_only_fields = [
            'organization', 'created_by_username',
            'updated_by_username'
        ] 