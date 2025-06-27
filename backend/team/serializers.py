from rest_framework import serializers
from .models import Team
from authentication.serializers import UserLiteSerializer
# from project.serializers import ProjectSerializer # This is moved to prevent circular import

class TeamLiteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Team
        fields = ['id', 'name', 'organization']

class TeamSerializer(serializers.ModelSerializer):
    team_lead = UserLiteSerializer(read_only=True)
    members = UserLiteSerializer(many=True, read_only=True)
    projects = serializers.SerializerMethodField()

    class Meta:
        model = Team
        fields = ['id', 'name', 'organization', 'team_lead', 'members', 'projects', 'contact_number', 'created_at', 'updated_at']

    def get_projects(self, obj):
        from project.serializers import ProjectSerializer
        return ProjectSerializer(obj.projects.all(), many=True).data 