from rest_framework import serializers
from .models import Project
from team.serializers import TeamLiteSerializer

class ProjectSerializer(serializers.ModelSerializer):
    teams = TeamLiteSerializer(many=True, read_only=True)
    class Meta:
        model = Project
        fields = ['id', 'name', 'teams', 'created_at', 'updated_at'] 