from rest_framework import serializers
from .models import Project
from team.serializers import TeamLiteSerializer

class ProjectSerializer(serializers.ModelSerializer):
    """
    Serializer for the Project model.
    """
    created_by_username = serializers.CharField(source='created_by.username', read_only=True)
    # The 'teams' field is no longer relevant as Project is not directly linked to Team
    # teams = TeamLiteSerializer(many=True, read_only=True)

    class Meta:
        model = Project
        fields = [
            'id', 'name', 'description', 'status',
            'created_at', 'created_by', 'created_by_username',
            'updated_at'
        ]
        read_only_fields = [
            'created_by', 'created_by_username', 'updated_at'
        ] 