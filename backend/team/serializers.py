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
    Serializer for the Team model, providing detailed read representations
    and a clear write API using IDs.
    """
    # Read-only nested serializers for detailed representation
    team_lead = UserLiteSerializer(read_only=True)
    members = UserLiteSerializer(many=True, read_only=True)
    created_by = UserLiteSerializer(read_only=True)
    updated_by = UserLiteSerializer(read_only=True)

    # Allow writing relationships by ID
    projects = serializers.PrimaryKeyRelatedField(
        queryset=Project.objects.all(), many=True, required=False
    )
    team_lead_id = serializers.IntegerField(
        write_only=True, required=False, allow_null=True, source='team_lead'
    )
    member_ids = serializers.ListField(
        child=serializers.IntegerField(), write_only=True, required=False
    )

    class Meta:
        model = Team
        fields = [
            'id', 'name', 'description', 'organization', 'contact_number',
            # Read-only objects
            'team_lead', 'members', 
            # Writeable relationships
            'projects', 'team_lead_id', 'member_ids',
            # Audit fields
            'created_at', 'updated_at', 'created_by', 'updated_by'
        ]
        read_only_fields = ['organization', 'created_by', 'updated_by']
        
    def create(self, validated_data):
        member_ids = validated_data.pop('member_ids', [])
        
        # Create the team instance from the remaining validated data
        team = Team.objects.create(**validated_data)
        
        # Set members if provided
        if member_ids:
            members = User.objects.filter(id__in=member_ids)
            team.members.set(members)
        
        return team
        
    def update(self, instance, validated_data):
        member_ids = validated_data.pop('member_ids', None)
        
        # Update the instance with the remaining validated data
        # DRF's default update will handle the team_lead update via `source='team_lead'`
        instance = super().update(instance, validated_data)
        
        # Update members if a list was provided
        if member_ids is not None:
            members = User.objects.filter(id__in=member_ids)
            instance.members.set(members)
        
        return instance
