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
    members = UserLiteSerializer(many=True, read_only=True)
    projects = serializers.PrimaryKeyRelatedField(queryset=Project.objects.all(), many=True, required=False)
    
    # Write-only fields for creation/updates
    team_lead_id = serializers.IntegerField(write_only=True, required=False, allow_null=True)
    member_ids = serializers.ListField(
        child=serializers.IntegerField(),
        write_only=True,
        required=False,
        allow_empty=True
    )

    class Meta:
        model = Team
        fields = ['id', 'name', 'organization', 'team_lead', 'members', 'projects', 'contact_number', 'created_at', 'team_lead_id', 'member_ids']
        read_only_fields = ['organization']
        
    def create(self, validated_data):
        # Extract the write-only fields
        team_lead_id = validated_data.pop('team_lead_id', None)
        member_ids = validated_data.pop('member_ids', [])
        
        # Create the team
        team = Team.objects.create(**validated_data)
        
        # Set team lead if provided
        if team_lead_id:
            try:
                team_lead = User.objects.get(id=team_lead_id)
                team.team_lead = team_lead
                team.save()
            except User.DoesNotExist:
                pass
        
        # Set members if provided
        if member_ids:
            members = User.objects.filter(id__in=member_ids)
            team.members.set(members)
        
        return team
        
    def update(self, instance, validated_data):
        # Extract the write-only fields
        team_lead_id = validated_data.pop('team_lead_id', None)
        member_ids = validated_data.pop('member_ids', None)
        
        # Update regular fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        
        # Update team lead if provided
        if team_lead_id is not None:
            if team_lead_id:
                try:
                    team_lead = User.objects.get(id=team_lead_id)
                    instance.team_lead = team_lead
                except User.DoesNotExist:
                    pass
            else:
                instance.team_lead = None
            instance.save()
        
        # Update members if provided
        if member_ids is not None:
            members = User.objects.filter(id__in=member_ids)
            instance.members.set(members)
        
        return instance 