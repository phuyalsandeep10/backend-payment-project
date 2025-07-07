from rest_framework import serializers
from .models import Client, ClientActivity


class ClientActivitySerializer(serializers.ModelSerializer):
    """
    Serializer for client activities
    """
    class Meta:
        model = ClientActivity
        fields = ['timestamp', 'description', 'type']


class ClientSerializer(serializers.ModelSerializer):
    """
    Serializer for the Client model to match frontend expectations.
    """
    name = serializers.CharField(source='client_name')
    phoneNumber = serializers.CharField(source='phone_number', required=False)
    lastContact = serializers.DateTimeField(source='last_contact', required=False)
    expectedClose = serializers.DateField(source='expected_close', required=False)
    category = serializers.CharField(required=False)
    status = serializers.CharField(required=False)
    satisfaction = serializers.CharField(required=False)
    value = serializers.DecimalField(max_digits=12, decimal_places=2, required=False)
    remarks = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    primaryContactName = serializers.CharField(source='primary_contact_name', required=False)
    primaryContactPhone = serializers.CharField(source='primary_contact_phone', required=False)  
    nationality = serializers.CharField(required=False)
    activeDate = serializers.DateTimeField(source='active_date', read_only=True)
    avatarUrl = serializers.URLField(source='avatar_url', required=False)
    activities = ClientActivitySerializer(many=True, read_only=True)
    salesperson = serializers.SerializerMethodField()
    sales_leads = serializers.SerializerMethodField()
    createdAt = serializers.SerializerMethodField(read_only=True)
    updatedAt = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Client
        fields = [
            'id', 'name', 'email', 'phoneNumber', 'category', 'salesperson', 'lastContact', 
            'expectedClose', 'value', 'status', 'satisfaction', 'remarks',
            'primaryContactName', 'primaryContactPhone', 'nationality', 'address', 'activeDate',
            'activities', 'avatarUrl', 'sales_leads', 'createdAt', 'updatedAt'
        ]
        read_only_fields = ['created_by', 'organization']

    def get_salesperson(self, obj):
        """Return salesperson name"""
        return obj.salesperson.get_full_name() if obj.salesperson else None

    def get_sales_leads(self, obj):
        """Return list of sales lead objects with id, name, and avatar"""
        if obj.salesperson:
            return [{
                'id': str(obj.salesperson.id),
                'name': obj.salesperson.get_full_name() or obj.salesperson.username,
                'avatar': getattr(obj.salesperson, 'avatar', None) or f"https://ui-avatars.com/api/?name={obj.salesperson.get_full_name() or obj.salesperson.username}&background=random"
            }]
        return []

    def get_createdAt(self, obj):
        return obj.created_at.isoformat() if obj.created_at else None

    def get_updatedAt(self, obj):
        return obj.updated_at.isoformat() if obj.updated_at else None
        
        