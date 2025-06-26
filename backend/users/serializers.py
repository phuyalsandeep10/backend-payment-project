from rest_framework import serializers
from .models import CustomUser
from django.contrib.auth import get_user_model

User = get_user_model()


class UserRegistrationSerializer(serializers.ModelSerializer):
    
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    password_confirm = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'}, label='Confirm password')
    class Meta:
        model = CustomUser
        fields = ('id', 'email', 'full_name', 'password', 'password_confirm')
        extra_kwargs = {
            'id': {'read_only': True},
        }
        
    def validate(self, attrs):
            if attrs['password'] != attrs['password_confirm']:
                raise serializers.ValidationError({"password": "Password fields didn't match."})
            return attrs
        
    def create(self, validated_data):
            validated_data.pop('password_confirm')
            password = validated_data.pop('password')
            user = User(**validated_data)
            user.set_password(password)
            user.save()
            return user
        
        

class UserSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = CustomUser
        fields = (
            'id',              # UUID primary key    
            'email',           # unique email (username field)
            'full_name',       # your combined name field
            'phone_number',
            'address',
            'city',
            'state',
            'zip_code',
            'country',
            'is_active',
            'is_staff',
            'date_joined',
            'last_login',
        )
        read_only_fields = ('id', 'date_joined', 'last_login', 'is_staff')
        
    def get_user_id(self, obj):
        return str(obj.id)

    def validate(self, data):
        instance = getattr(self, 'instance', None) 
        if instance and hasattr(instance, 'is_active') and not instance.is_active:
            raise serializers.ValidationError('Cannot update or delete an inactive (soft-deleted) user.')
        return data