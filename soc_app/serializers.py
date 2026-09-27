"""
Django REST Framework (DRF) Serializers
Validates incoming REST payloads and formats API responses.
"""

from rest_framework import serializers
from django.contrib.auth.models import User
from soc_app.models import Profile, Incident, PredictionLog, AuditLog

class ProfileSerializer(serializers.ModelSerializer):
    """Serializes user roles profiles."""
    class Meta:
        model = Profile
        fields = ['role']

class UserSerializer(serializers.ModelSerializer):
    """Public user serializer profile representation."""
    role = serializers.CharField(source='profile.role', read_only=True)
    created_at = serializers.DateTimeField(source='date_joined', format="%Y-%m-%d %H:%M:%S", read_only=True)
    
    class Meta:
        model = User
        fields = ['id', 'username', 'role', 'created_at']

class UserCreateSerializer(serializers.ModelSerializer):
    """Registration serializer (restriced to Admin role)."""
    role = serializers.CharField(write_only=True, default="Viewer")
    password = serializers.CharField(write_only=True, min_length=6)

    class Meta:
        model = User
        fields = ['username', 'password', 'role']

    def validate_role(self, value):
        if value not in ["Admin", "Security Analyst", "Viewer"]:
            raise serializers.ValidationError("Role must be one of: Admin, Security Analyst, Viewer.")
        return value

    def create(self, validated_data):
        role = validated_data.pop('role', 'Viewer')
        password = validated_data.pop('password')
        
        # Create built-in User object
        user = User.objects.create_user(**validated_data)
        user.set_password(password)
        user.save()
        
        # Profile is created automatically by database post_save signal
        # We manually update the role
        user.profile.role = role
        user.profile.save()
        return user


class IncidentSerializer(serializers.ModelSerializer):
    """Validates security incident log records uploads."""
    class Meta:
        model = Incident
        fields = '__all__'

    def validate_port(self, value):
        if value < 0 or value > 65535:
            raise serializers.ValidationError("Destination port must be inside the valid range [0, 65535].")
        return value


class PredictionRequestSerializer(serializers.Serializer):
    """Validation schema for real-time ML risk predictions requests."""
    Attack_Type = serializers.CharField(required=True)
    Protocol = serializers.CharField(required=True)
    Port = serializers.IntegerField(min_value=0, max_value=65535, required=True)
    Device = serializers.CharField(required=True)
    Country = serializers.CharField(required=True)
    Failed_Login_Count = serializers.IntegerField(min_value=0, default=0)
    Hour = serializers.IntegerField(min_value=0, max_value=23, required=True)
    Weekend_Flag = serializers.IntegerField(min_value=0, max_value=1, default=0)
    Attack_Frequency = serializers.IntegerField(min_value=1, default=1)
    Suspicious_IP_Score = serializers.FloatRangeField(default=0.0) if hasattr(serializers, 'FloatRangeField') else serializers.FloatField(default=0.0)
    Session_Duration = serializers.FloatField(default=0.0)
    User_Role = serializers.CharField(default="Standard Employee")
    Auth_Method = serializers.CharField(default="Password")


class AuditLogSerializer(serializers.ModelSerializer):
    """Serializes system audit logs."""
    class Meta:
        model = AuditLog
        fields = '__all__'
