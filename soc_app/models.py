"""
Django Database Models Schema
Defines ORM models for Security Incidents, Prediction Logs, Audit Logs, and User Profiles (RBAC).
"""

from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

class Profile(models.Model):
    """Extends default Django user to house RBAC roles (Admin, Security Analyst, Viewer)."""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    role = models.CharField(max_length=30, default="Viewer") # Admin, Security Analyst, Viewer

    def __str__(self) -> str:
        return f"{self.user.username} ({self.role})"
        
    def to_dict(self) -> dict:
        return {
            "id": self.user.id,
            "username": self.user.username,
            "role": self.role,
            "created_at": self.user.date_joined.strftime("%Y-%m-%d %H:%M:%S")
        }

# Signals to automatically manage profile instantiation on user creation
@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    if hasattr(instance, 'profile'):
        instance.profile.save()
    else:
        Profile.objects.create(user=instance)


class Incident(models.Model):
    """Database schema holding ingested security telemetry logs."""
    timestamp = models.DateTimeField(db_index=True)
    source_ip = models.CharField(max_length=45, db_index=True)
    destination_ip = models.CharField(max_length=45)
    attack_type = models.CharField(max_length=100)
    protocol = models.CharField(max_length=20)
    port = models.IntegerField()
    severity = models.CharField(max_length=20)
    status = models.CharField(max_length=50)
    country = models.CharField(max_length=50)
    device = models.CharField(max_length=100)
    action_taken = models.CharField(max_length=100)
    failed_login_count = models.IntegerField(default=0)
    session_duration = models.FloatField(default=0.0)

    def __str__(self) -> str:
        return f"Incident #{self.id} - {self.attack_type} ({self.source_ip})"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "Timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S") if self.timestamp else "",
            "Source_IP": self.source_ip,
            "Destination_IP": self.destination_ip,
            "Attack_Type": self.attack_type,
            "Protocol": self.protocol,
            "Port": self.port,
            "Severity": self.severity,
            "Status": self.status,
            "Country": self.country,
            "Device": self.device,
            "Action_Taken": self.action_taken,
            "Failed_Login_Count": self.failed_login_count,
            "Session_Duration": self.session_duration
        }


class PredictionLog(models.Model):
    """ORM model storing threat risk evaluation predictions for compliance auditing."""
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    source_ip = models.CharField(max_length=45)
    dest_ip = models.CharField(max_length=45)
    attack_type = models.CharField(max_length=100)
    risk_level = models.CharField(max_length=30)
    confidence = models.FloatField()
    recommendation = models.TextField()
    features_json = models.TextField() # Serialized JSON string of the exact input variables

    def __str__(self) -> str:
        return f"Prediction #{self.id} - {self.risk_level} (Conf: {self.confidence}%)"


class AuditLog(models.Model):
    """Central compliance audit repository capturing system events and user commands."""
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    username = models.CharField(max_length=100, db_index=True)
    action = models.TextField()
    ip_address = models.CharField(max_length=45, null=True, blank=True)

    def __str__(self) -> str:
        return f"[{self.timestamp}] User '{self.username}' -> {self.action}"
        
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "username": self.username,
            "action": self.action,
            "ip_address": self.ip_address
        }
