import uuid

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.db.models.functions import Lower


class AccountType(models.TextChoices):
    LOCAL = "LOCAL", "Local"
    ENTRA = "ENTRA", "Microsoft Entra"


class AccountStatus(models.TextChoices):
    ACTIVE = "ACTIVE", "Active"
    SUSPENDED = "SUSPENDED", "Suspended"
    DISABLED = "DISABLED", "Disabled"


class User(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    account_type = models.CharField(max_length=16, choices=AccountType.choices, default=AccountType.LOCAL)
    status = models.CharField(max_length=16, choices=AccountStatus.choices, default=AccountStatus.ACTIVE)
    email = models.EmailField()
    display_name = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                Lower("email"),
                condition=models.Q(account_type=AccountType.LOCAL),
                name="unique_local_email_case_insensitive",
            ),
        ]

    def save(self, *args, **kwargs):
        if self.account_type == AccountType.ENTRA:
            self.set_unusable_password()
        self.is_active = self.status == AccountStatus.ACTIVE
        super().save(*args, **kwargs)


class EntraIdentity(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="entra_identity")
    tenant_id = models.UUIDField()
    object_id = models.UUIDField()
    name_id = models.CharField(max_length=512, blank=True)
    issuer = models.CharField(max_length=512)
    last_authenticated_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=("tenant_id", "object_id"), name="unique_entra_identity")]


class Service(models.Model):
    key = models.SlugField(primary_key=True)
    name = models.CharField(max_length=100)


class Permission(models.Model):
    key = models.CharField(max_length=128, primary_key=True)
    service = models.ForeignKey(Service, on_delete=models.CASCADE, related_name="permissions")
    description = models.CharField(max_length=255, blank=True)


class Role(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    key = models.CharField(max_length=128, unique=True)
    name = models.CharField(max_length=100)
    service = models.ForeignKey(Service, on_delete=models.CASCADE, related_name="roles")
    permissions = models.ManyToManyField(Permission, through="RolePermission", related_name="roles")


class RolePermission(models.Model):
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

    class Meta:
        constraints = [models.UniqueConstraint(fields=("role", "permission"), name="unique_role_permission")]


class UserRole(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="role_assignments")
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name="user_assignments")
    assigned_by = models.ForeignKey(User, null=True, on_delete=models.SET_NULL, related_name="roles_assigned")
    assigned_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=("user", "role"), name="unique_user_role")]


class RefreshSession(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="refresh_sessions")
    token_hash = models.CharField(max_length=64)
    authentication_method = models.CharField(max_length=16)
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)


class SecurityAuditEvent(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, null=True, on_delete=models.SET_NULL)
    event_type = models.CharField(max_length=80)
    outcome = models.CharField(max_length=24)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    details = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

