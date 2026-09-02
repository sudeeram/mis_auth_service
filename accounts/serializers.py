import uuid

from rest_framework import serializers

from .models import Role, User
from .tokens import effective_access


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(trim_whitespace=False, write_only=True)


class MeSerializer(serializers.ModelSerializer):
    roles = serializers.SerializerMethodField()
    permissions = serializers.SerializerMethodField()
    services = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ("id", "email", "display_name", "account_type", "status", "roles", "permissions", "services")

    def _access(self, obj):
        return effective_access(obj)

    def get_roles(self, obj): return self._access(obj)[0]
    def get_permissions(self, obj): return self._access(obj)[1]
    def get_services(self, obj): return self._access(obj)[2]


class UserSerializer(MeSerializer):
    class Meta(MeSerializer.Meta):
        fields = MeSerializer.Meta.fields + ("created_at", "last_login")


class CreateLocalUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=12)

    class Meta:
        model = User
        fields = ("id", "email", "display_name", "password")
        read_only_fields = ("id",)

    def create(self, validated_data):
        password = validated_data.pop("password")
        email = validated_data.pop("email").lower()
        user = User(username=f"local:{uuid.uuid4()}", email=email, **validated_data)
        user.set_password(password)
        user.save()
        return user


class RoleSerializer(serializers.ModelSerializer):
    permissions = serializers.SlugRelatedField(many=True, read_only=True, slug_field="key")

    class Meta:
        model = Role
        fields = ("id", "key", "name", "service", "permissions")
