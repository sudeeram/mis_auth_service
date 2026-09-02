from django.core.management.base import BaseCommand

from accounts.models import Permission, Role, RolePermission, Service

CATALOG = {
    "platform": {
        "platform.user_administrator": ["platform:users:admin"],
        "platform.security_administrator": ["platform:users:admin", "platform:security:admin"],
    },
    "network": {
        "network.viewer": ["network:dashboard:view", "network:devices:view"],
        "network.operator": ["network:dashboard:view", "network:devices:view", "network:devices:create", "network:devices:update", "network:operations:execute"],
        "network.administrator": ["network:dashboard:view", "network:devices:view", "network:devices:create", "network:devices:update", "network:devices:delete", "network:operations:execute", "network:administration"],
    },
    "aws": {
        "aws.viewer": ["aws:dashboard:view", "aws:connections:view", "aws:resources:view"],
        "aws.operator": ["aws:dashboard:view", "aws:connections:view", "aws:resources:view", "aws:operations:execute"],
        "aws.administrator": ["aws:dashboard:view", "aws:connections:view", "aws:connections:create", "aws:connections:update", "aws:connections:delete", "aws:resources:view", "aws:operations:execute", "aws:administration"],
    },
}


class Command(BaseCommand):
    def handle(self, *args, **options):
        for service_key, roles in CATALOG.items():
            service, _ = Service.objects.get_or_create(key=service_key, defaults={"name": service_key.title()})
            for role_key, permission_keys in roles.items():
                role, _ = Role.objects.get_or_create(key=role_key, defaults={"name": role_key.split(".")[-1].title(), "service": service})
                for permission_key in permission_keys:
                    permission, _ = Permission.objects.get_or_create(key=permission_key, defaults={"service": service})
                    RolePermission.objects.get_or_create(role=role, permission=permission)
        self.stdout.write(self.style.SUCCESS("RBAC catalog seeded"))

