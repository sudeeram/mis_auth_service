from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import EntraIdentity, Permission, RefreshSession, Role, Service, User, UserRole


@admin.register(User)
class PlatformUserAdmin(UserAdmin):
    fieldsets = UserAdmin.fieldsets + (("Platform", {"fields": ("account_type", "status", "display_name")}),)
    list_display = ("email", "display_name", "account_type", "status", "is_staff")


admin.site.register([EntraIdentity, Service, Permission, Role, UserRole, RefreshSession])

