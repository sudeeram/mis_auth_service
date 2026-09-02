import uuid

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from djangosaml2.backends import Saml2Backend

from .models import AccountStatus, AccountType, EntraIdentity, User


class EntraSaml2Backend(Saml2Backend):
    """Provision SAML users by immutable Entra tenant/object identifiers."""

    def is_authorized(self, attributes, attribute_mapping, idp_entityid, assertion_info, **kwargs):
        expected_issuer = settings.SAML_IDP_ENTITY_ID
        has_object_id = bool(attributes.get(settings.SAML_ENTRA_OBJECT_ID_ATTRIBUTE))
        return bool(has_object_id and (not expected_issuer or idp_entityid == expected_issuer))

    @transaction.atomic
    def get_or_create_user(
        self, user_lookup_key, user_lookup_value, create_unknown_user,
        idp_entityid, attributes, attribute_mapping, request,
    ):
        try:
            tenant_id = uuid.UUID(settings.SAML_TENANT_ID)
            object_id = uuid.UUID(str(user_lookup_value))
        except (TypeError, ValueError):
            return None, False

        identity = EntraIdentity.objects.select_related("user").filter(
            tenant_id=tenant_id, object_id=object_id
        ).first()
        if identity:
            identity.last_authenticated_at = timezone.now()
            identity.save(update_fields=["last_authenticated_at"])
            return identity.user, False
        if not create_unknown_user:
            return None, False

        email_claim = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
        display_claim = "http://schemas.microsoft.com/identity/claims/displayname"
        email = (attributes.get(email_claim) or [""])[0]
        display_name = (attributes.get(display_claim) or [email])[0]
        user = User.objects.create(
            username=f"entra:{tenant_id}:{object_id}",
            email=email,
            display_name=display_name,
            account_type=AccountType.ENTRA,
            status=AccountStatus.ACTIVE,
        )
        EntraIdentity.objects.create(
            user=user,
            tenant_id=tenant_id,
            object_id=object_id,
            issuer=idp_entityid,
            last_authenticated_at=timezone.now(),
        )
        return user, True
