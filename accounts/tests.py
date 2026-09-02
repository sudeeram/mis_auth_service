from django.core.management import call_command
from django.db import IntegrityError, transaction
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from .models import AccountType, EntraIdentity, Role, User, UserRole
from .tokens import effective_access
from .saml_backend import EntraSaml2Backend


class IdentityModelTests(TestCase):
    def test_local_and_entra_users_can_share_email(self):
        local = User.objects.create_user(username="local:alice@example.com", email="alice@example.com", password="long-test-password")
        entra = User.objects.create(username="entra:alice", email="alice@example.com", account_type=AccountType.ENTRA)
        EntraIdentity.objects.create(
            user=entra,
            tenant_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            object_id="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            issuer="https://sts.windows.net/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/",
        )
        self.assertNotEqual(local.id, entra.id)
        self.assertFalse(entra.has_usable_password())

    def test_local_email_is_case_insensitively_unique(self):
        User.objects.create_user(username="local:first", email="alice@example.com", password="long-test-password")
        with self.assertRaises(IntegrityError), transaction.atomic():
            User.objects.create_user(username="local:second", email="ALICE@example.com", password="long-test-password")


class RoleTests(TestCase):
    def test_multiple_roles_combine_permissions(self):
        call_command("seed_rbac", verbosity=0)
        user = User.objects.create_user(username="local:operator", email="operator@example.com", password="long-test-password")
        for key in ("network.viewer", "aws.operator"):
            UserRole.objects.create(user=user, role=Role.objects.get(key=key))
        roles, permissions, services = effective_access(user)
        self.assertEqual(roles, ["aws.operator", "network.viewer"])
        self.assertIn("network:devices:view", permissions)
        self.assertIn("aws:operations:execute", permissions)
        self.assertEqual(services, ["aws", "network"])


@override_settings(
    SAML_TENANT_ID="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    SAML_IDP_ENTITY_ID="https://sts.windows.net/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/",
)
class SamlProvisioningTests(TestCase):
    def test_first_login_provisions_entra_user_without_business_roles(self):
        object_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        issuer = "https://sts.windows.net/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/"
        attributes = {
            "http://schemas.microsoft.com/identity/claims/objectidentifier": [object_id],
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": ["alice@example.com"],
            "http://schemas.microsoft.com/identity/claims/displayname": ["Alice"],
        }
        user, created = EntraSaml2Backend().get_or_create_user(
            "username", object_id, True, issuer, attributes, {}, None,
        )
        self.assertTrue(created)
        self.assertEqual(user.account_type, AccountType.ENTRA)
        self.assertFalse(user.has_usable_password())
        self.assertEqual(effective_access(user), ([], [], []))

        same_user, created_again = EntraSaml2Backend().get_or_create_user(
            "username", object_id, True, issuer, attributes, {}, None,
        )
        self.assertFalse(created_again)
        self.assertEqual(same_user.id, user.id)


class LoginTests(TestCase):
    def setUp(self):
        self.client = APIClient(enforce_csrf_checks=True)
        self.user = User.objects.create_user(username="local:login", email="login@example.com", password="long-test-password")

    def test_login_requires_csrf_and_issues_http_only_cookies(self):
        rejected = self.client.post("/api/auth/login", {"email": self.user.email, "password": "long-test-password"}, format="json")
        self.assertEqual(rejected.status_code, 403)
        csrf = self.client.get("/api/auth/csrf").json()["csrfToken"]
        response = self.client.post(
            "/api/auth/login",
            {"email": self.user.email, "password": "long-test-password"},
            format="json",
            HTTP_X_CSRFTOKEN=csrf,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.cookies["platform_access"]["httponly"])
        self.assertTrue(response.cookies["platform_refresh"]["httponly"])
