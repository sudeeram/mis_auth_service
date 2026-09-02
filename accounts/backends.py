from django.contrib.auth.backends import ModelBackend

from .models import AccountStatus, AccountType, User


class LocalEmailBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, email=None, **kwargs):
        identifier = email or username
        if not identifier or not password:
            return None
        try:
            user = User.objects.get(email__iexact=identifier, account_type=AccountType.LOCAL)
        except User.DoesNotExist:
            User().set_password(password)
            return None
        if user.status == AccountStatus.ACTIVE and user.check_password(password):
            return user
        return None

