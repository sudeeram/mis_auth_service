# Auth Service

Django authentication authority for local accounts and Microsoft Entra SAML 2.0 SSO. It owns users, sessions, roles, permissions, SAML identities, and application JWT signing.

## Required runtime configuration

See `config/settings.py` for environment variables. Runtime secrets are mounted at `/run/secrets`:

- `jwt-private.pem` and `jwt-public.pem`
- `saml-sp-key.pem` and `saml-sp-cert.pem`
- `entra-idp-metadata.xml`

Set `SAML_ENABLED=true` only after the metadata and SP keypair are mounted. The Entra object identifier claim is the immutable provisioning key. Entra Enterprise Application assignment must enforce the allowed AD group.

## Development commands

```bash
uv sync --frozen
uv run python manage.py migrate
uv run python manage.py seed_rbac
uv run python manage.py createsuperuser
uv run python manage.py runserver
```

`uv` reads `.python-version`, creates an isolated `.venv`, and installs the exact
dependency versions recorded in `uv.lock`.

The normal development runtime is the Minikube deployment from `platform-infrastructure`.
