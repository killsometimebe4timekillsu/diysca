"""Auth: OIDC login, roles (viewer, operator, approver, admin) limited to systems, audit log."""
from diysca.core.modules import Module


def _setup():
    from diysca.auth import rbac
    rbac.setup()


MODULE = Module(
    name="auth", title="Access", description="Single sign-on with OIDC, roles per IdP group, host scopes, audit log.",
    routes="diysca.auth.routes",
    settings_tabs=[("access", "/settings/access", "Access", 50)],
    setup=_setup,
    openapi_tags=[{"name": "auth", "description": "The caller's identity and role."}],
)
