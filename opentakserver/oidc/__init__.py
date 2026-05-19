"""Authentik OIDC authentication for the OpenTAKServer web UI.

Adds an additive OIDC login path against the Mass Zero Authentik realm
(application slug ``mass-zero-tak``). The existing Flask-Security
username/password and LDAP paths are left untouched; this module only
runs when ``OIDC_ENABLED`` is True in the OTS config.
"""

from opentakserver.oidc.routes import oidc_bp

__all__ = ["oidc_bp"]
