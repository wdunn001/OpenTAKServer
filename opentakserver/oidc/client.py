"""Authentik OIDC client helpers.

Wraps the Authlib OAuth2 client with the OTS-specific config keys defined
in ``opentakserver.defaultconfig.DefaultConfig`` (OIDC_ISSUER, OIDC_CLIENT_ID,
OIDC_CLIENT_SECRET, OIDC_REDIRECT_URI, OIDC_SCOPES).

Authentik exposes its OIDC discovery document at::

    {OIDC_ISSUER}.well-known/openid-configuration

For the Mass Zero realm that's::

    https://auth.masszerofpv.com/application/o/mass-zero-tak/.well-known/openid-configuration

This module is intentionally side-effect-free at import time so the OIDC
blueprint can be imported (and smoke-tested) without a running Authentik
or a populated config.
"""

from __future__ import annotations

from typing import Any, Dict, Optional
from urllib.parse import urljoin

import requests
from flask import current_app

# Cache of resolved discovery documents, keyed by issuer URL.
_DISCOVERY_CACHE: Dict[str, Dict[str, Any]] = {}


def _normalize_issuer(issuer: str) -> str:
    """Ensure the issuer URL ends with a trailing slash so ``urljoin`` works."""
    if not issuer:
        return issuer
    return issuer if issuer.endswith("/") else issuer + "/"


def discovery_url(issuer: str) -> str:
    """Return the OIDC discovery URL for a given Authentik issuer."""
    return urljoin(_normalize_issuer(issuer), ".well-known/openid-configuration")


def fetch_discovery(issuer: str, *, timeout: float = 5.0) -> Dict[str, Any]:
    """Fetch and cache the OIDC discovery document for ``issuer``.

    Raises ``requests.HTTPError`` on a non-2xx response, ``ValueError`` if
    the issuer is empty.
    """
    if not issuer:
        raise ValueError("OIDC_ISSUER is not configured")

    normalized = _normalize_issuer(issuer)
    if normalized in _DISCOVERY_CACHE:
        return _DISCOVERY_CACHE[normalized]

    resp = requests.get(discovery_url(normalized), timeout=timeout)
    resp.raise_for_status()
    doc = resp.json()
    _DISCOVERY_CACHE[normalized] = doc
    return doc


def get_config() -> Dict[str, Any]:
    """Read the OIDC-relevant keys from the active Flask app config."""
    cfg = current_app.config
    return {
        "enabled": bool(cfg.get("OIDC_ENABLED")),
        "issuer": cfg.get("OIDC_ISSUER", ""),
        "client_id": cfg.get("OIDC_CLIENT_ID", ""),
        "client_secret": cfg.get("OIDC_CLIENT_SECRET", ""),
        "redirect_uri": cfg.get("OIDC_REDIRECT_URI", ""),
        "scopes": cfg.get("OIDC_SCOPES", "openid profile email"),
        "default_roles": cfg.get("OIDC_DEFAULT_ROLES", ["administrator"]),
        "button_label": cfg.get("OIDC_BUTTON_LABEL", "Sign in with Mass Zero"),
        "logout_redirect": bool(cfg.get("OIDC_LOGOUT_REDIRECT")),
    }


def get_oauth_client():
    """Return a lazily-constructed Authlib OAuth2 client for Authentik.

    Authlib is imported lazily so the OIDC blueprint can still be imported
    when ``authlib`` is not installed (e.g. during a partial Docker build
    or a unit-test environment that has not yet pulled the dep).
    """
    from authlib.integrations.requests_client import OAuth2Session  # type: ignore

    cfg = get_config()
    return OAuth2Session(
        client_id=cfg["client_id"],
        client_secret=cfg["client_secret"] or None,
        scope=cfg["scopes"],
        redirect_uri=cfg["redirect_uri"],
        token_endpoint_auth_method=(
            "client_secret_post" if cfg["client_secret"] else "none"
        ),
        code_challenge_method="S256",
    )


def end_session_url(id_token_hint: Optional[str] = None) -> Optional[str]:
    """Build an Authentik ``end_session_endpoint`` URL for SLO.

    Returns ``None`` if discovery has not run yet or the endpoint is missing.
    """
    cfg = get_config()
    try:
        doc = fetch_discovery(cfg["issuer"])
    except Exception:  # pragma: no cover - defensive
        return None
    endpoint = doc.get("end_session_endpoint")
    if not endpoint:
        return None
    if id_token_hint:
        sep = "&" if "?" in endpoint else "?"
        endpoint = f"{endpoint}{sep}id_token_hint={id_token_hint}"
    return endpoint
