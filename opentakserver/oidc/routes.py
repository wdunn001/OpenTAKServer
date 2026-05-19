"""Authentik OIDC blueprint routes.

Exposes:

* ``GET /api/oidc/config`` — public config introspection so the React SPA can
  decide whether to render the "Sign in with Mass Zero" button.
* ``GET /api/oidc/login`` — kicks off the authorization_code + PKCE flow by
  redirecting the browser to Authentik's authorization endpoint.
* ``GET /auth/login`` — minimal server-rendered login page (used by the
  Authentik strict redirect URI for the OTS web admin) so the OIDC flow
  works even when the SPA bundle is not in front of the API.
* ``GET /auth/callback`` — Authentik redirects here after consent; the
  handler exchanges the code for tokens, validates the id_token, finds-or-
  creates the local Flask-Security user, and logs them in.
* ``GET /api/oidc/logout`` — clears the local session and (if configured)
  redirects the browser to Authentik's ``end_session_endpoint`` so the SSO
  session is terminated upstream.

This blueprint is registered regardless of ``OIDC_ENABLED``; each route
short-circuits with a 404-like response when OIDC is disabled so the SPA
gets a deterministic "off" answer.
"""

from __future__ import annotations

import secrets
from typing import Optional

from flask import Blueprint
from flask import current_app as app
from flask import jsonify, redirect, request, session, url_for

from opentakserver.extensions import logger
from opentakserver.oidc.client import fetch_discovery, get_config

oidc_bp = Blueprint(
    "oidc",
    __name__,
    template_folder="templates",
)

# Session keys used to round-trip PKCE + nonce + state across the redirect.
_S_STATE = "_oidc_state"
_S_VERIFIER = "_oidc_code_verifier"
_S_NONCE = "_oidc_nonce"
_S_NEXT = "_oidc_next"
_S_ID_TOKEN = "_oidc_id_token"


def _disabled_response():
    return (
        jsonify({"success": False, "error": "OIDC is disabled"}),
        404,
    )


def _b64url_no_pad(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _pkce_pair() -> tuple[str, str]:
    """Return a ``(code_verifier, code_challenge)`` PKCE pair (S256)."""
    import hashlib

    verifier = _b64url_no_pad(secrets.token_bytes(64))
    challenge = _b64url_no_pad(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


@oidc_bp.route("/api/oidc/config", methods=["GET"])
def oidc_config():
    """Public introspection: is OIDC available, and what's the button label?"""
    cfg = get_config()
    return jsonify(
        {
            "enabled": cfg["enabled"],
            "issuer": cfg["issuer"] if cfg["enabled"] else "",
            "button_label": cfg["button_label"],
            "login_url": "/api/oidc/login",
        }
    )


@oidc_bp.route("/api/oidc/login", methods=["GET"])
def oidc_login():
    """Redirect the browser to Authentik's authorization endpoint (PKCE)."""
    cfg = get_config()
    if not cfg["enabled"]:
        return _disabled_response()

    try:
        discovery = fetch_discovery(cfg["issuer"])
    except Exception as e:  # pragma: no cover - network failure path
        logger.error(f"OIDC discovery failed: {e}")
        return (
            jsonify({"success": False, "error": "OIDC provider unreachable"}),
            502,
        )

    auth_endpoint = discovery.get("authorization_endpoint")
    if not auth_endpoint:
        return (
            jsonify(
                {"success": False, "error": "OIDC discovery missing authorization_endpoint"}
            ),
            502,
        )

    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    verifier, challenge = _pkce_pair()

    session[_S_STATE] = state
    session[_S_VERIFIER] = verifier
    session[_S_NONCE] = nonce
    # Where to land after a successful login; default to "/"
    session[_S_NEXT] = request.args.get("next", "/")

    from urllib.parse import urlencode

    params = {
        "response_type": "code",
        "client_id": cfg["client_id"],
        "redirect_uri": cfg["redirect_uri"],
        "scope": cfg["scopes"],
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    sep = "&" if "?" in auth_endpoint else "?"
    url = f"{auth_endpoint}{sep}{urlencode(params)}"
    logger.info(f"OIDC: redirecting to authorization endpoint for client {cfg['client_id']}")
    return redirect(url)


@oidc_bp.route("/auth/login", methods=["GET"])
def auth_login_page():
    """Minimal server-rendered login page.

    The Authentik strict redirect URI for the OTS web admin lives at
    ``/auth/callback``; this companion page lets a human land on
    ``https://tak.masszerofpv.com/auth/login`` and click the SSO button
    without depending on the SPA bundle. The default username/password
    Flask-Security login at ``/api/login`` remains the primary admin path.
    """
    cfg = get_config()
    # The styled template lands in commit 4 ("Sign in with Mass Zero" UI hook).
    # For now return a minimal placeholder so the route is wired and the
    # blueprint registers cleanly.
    if not cfg["enabled"]:
        return ("OIDC login is disabled.", 200, {"Content-Type": "text/plain"})
    return (
        f"<a href='/api/oidc/login'>{cfg['button_label']}</a>",
        200,
        {"Content-Type": "text/html"},
    )


@oidc_bp.route("/auth/callback", methods=["GET"])
def oidc_callback():
    """Placeholder — full token-exchange + user-provisioning lands in commit 3."""
    if not get_config()["enabled"]:
        return _disabled_response()
    return (
        jsonify(
            {
                "success": False,
                "error": "OIDC callback not yet implemented in this build",
            }
        ),
        501,
    )


@oidc_bp.route("/api/oidc/logout", methods=["GET", "POST"])
def oidc_logout():
    """Clear the local Flask-Security session and bounce to Authentik SLO."""
    from flask_security import logout_user

    id_token = session.pop(_S_ID_TOKEN, None)
    logout_user()
    session.clear()

    cfg = get_config()
    if cfg["enabled"] and cfg["logout_redirect"]:
        from opentakserver.oidc.client import end_session_url

        target: Optional[str] = end_session_url(id_token)
        if target:
            return redirect(target)
    # Fall back to the existing Flask-Security logout view.
    return redirect(url_for("security.login") if app.url_map.bind("").match else "/")
