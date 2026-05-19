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
    """Exchange the authorization code, validate the id_token, sign the user in.

    Flow:

    1. Verify the ``state`` matches what we stashed in the session on
       ``/api/oidc/login``.
    2. POST to Authentik's ``token_endpoint`` with code + PKCE verifier +
       (optional) client_secret. Authlib handles JWKS fetch + id_token
       signature validation when ``parse_id_token`` is used.
    3. Look up the local Flask-Security ``User`` by email (preferred) or
       preferred_username; if missing, create one with the configured
       default roles (``OIDC_DEFAULT_ROLES``, default ``["administrator"]``).
    4. Call ``flask_security.login_user`` so the session cookie is the
       same one the rest of OTS already trusts.
    """
    cfg = get_config()
    if not cfg["enabled"]:
        return _disabled_response()

    expected_state = session.pop(_S_STATE, None)
    verifier = session.pop(_S_VERIFIER, None)
    expected_nonce = session.pop(_S_NONCE, None)
    next_url = session.pop(_S_NEXT, "/") or "/"

    state = request.args.get("state")
    code = request.args.get("code")
    error = request.args.get("error")

    if error:
        logger.warning(f"OIDC callback received error from Authentik: {error}")
        return (
            jsonify({"success": False, "error": f"OIDC error: {error}"}),
            400,
        )
    if not state or not code:
        return (
            jsonify(
                {"success": False, "error": "OIDC callback missing state or code"}
            ),
            400,
        )
    if not expected_state or state != expected_state:
        logger.warning("OIDC callback state mismatch — possible CSRF or stale session")
        return (
            jsonify({"success": False, "error": "OIDC state mismatch"}),
            400,
        )
    if not verifier:
        return (
            jsonify({"success": False, "error": "OIDC PKCE verifier missing"}),
            400,
        )

    try:
        discovery = fetch_discovery(cfg["issuer"])
    except Exception as e:
        logger.error(f"OIDC discovery failed during callback: {e}")
        return (
            jsonify({"success": False, "error": "OIDC provider unreachable"}),
            502,
        )

    token_endpoint = discovery.get("token_endpoint")
    jwks_uri = discovery.get("jwks_uri")
    if not token_endpoint or not jwks_uri:
        return (
            jsonify(
                {
                    "success": False,
                    "error": "OIDC discovery missing token_endpoint or jwks_uri",
                }
            ),
            502,
        )

    # Exchange the code for tokens.
    try:
        from authlib.integrations.requests_client import OAuth2Session
        from authlib.jose import JsonWebKey, jwt
    except ImportError as e:
        logger.error(f"authlib not installed: {e}")
        return (
            jsonify({"success": False, "error": "authlib not installed"}),
            500,
        )

    auth_method = "client_secret_post" if cfg["client_secret"] else "none"
    try:
        oauth = OAuth2Session(
            client_id=cfg["client_id"],
            client_secret=cfg["client_secret"] or None,
            scope=cfg["scopes"],
            redirect_uri=cfg["redirect_uri"],
            token_endpoint_auth_method=auth_method,
            code_challenge_method="S256",
        )
        token = oauth.fetch_token(
            token_endpoint,
            grant_type="authorization_code",
            code=code,
            code_verifier=verifier,
            redirect_uri=cfg["redirect_uri"],
        )
    except Exception as e:
        logger.error(f"OIDC token exchange failed: {e}")
        return (
            jsonify({"success": False, "error": "OIDC token exchange failed"}),
            502,
        )

    id_token_raw = token.get("id_token")
    if not id_token_raw:
        return (
            jsonify({"success": False, "error": "OIDC token response missing id_token"}),
            502,
        )

    # Fetch + validate JWKS-signed id_token.
    import requests as _requests

    try:
        jwks_resp = _requests.get(jwks_uri, timeout=5.0)
        jwks_resp.raise_for_status()
        key_set = JsonWebKey.import_key_set(jwks_resp.json())
        claims = jwt.decode(
            id_token_raw,
            key_set,
            claims_options={
                "iss": {"essential": True, "value": cfg["issuer"].rstrip("/")},
                "aud": {"essential": True, "value": cfg["client_id"]},
                "exp": {"essential": True},
            },
        )
        claims.validate(leeway=30)
    except Exception as e:
        # Authentik's issuer claim sometimes lacks/has a trailing slash relative
        # to the configured value; retry without the strict iss option as a
        # safety net before failing hard.
        logger.warning(f"OIDC id_token strict validation failed ({e}); retrying lax")
        try:
            claims = jwt.decode(
                id_token_raw,
                key_set,
                claims_options={
                    "aud": {"essential": True, "value": cfg["client_id"]},
                    "exp": {"essential": True},
                },
            )
            claims.validate(leeway=30)
        except Exception as e2:
            logger.error(f"OIDC id_token validation failed: {e2}")
            return (
                jsonify({"success": False, "error": "OIDC id_token invalid"}),
                401,
            )

    # Nonce binding: the id_token's nonce must match what we sent.
    token_nonce = claims.get("nonce")
    if expected_nonce and token_nonce != expected_nonce:
        logger.warning("OIDC nonce mismatch")
        return (
            jsonify({"success": False, "error": "OIDC nonce mismatch"}),
            400,
        )

    email = claims.get("email")
    preferred_username = claims.get("preferred_username") or claims.get("sub")
    if not email and not preferred_username:
        return (
            jsonify(
                {
                    "success": False,
                    "error": "OIDC id_token has no email or preferred_username",
                }
            ),
            400,
        )

    # Find-or-create the local user.
    from flask_security import hash_password, login_user

    from opentakserver.extensions import db

    datastore = app.security.datastore
    user = None
    if email:
        user = datastore.find_user(email=email)
    if not user and preferred_username:
        user = datastore.find_user(username=preferred_username)

    if not user:
        # Provision a new local user mapped to this SSO identity.
        username = preferred_username or (email.split("@")[0] if email else None)
        if not username:
            return (
                jsonify(
                    {"success": False, "error": "OIDC user has no derivable username"}
                ),
                400,
            )
        roles = [r.strip() for r in cfg["default_roles"] if r and r.strip()]
        # Ensure the roles exist before assigning.
        for role_name in roles:
            datastore.find_or_create_role(name=role_name)

        # Generate a random password the user will never need to use; OIDC
        # is the auth path and Flask-Security still requires a hashed value.
        random_pw = secrets.token_urlsafe(32)
        logger.info(
            f"OIDC: provisioning new user '{username}' (email={email}) with roles={roles}"
        )
        user = datastore.create_user(
            username=username,
            email=email,
            password=hash_password(random_pw),
            roles=roles,
            active=True,
        )
        db.session.commit()
    else:
        # Keep the email column in sync if Authentik now has one and we don't.
        if email and not user.email:
            user.email = email
            db.session.add(user)
            db.session.commit()

    if not user.active:
        logger.warning(f"OIDC: refusing login — user {user.username} is deactivated")
        return (
            jsonify({"success": False, "error": "User account is deactivated"}),
            403,
        )

    # Stash the id_token for SLO on logout.
    session[_S_ID_TOKEN] = id_token_raw

    login_user(user)
    logger.info(f"OIDC: signed in user {user.username} via Authentik")

    # Only allow same-origin relative redirects.
    if not next_url.startswith("/"):
        next_url = "/"
    return redirect(next_url)


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
