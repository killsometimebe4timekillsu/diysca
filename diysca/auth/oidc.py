"""OpenID Connect login (authorization code flow with PKCE).

Works with Keycloak, Microsoft Entra ID, Authentik, Zitadel, Okta, Google, GitLab, Dex and other OIDC providers.

    oidc:
      issuer: https://sso.example.org/realms/acme
      client_id: diysca
      client_secret: ...          # or client_secret_env: DIYSCA_OIDC_SECRET
      scopes: [openid, profile, email, groups]
      username_claim: preferred_username
      groups_claim: groups        # dotted paths work: realm_access.roles

The ID token comes straight from the provider's token endpoint over TLS, so (as the OIDC spec allows for
this flow) its signature isn't checked; issuer, audience, expiry and nonce are.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
from urllib.parse import urlencode

import httpx

from diysca.core.config import settings
from diysca.core.security import safe_next

_discovery: dict = {}


class OIDCError(Exception):
    pass


def configured() -> bool:
    o = settings.oidc or {}
    return bool(o.get("issuer") and o.get("client_id"))


def _secret() -> str:
    o = settings.oidc or {}
    if o.get("client_secret_env"):
        return os.environ.get(o["client_secret_env"], "")
    return str(o.get("client_secret") or "")


def redirect_uri() -> str:
    return (settings.oidc or {}).get("redirect_uri") or settings.base_url.rstrip("/") + "/auth/callback"


def _client() -> httpx.Client:
    return httpx.Client(timeout=settings.http_timeout, verify=settings.http_proxy_ca or True)


def discovery(transport=None) -> dict:
    issuer = settings.oidc["issuer"].rstrip("/")
    cached = _discovery.get(issuer)
    if cached and cached["_at"] > time.time() - 3600:
        return cached
    with (httpx.Client(transport=transport) if transport else _client()) as c:
        r = c.get(issuer + "/.well-known/openid-configuration")
    if r.status_code != 200:
        raise OIDCError(f"discovery failed: HTTP {r.status_code}")
    d = r.json()
    if d.get("issuer", "").rstrip("/") != issuer:
        raise OIDCError(f"issuer mismatch: {d.get('issuer')} != {issuer}")
    d["_at"] = time.time()
    _discovery[issuer] = d
    return d


def start(next_url: str = "/", transport=None) -> tuple[str, dict]:
    """-> (authorization URL, flow state to keep in a short-lived signed cookie)."""
    d = discovery(transport)
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    scopes = settings.oidc.get("scopes") or ["openid", "profile", "email"]
    params = {"response_type": "code", "client_id": settings.oidc["client_id"], "redirect_uri": redirect_uri(),
              "scope": " ".join(scopes) if isinstance(scopes, list) else str(scopes), "state": state, "nonce": nonce,
              "code_challenge": challenge, "code_challenge_method": "S256"}
    return d["authorization_endpoint"] + "?" + urlencode(params), \
        {"state": state, "nonce": nonce, "verifier": verifier, "next": safe_next(next_url)}


def _claims_from_jwt(token: str) -> dict:
    try:
        payload = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (IndexError, ValueError) as e:
        raise OIDCError("malformed ID token") from e


def claim(claims: dict, path: str):
    cur = claims
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def finish(code: str, state: str, flow: dict, transport=None) -> dict:
    """Exchange the code, check the ID token. -> {"name", "email", "groups", "claims"}."""
    if not flow or not secrets.compare_digest(str(flow.get("state", "")), state or ""):
        raise OIDCError("login state mismatch (expired or opened in another browser); try again")
    d = discovery(transport)
    data = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri(),
            "client_id": settings.oidc["client_id"], "code_verifier": flow["verifier"]}
    if _secret():
        data["client_secret"] = _secret()
    with (httpx.Client(transport=transport) if transport else _client()) as c:
        r = c.post(d["token_endpoint"], data=data, headers={"Accept": "application/json"})
        if r.status_code != 200:
            raise OIDCError(f"token exchange failed: HTTP {r.status_code} {r.text[:200]}")
        tok = r.json()
        if "id_token" not in tok:
            raise OIDCError("the provider returned no ID token (is 'openid' in scopes?)")
        claims = _claims_from_jwt(tok["id_token"])
        iss = d["issuer"].rstrip("/")
        aud = claims.get("aud")
        auds = aud if isinstance(aud, list) else [aud]
        if str(claims.get("iss", "")).rstrip("/") != iss:
            raise OIDCError("ID token: wrong issuer")
        if settings.oidc["client_id"] not in auds:
            raise OIDCError("ID token: wrong audience")
        if float(claims.get("exp", 0)) < time.time() - 60:
            raise OIDCError("ID token expired")
        if claims.get("nonce") != flow.get("nonce"):
            raise OIDCError("ID token: nonce mismatch")
        gclaim = settings.oidc.get("groups_claim") or "groups"
        if claim(claims, gclaim) is None and d.get("userinfo_endpoint") and tok.get("access_token"):
            u = c.get(d["userinfo_endpoint"], headers={"Authorization": f"Bearer {tok['access_token']}"})
            if u.status_code == 200:
                claims = {**u.json(), **claims}
    uclaim = settings.oidc.get("username_claim") or "preferred_username"
    name = claim(claims, uclaim) or claims.get("email") or claims.get("sub")
    groups = claim(claims, gclaim) or []
    if isinstance(groups, str):
        groups = [g.strip() for g in groups.split(",")]
    groups = [str(g).lstrip("/") for g in groups]  # Keycloak full-path groups: /secops -> secops
    return {"name": str(name), "email": str(claims.get("email") or ""), "groups": groups, "claims": claims}


def logout_url() -> str | None:
    try:
        d = discovery()
    except (OIDCError, httpx.HTTPError):
        return None
    if not d.get("end_session_endpoint"):
        return None
    return d["end_session_endpoint"] + "?" + urlencode({"client_id": settings.oidc["client_id"],
                                                        "post_logout_redirect_uri": settings.base_url.rstrip("/") + "/login"})
