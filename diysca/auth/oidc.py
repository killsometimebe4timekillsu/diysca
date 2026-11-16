"""OpenID Connect login (authorization code flow with PKCE).

Works with Keycloak, Microsoft Entra ID, Authentik, Zitadel, Okta, Google, GitLab, Dex and other OIDC providers.

    oidc:
      issuer: https://sso.example.org/realms/acme
      client_id: diysca
      client_secret: ...          # or client_secret_env: DIYSCA_OIDC_SECRET
      scopes: [openid, profile, email, groups]
      username_claim: preferred_username
      groups_claim: groups        # dotted paths work: realm_access.roles

      verify_signature: true      # check the ID token's signature against the provider's keys (jwks_uri)

The ID token's signature is checked against the provider's published keys (RS*, PS*, ES* algorithms, or HS*
with the client secret), and so are issuer, audience, expiry and nonce. "alg: none" is always refused.
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


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _claims_from_jwt(token: str) -> dict:
    try:
        return json.loads(_b64d(token.split(".")[1]))
    except (IndexError, ValueError) as e:
        raise OIDCError("malformed ID token") from e


# ------------------------------------------------------------------ signatures
_jwks_cache: dict[str, dict] = {}
_HASH = {"256": "SHA256", "384": "SHA384", "512": "SHA512"}


def _jwks(d: dict, transport=None, refresh: bool = False) -> list[dict]:
    uri = d.get("jwks_uri")
    if not uri:
        raise OIDCError("the provider publishes no jwks_uri, so the ID token signature can't be checked")
    cached = _jwks_cache.get(uri)
    if cached and not refresh and cached["_at"] > time.time() - 3600:
        return cached["keys"]
    with (httpx.Client(transport=transport) if transport else _client()) as c:
        r = c.get(uri)
    if r.status_code != 200:
        raise OIDCError(f"loading the provider's keys failed: HTTP {r.status_code}")
    keys = [k for k in (r.json().get("keys") or []) if isinstance(k, dict)]
    _jwks_cache[uri] = {"_at": time.time(), "keys": keys}
    return keys


def _public_key(jwk: dict):
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    if jwk.get("kty") == "RSA":
        n, e = (int.from_bytes(_b64d(jwk[k]), "big") for k in ("n", "e"))
        return rsa.RSAPublicNumbers(e, n).public_key()
    if jwk.get("kty") == "EC":
        curve = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1, "P-521": ec.SECP521R1}[jwk["crv"]]()
        x, y = (int.from_bytes(_b64d(jwk[k]), "big") for k in ("x", "y"))
        return ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
    raise OIDCError(f"unsupported key type {jwk.get('kty')}")


def _check(alg: str, key_or_secret, signed: bytes, sig: bytes) -> bool:
    import hmac as _hmac

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    h = getattr(hashes, _HASH[alg[2:]])()
    try:
        if alg.startswith("HS"):
            return _hmac.compare_digest(_hmac.new(key_or_secret, signed, alg.replace("HS", "sha")).digest(), sig)
        if alg.startswith("RS"):
            key_or_secret.verify(sig, signed, padding.PKCS1v15(), h)
        elif alg.startswith("PS"):
            key_or_secret.verify(sig, signed, padding.PSS(padding.MGF1(h), h.digest_size), h)
        elif alg.startswith("ES"):
            half = len(sig) // 2
            der = encode_dss_signature(int.from_bytes(sig[:half], "big"), int.from_bytes(sig[half:], "big"))
            key_or_secret.verify(der, signed, ec.ECDSA(h))
        else:
            return False
        return True
    except InvalidSignature:
        return False


ALGS = {f"{p}{n}" for p in ("RS", "PS", "ES", "HS") for n in ("256", "384", "512")}


def verify_signature(token: str, d: dict, transport=None):
    """Raise OIDCError unless `token` is signed by one of the provider's keys (or, for HS*, the client secret)."""
    try:
        head_b64, body_b64, sig_b64 = token.split(".")
        header, sig = json.loads(_b64d(head_b64)), _b64d(sig_b64)
    except ValueError as e:
        raise OIDCError("malformed ID token") from e
    alg = str(header.get("alg") or "")
    if alg not in ALGS:
        raise OIDCError(f"ID token: algorithm '{alg}' is not accepted")
    signed = f"{head_b64}.{body_b64}".encode()
    if alg.startswith("HS"):
        if not _secret() or not _check(alg, _secret().encode(), signed, sig):
            raise OIDCError("ID token: bad signature")
        return
    kty = "EC" if alg.startswith("ES") else "RSA"
    for refresh in (False, True):  # unknown kid: the provider may have rotated its keys
        keys = [k for k in _jwks(d, transport, refresh) if k.get("kty") == kty and k.get("use", "sig") == "sig"
                and (not header.get("kid") or k.get("kid") == header["kid"])]
        if keys:
            break
    if not keys:
        raise OIDCError("ID token: no provider key matches it")
    for k in keys:
        try:
            if _check(alg, _public_key(k), signed, sig):
                return
        except (KeyError, ValueError):
            continue
    raise OIDCError("ID token: bad signature")


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
        if settings.oidc.get("verify_signature", True) is not False:
            verify_signature(tok["id_token"], d, transport)
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
    # An address the provider says it has not verified must not match an `email:` binding.
    email = "" if claims.get("email_verified") in (False, "false") else str(claims.get("email") or "")
    return {"name": str(name), "email": email, "groups": groups, "claims": claims}


def logout_url() -> str | None:
    try:
        d = discovery()
    except (OIDCError, httpx.HTTPError):
        return None
    if not d.get("end_session_endpoint"):
        return None
    return d["end_session_endpoint"] + "?" + urlencode({"client_id": settings.oidc["client_id"],
                                                        "post_logout_redirect_uri": settings.base_url.rstrip("/") + "/login"})
