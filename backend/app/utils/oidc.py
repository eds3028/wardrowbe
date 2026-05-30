import logging
import ssl
import time
from typing import Any

import httpx
import jwt
from jwt import PyJWKClient

from app.config import get_settings

logger = logging.getLogger(__name__)

_jwk_clients: dict[str, PyJWKClient] = {}
_jwks_cache_times: dict[str, float] = {}
JWKS_CACHE_TTL = 3600


def _get_jwk_client(jwks_uri: str, verify_tls: bool = True) -> PyJWKClient:
    now = time.time()
    cache_key = f"{jwks_uri}|verify={verify_tls}"
    cached_time = _jwks_cache_times.get(cache_key, 0)
    if cache_key in _jwk_clients and (now - cached_time) < JWKS_CACHE_TTL:
        return _jwk_clients[cache_key]

    ssl_context = None if verify_tls else ssl._create_unverified_context()
    client = PyJWKClient(jwks_uri, ssl_context=ssl_context)
    _jwk_clients[cache_key] = client
    _jwks_cache_times[cache_key] = now
    return client


def _token_debug_context(token: str) -> dict[str, Any]:
    """Return non-sensitive token metadata for validation logs."""
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        header = {}

    try:
        claims = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        claims = {}

    return {
        "alg": header.get("alg"),
        "kid_present": bool(header.get("kid")),
        "typ": header.get("typ"),
        "iss": claims.get("iss"),
        "aud": claims.get("aud"),
        "azp": claims.get("azp"),
        "scope_present": bool(claims.get("scope")),
        "claim_keys": sorted(claims.keys()),
    }


def _issuer_matches(token_issuer: str | None, valid_issuers: list[str]) -> bool:
    if not token_issuer:
        return False
    for valid_issuer in valid_issuers:
        if token_issuer == valid_issuer:
            return True
        # Some providers publish path-based issuer identifiers with a trailing slash while
        # deployment env vars are often normalized without one. Treat only this exact slash
        # difference as equivalent; all other issuer differences remain invalid.
        if token_issuer.rstrip("/") == valid_issuer.rstrip("/"):
            return True
    return False


def _unique_issuers(*issuers: str | None) -> list[str]:
    unique: list[str] = []
    for issuer in issuers:
        if issuer and issuer not in unique:
            unique.append(issuer)
    return unique


async def validate_oidc_id_token(
    id_token: str,
    issuer_url: str,
    client_id: str | list[str],
) -> dict:
    settings = get_settings()
    normalized_issuer = issuer_url.rstrip("/")
    verify_tls = not settings.oidc_skip_ssl_verify

    try:
        discovery_url = f"{normalized_issuer}/.well-known/openid-configuration"
        async with httpx.AsyncClient(
            timeout=10, verify=verify_tls, follow_redirects=True
        ) as client:
            disc_resp = await client.get(discovery_url)
            disc_resp.raise_for_status()
            discovery = disc_resp.json()
            jwks_uri = discovery["jwks_uri"]
            discovered_issuer = discovery.get("issuer")
    except httpx.HTTPError as e:
        logger.error("Failed to fetch OIDC discovery from %s: %s", issuer_url, e)
        raise ValueError("Failed to contact OIDC provider") from None
    except (KeyError, ValueError) as e:
        logger.error("OIDC discovery document from %s is invalid: %s", issuer_url, e)
        raise ValueError("Invalid OIDC provider configuration") from None

    audience = [client_id] if isinstance(client_id, str) else client_id
    valid_issuers = _unique_issuers(issuer_url, normalized_issuer, discovered_issuer)

    try:
        jwk_client = _get_jwk_client(jwks_uri, verify_tls=verify_tls)
        signing_key = jwk_client.get_signing_key_from_jwt(id_token)
        payload: dict[str, Any] = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256", "ES256"],
            audience=audience,
            options={"verify_exp": True, "verify_iss": False},
        )

        if not _issuer_matches(payload.get("iss"), valid_issuers):
            logger.warning(
                "OIDC ID token validation failed: invalid issuer. "
                "expected_one_of=%s token_context=%s",
                valid_issuers,
                _token_debug_context(id_token),
            )
            raise ValueError("Invalid OIDC token") from None
    except ValueError:
        raise
    except jwt.PyJWTError as e:
        logger.warning(
            "OIDC ID token validation failed: %s. token_context=%s",
            e,
            _token_debug_context(id_token),
        )
        raise ValueError("Invalid OIDC token") from None

    return payload
