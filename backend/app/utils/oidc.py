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


async def validate_oidc_id_token(
    id_token: str,
    issuer_url: str,
    client_id: str | list[str],
) -> dict:
    settings = get_settings()

    try:
        normalized_issuer = issuer_url.rstrip("/")
        verify_tls = not settings.oidc_skip_ssl_verify
        discovery_url = f"{normalized_issuer}/.well-known/openid-configuration"
        async with httpx.AsyncClient(
            timeout=10, verify=verify_tls, follow_redirects=True
        ) as client:
            disc_resp = await client.get(discovery_url)
            disc_resp.raise_for_status()
            jwks_uri = disc_resp.json()["jwks_uri"]
    except httpx.HTTPError as e:
        logger.error("Failed to fetch OIDC discovery from %s: %s", issuer_url, e)
        raise ValueError("Failed to contact OIDC provider") from None

    audience = [client_id] if isinstance(client_id, str) else client_id

    try:
        jwk_client = _get_jwk_client(jwks_uri, verify_tls=not settings.oidc_skip_ssl_verify)
        signing_key = jwk_client.get_signing_key_from_jwt(id_token)
        payload: dict[str, Any] = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256", "ES256"],
            audience=audience,
            issuer=issuer_url.rstrip("/"),
            options={"verify_exp": True},
        )
    except jwt.PyJWTError:
        raise ValueError("Invalid OIDC token") from None

    return payload
