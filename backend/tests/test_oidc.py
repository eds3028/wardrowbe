from unittest.mock import patch

import pytest

from app.utils.oidc import _issuer_matches, validate_oidc_id_token


class _FakeDiscoveryResponse:
    def raise_for_status(self):
        return None

    def json(self):
        return {
            "issuer": "https://auth.example.com/application/o/wardrowbe/",
            "jwks_uri": "https://auth.example.com/application/o/wardrowbe/jwks/",
        }


class _FakeAsyncClient:
    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def get(self, url):
        assert (
            url
            == "https://auth.example.com/application/o/wardrowbe/.well-known/openid-configuration"
        )
        return _FakeDiscoveryResponse()


class _FakeSigningKey:
    key = "public-key"


class _FakeJwkClient:
    def get_signing_key_from_jwt(self, token):
        assert token == "signed-id-token"
        return _FakeSigningKey()


def test_issuer_matches_allows_only_trailing_slash_difference():
    assert _issuer_matches(
        "https://auth.example.com/application/o/wardrowbe/",
        ["https://auth.example.com/application/o/wardrowbe"],
    )
    assert not _issuer_matches(
        "https://auth.example.com/application/o/other/",
        ["https://auth.example.com/application/o/wardrowbe"],
    )


@pytest.mark.asyncio
async def test_validate_oidc_id_token_accepts_discovered_trailing_slash_issuer():
    decoded_claims = {
        "iss": "https://auth.example.com/application/o/wardrowbe/",
        "sub": "user-123",
        "aud": "client-id",
        "email": "user@example.com",
    }

    with (
        patch("app.utils.oidc.httpx.AsyncClient", _FakeAsyncClient),
        patch("app.utils.oidc._get_jwk_client", return_value=_FakeJwkClient()),
        patch("app.utils.oidc.jwt.decode", return_value=decoded_claims) as decode,
    ):
        claims = await validate_oidc_id_token(
            "signed-id-token",
            "https://auth.example.com/application/o/wardrowbe/",
            "client-id",
        )

    assert claims == decoded_claims
    _, kwargs = decode.call_args
    assert kwargs["audience"] == ["client-id"]
    assert kwargs["options"]["verify_iss"] is False
