"""Developer token generation and private key loading."""

import subprocess

from cryptography.hazmat.primitives import serialization
import jwt
import pytest

from mcp_apple_music import auth, keysource


def _public_pem(private_pem: str) -> str:
    """Derive the verifying key so signatures can be checked, not just decoded."""
    key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def test_token_ttl_is_one_hour_not_apple_maximum(ec_private_key_pem):
    """The token is re-signed on demand, so it must not be minted long-lived.

    Regression guard for the original 15,777,000s (~6 month) lifetime, which
    left a leaked token usable for half a year to no benefit.
    """
    token, expiry = auth.generate_developer_token(
        team_id="TEAM123456",
        key_id="KEY1234567",
        private_key=ec_private_key_pem,
        now=1_000_000,
    )

    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["iat"] == 1_000_000
    assert claims["exp"] == 1_000_000 + 3600
    assert expiry == 1_000_000 + 3600
    assert auth.DEVELOPER_TOKEN_TTL_SECONDS == 3600


def test_token_carries_team_and_key_identifiers(ec_private_key_pem):
    token, _ = auth.generate_developer_token(
        team_id="TEAM123456",
        key_id="KEY1234567",
        private_key=ec_private_key_pem,
    )

    assert jwt.get_unverified_header(token)["kid"] == "KEY1234567"
    assert jwt.get_unverified_header(token)["alg"] == "ES256"
    assert jwt.decode(token, options={"verify_signature": False})["iss"] == "TEAM123456"


def test_token_verifies_against_the_signing_key(ec_private_key_pem):
    """A malformed token would still decode unverified; prove the signature."""
    token, _ = auth.generate_developer_token(
        team_id="TEAM123456",
        key_id="KEY1234567",
        private_key=ec_private_key_pem,
    )

    claims = jwt.decode(token, _public_pem(ec_private_key_pem), algorithms=["ES256"])
    assert claims["iss"] == "TEAM123456"


def test_cached_token_is_reused_until_the_renewal_margin(ec_private_key_pem, tmp_path):
    """Signing on every request would be wasteful; signing too late would race."""
    instance = auth.AppleMusicAuth(config_path=tmp_path / "absent.json")
    instance._config = {
        "team_id": "TEAM123456",
        "key_id": "KEY1234567",
        "private_key_content": ec_private_key_pem,
    }

    first = instance.get_developer_token()
    assert instance.get_developer_token() is first

    # Push the clock past the renewal margin; the next call must re-sign.
    instance._token_expiry = 0
    assert instance.get_developer_token() is not first


def test_private_key_is_resolved_once_across_token_regenerations(
    monkeypatch, ec_private_key_pem, tmp_path
):
    """Resolving the key can be interactive — a 1Password read may raise a
    biometric prompt — so the hourly re-sign must reuse the cached PEM.
    """
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout=ec_private_key_pem, stderr="")

    monkeypatch.setattr(keysource.subprocess, "run", fake_run)

    instance = auth.AppleMusicAuth(config_path=tmp_path / "absent.json")
    instance._config = {
        "team_id": "TEAM123456",
        "key_id": "KEY1234567",
        "private_key_op_ref": "op://Private/MusicKit/AuthKey.p8",
    }

    first = instance.get_developer_token()
    instance._token_expiry = 0
    second = instance.get_developer_token()
    instance._token_expiry = 0
    instance.get_developer_token()

    assert second is not first, "token should have been re-signed"
    assert len(calls) == 1, f"1Password consulted {len(calls)} times, expected 1"
