"""Developer token generation and private key loading."""

from cryptography.hazmat.primitives import serialization
import jwt
import pytest

from mcp_apple_music import auth


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


def test_read_private_key_prefers_inline_content(ec_private_key_pem):
    config = {"private_key_content": ec_private_key_pem}
    assert auth.read_private_key(config) == ec_private_key_pem


def test_read_private_key_unescapes_newlines_from_env_vars(ec_private_key_pem):
    """Env vars commonly carry the PEM with literal backslash-n sequences."""
    escaped = ec_private_key_pem.replace("\n", "\\n")
    assert auth.read_private_key({"private_key_content": escaped}) == ec_private_key_pem


def test_read_private_key_reads_from_path(tmp_path, ec_private_key_pem):
    p8 = tmp_path / "AuthKey_TEST.p8"
    p8.write_text(ec_private_key_pem)

    assert auth.read_private_key({"private_key_path": str(p8)}) == ec_private_key_pem


def test_read_private_key_fails_loudly_on_missing_file(tmp_path):
    missing = tmp_path / "nope.p8"

    with pytest.raises(FileNotFoundError, match="MusicKit private key not found"):
        auth.read_private_key({"private_key_path": str(missing)})


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
