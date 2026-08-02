"""Shared fixtures for the mcp-apple-music test suite."""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import pytest


@pytest.fixture
def ec_private_key_pem() -> str:
    """A throwaway P-256 key, the curve Apple requires for ES256 signing."""
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
