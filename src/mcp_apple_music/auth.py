"""
Authentication module for Apple Music API.

Apple Music uses a two-token system:
  1. Developer Token  — a JWT you sign with your MusicKit private key (.p8).
                        Short-lived and regenerated on demand from the local
                        key, so there is no reason to mint one near Apple's
                        six-month ceiling; see DEVELOPER_TOKEN_TTL_SECONDS.
  2. Music User Token — obtained once via MusicKit JS in a browser.
                        Stored in ~/.config/mcp-apple-music/config.json.
                        Its ~6-month lifetime is set by Apple and is
                        independent of the developer token's expiry.

The signing key itself comes from exactly one source — a 1Password vault, a
file, or inline PEM content — resolved by the keysource module.

Configuration can be provided via:
  - Config file: ~/.config/mcp-apple-music/config.json  (default)
  - Environment variables (useful for Docker / CI):
      APPLE_TEAM_ID              Your Apple Developer Team ID
      APPLE_KEY_ID               Your MusicKit Key ID
      APPLE_PRIVATE_KEY          Full content of your .p8 private key
      APPLE_PRIVATE_KEY_OP_REF   1Password reference to the .p8 instead
      APPLE_MUSIC_USER_TOKEN     Your Music User Token
      APPLE_STOREFRONT           App Store storefront (default: us)
      OP_CLI_PATH                Absolute path to the `op` binary, if it is
                                 not on PATH (GUI launchers often lack it)
"""

import json
import os
import time
from pathlib import Path
from typing import Optional

import jwt  # PyJWT

from .keysource import load_private_key

DEFAULT_CONFIG_PATH = Path.home() / ".config" / "mcp-apple-music" / "config.json"

# Apple permits up to six months, but the token is re-signed from the local .p8
# whenever it is needed, so a long lifetime buys nothing and only widens the
# window in which a leaked token stays usable.
DEVELOPER_TOKEN_TTL_SECONDS = 3600  # 1 hour

# Re-sign this long before expiry rather than racing the deadline mid-request.
TOKEN_RENEWAL_MARGIN_SECONDS = 300  # 5 minutes


def generate_developer_token(
    team_id: str,
    key_id: str,
    private_key: str,
    ttl_seconds: int = DEVELOPER_TOKEN_TTL_SECONDS,
    now: Optional[float] = None,
) -> tuple[str, int]:
    """Sign an ES256 Developer Token.

    Returns:
        (token, expiry_epoch_seconds)
    """
    issued = int(now if now is not None else time.time())
    expiry = issued + ttl_seconds
    token = jwt.encode(
        payload={"iss": team_id, "iat": issued, "exp": expiry},
        key=private_key,
        algorithm="ES256",
        headers={"kid": key_id},
    )
    return token, expiry


class AppleMusicAuth:
    """Manages Developer Token generation and Music User Token retrieval."""

    def __init__(self, config_path: Path = DEFAULT_CONFIG_PATH):
        self.config_path = Path(config_path)
        self._config: Optional[dict] = None
        self._developer_token: Optional[str] = None
        self._token_expiry: float = 0
        # Cached for the process lifetime. Resolving the key can be expensive
        # and interactive — a 1Password read may raise a biometric prompt — so
        # the hourly token re-sign must not repeat it.
        self._private_key: Optional[str] = None

    # ------------------------------------------------------------------ #
    #  Config                                                              #
    # ------------------------------------------------------------------ #

    @property
    def config(self) -> dict:
        if self._config is None:
            self._config = self._load_config()
        return self._config

    def _load_config(self) -> dict:
        """Load config from environment variables first, then fall back to file."""
        # Try environment variables first (Docker / CI friendly)
        env_team_id = os.environ.get("APPLE_TEAM_ID", "").strip()
        env_key_id = os.environ.get("APPLE_KEY_ID", "").strip()
        env_private_key = os.environ.get("APPLE_PRIVATE_KEY", "").strip()
        env_op_ref = os.environ.get("APPLE_PRIVATE_KEY_OP_REF", "").strip()
        env_op_cli = os.environ.get("OP_CLI_PATH", "").strip()
        env_user_token = os.environ.get("APPLE_MUSIC_USER_TOKEN", "").strip()
        env_storefront = os.environ.get("APPLE_STOREFRONT", "").strip()

        if env_team_id and env_key_id and (env_private_key or env_op_ref):
            config = {
                "team_id": env_team_id,
                "key_id": env_key_id,
                "music_user_token": env_user_token,
                "storefront": env_storefront or "us",
            }
            # Set whatever is present and let keysource reject the ambiguity if
            # both are, rather than quietly preferring one here.
            if env_private_key:
                config["private_key_content"] = env_private_key
            if env_op_ref:
                config["private_key_op_ref"] = env_op_ref
            if env_op_cli:
                config["op_cli_path"] = env_op_cli
            return config

        # Fall back to config file
        if not self.config_path.exists():
            raise FileNotFoundError(
                f"\n❌  Config not found: {self.config_path}\n"
                "    Run the setup wizard first:\n\n"
                "        mcp-apple-music-setup\n\n"
                "    Or set environment variables:\n"
                "        APPLE_TEAM_ID, APPLE_KEY_ID, APPLE_MUSIC_USER_TOKEN,\n"
                "        APPLE_STOREFRONT, and one of APPLE_PRIVATE_KEY or\n"
                "        APPLE_PRIVATE_KEY_OP_REF\n"
            )
        with open(self.config_path) as f:
            return json.load(f)

    # ------------------------------------------------------------------ #
    #  Developer Token (JWT)                                               #
    # ------------------------------------------------------------------ #

    def get_developer_token(self) -> str:
        """Return a valid Developer Token, generating a new one if needed."""
        now = time.time()
        if self._developer_token and now < self._token_expiry - TOKEN_RENEWAL_MARGIN_SECONDS:
            return self._developer_token

        if self._private_key is None:
            self._private_key = load_private_key(self.config)

        self._developer_token, self._token_expiry = generate_developer_token(
            team_id=self.config["team_id"],
            key_id=self.config["key_id"],
            private_key=self._private_key,
            now=now,
        )
        return self._developer_token

    # ------------------------------------------------------------------ #
    #  Music User Token                                                    #
    # ------------------------------------------------------------------ #

    def get_music_user_token(self) -> str:
        """Return the Music User Token stored in config."""
        token = self.config.get("music_user_token", "")
        if not token:
            raise ValueError(
                "\n❌  Music User Token missing.\n"
                "    Run the setup wizard to authorise your Apple Music account:\n\n"
                "        mcp-apple-music-setup\n\n"
                "    Or set the APPLE_MUSIC_USER_TOKEN environment variable.\n"
            )
        return token

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #

    def get_storefront(self) -> str:
        """Return the two-letter storefront country code (e.g. 'it', 'us')."""
        return self.config.get("storefront", "us")

    def get_auth_headers(self) -> dict[str, str]:
        """Return the HTTP headers required by every Apple Music API request."""
        return {
            "Authorization": f"Bearer {self.get_developer_token()}",
            "Music-User-Token": self.get_music_user_token(),
        }

    def get_catalog_headers(self) -> dict[str, str]:
        """Headers for catalog-only requests (no user token required)."""
        return {"Authorization": f"Bearer {self.get_developer_token()}"}
