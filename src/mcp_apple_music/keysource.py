"""Resolve the MusicKit signing key from exactly one configured source.

The key may come from a 1Password vault, a file on disk, or inline PEM content
supplied through an environment variable.

Exactly one source must be configured. An ambiguous configuration is an error
rather than a silent precedence decision, and a source that fails never falls
through to another one — a key that cannot be read is a hard stop, not a reason
to go looking elsewhere.
"""

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

DEFAULT_OP_BINARY = "op"

# Long enough for a human to answer a biometric prompt, short enough that an
# unattended one cannot wedge the MCP server on a tool call.
OP_READ_TIMEOUT_SECONDS = 60.0

#: Config keys that select a source, in the order they are reported to users.
SOURCE_KEYS = ("private_key_op_ref", "private_key_path", "private_key_content")


class PrivateKeyError(RuntimeError):
    """The signing key could not be resolved, read, or validated."""


class PrivateKeySource(Protocol):
    """Somewhere a PEM-encoded MusicKit private key can be read from."""

    def describe(self) -> str:
        """Human-readable origin, for error messages. Must not leak the key."""

    def read(self) -> str:
        """Return the PEM text, or raise PrivateKeyError."""


@dataclass(frozen=True)
class InlineKeySource:
    """A PEM carried directly in configuration, typically an environment var."""

    content: str

    def describe(self) -> str:
        return "inline key content"

    def read(self) -> str:
        # Environment variables routinely carry PEM data with the newlines
        # escaped; restore them before the key is validated.
        return self.content.replace("\\n", "\n")


@dataclass(frozen=True)
class FileKeySource:
    """A .p8 file on the local filesystem."""

    path: Path

    def describe(self) -> str:
        return f"file {self.path}"

    def read(self) -> str:
        if not self.path.exists():
            raise PrivateKeyError(f"MusicKit private key not found: {self.path}")
        return self.path.read_text()


@dataclass(frozen=True)
class OnePasswordKeySource:
    """A secret reference resolved through the 1Password CLI.

    The reference itself is not a secret — it names a location, not a value —
    so it is safe to store in config.json and to quote in error messages.
    """

    reference: str
    op_binary: str = DEFAULT_OP_BINARY
    timeout: float = OP_READ_TIMEOUT_SECONDS

    def describe(self) -> str:
        return f"1Password reference {self.reference}"

    def read(self) -> str:
        try:
            result = subprocess.run(
                [self.op_binary, "read", self.reference],
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            raise PrivateKeyError(
                f"1Password CLI not found: {self.op_binary!r}.\n"
                "    Install it, or point 'op_cli_path' in config.json (or the\n"
                "    OP_CLI_PATH environment variable) at its absolute path.\n"
                "    GUI-launched processes do not inherit your shell PATH, so\n"
                "    an absolute path is often required there."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise PrivateKeyError(
                f"Timed out after {self.timeout:.0f}s reading {self.reference} "
                "from 1Password.\n"
                "    The vault may be locked and waiting on an unanswered "
                "authorisation prompt."
            ) from exc

        if result.returncode != 0:
            # Report stderr only: stdout is where secret material would be.
            detail = result.stderr.strip() or f"exit status {result.returncode}"
            raise PrivateKeyError(
                f"1Password could not read {self.reference}:\n    {detail}"
            )

        return result.stdout


def resolve_key_source(config: dict) -> PrivateKeySource:
    """Pick the single configured key source, or explain why we cannot."""
    configured = [key for key in SOURCE_KEYS if str(config.get(key) or "").strip()]

    if not configured:
        raise PrivateKeyError(
            "No MusicKit private key configured. Set exactly one of:\n"
            "    private_key_op_ref   1Password reference, e.g.\n"
            "                         op://Private/MusicKit/AuthKey.p8\n"
            "    private_key_path     path to your .p8 file\n"
            "    private_key_content  the PEM itself (APPLE_PRIVATE_KEY)"
        )

    if len(configured) > 1:
        raise PrivateKeyError(
            "More than one MusicKit private key source is configured: "
            f"{', '.join(configured)}.\n"
            "    Set exactly one so there is no ambiguity about which key signs."
        )

    (selected,) = configured

    if selected == "private_key_op_ref":
        return OnePasswordKeySource(
            reference=config["private_key_op_ref"].strip(),
            op_binary=str(config.get("op_cli_path") or DEFAULT_OP_BINARY),
        )
    if selected == "private_key_path":
        return FileKeySource(Path(config["private_key_path"]).expanduser())
    return InlineKeySource(config["private_key_content"])


def validate_pem(pem: str, origin: str) -> str:
    """Confirm the PEM is an EC private key on P-256, the curve ES256 requires.

    Applied to every source, so a truncated file and a mangled vault field fail
    the same way — at load time, with a clear message, rather than as an opaque
    signing error later.
    """
    try:
        key = serialization.load_pem_private_key(pem.encode(), password=None)
    except (ValueError, TypeError) as exc:
        raise PrivateKeyError(
            f"Key from {origin} is not a readable unencrypted PEM private key: {exc}"
        ) from exc

    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise PrivateKeyError(
            f"Key from {origin} is a {type(key).__name__}, but Apple's ES256 "
            "signing requires an elliptic-curve key."
        )
    if not isinstance(key.curve, ec.SECP256R1):
        raise PrivateKeyError(
            f"Key from {origin} uses curve {key.curve.name}, but ES256 requires "
            "P-256 (secp256r1)."
        )
    return pem


def load_private_key(config: dict) -> str:
    """Resolve, read, and validate the configured MusicKit private key."""
    source = resolve_key_source(config)
    return validate_pem(source.read(), source.describe())
