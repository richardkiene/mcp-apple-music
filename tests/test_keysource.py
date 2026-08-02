"""Key source resolution, the 1Password subprocess, and PEM validation.

No test touches a real vault. The subprocess wiring is proven against a fake
`op` executable written to tmp_path; everything else is monkeypatched.
"""

import os
import stat
import subprocess
import textwrap

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
import jwt
import pytest

from mcp_apple_music import keysource
from mcp_apple_music.keysource import (
    FileKeySource,
    InlineKeySource,
    OnePasswordKeySource,
    PrivateKeyError,
    load_private_key,
    resolve_key_source,
    validate_pem,
)

OP_REF = "op://Private/MusicKit/AuthKey.p8"


def _fake_op(tmp_path, *, stdout="", stderr="", exit_code=0, name="op"):
    """Write an executable stand-in for the 1Password CLI."""
    script = tmp_path / name
    script.write_text(
        textwrap.dedent(
            f"""\
            #!/bin/sh
            printf '%s' "{stdout}"
            printf '%s' "{stderr}" >&2
            exit {exit_code}
            """
        )
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


# ---------------------------------------------------------------- #
#  Source selection                                                 #
# ---------------------------------------------------------------- #


def test_op_reference_selects_the_onepassword_source():
    source = resolve_key_source({"private_key_op_ref": OP_REF})

    assert isinstance(source, OnePasswordKeySource)
    assert source.reference == OP_REF
    assert source.op_binary == "op"


def test_op_cli_path_overrides_the_binary():
    source = resolve_key_source(
        {"private_key_op_ref": OP_REF, "op_cli_path": "/opt/homebrew/bin/op"}
    )

    assert source.op_binary == "/opt/homebrew/bin/op"


def test_path_source_expands_the_user_directory():
    source = resolve_key_source({"private_key_path": "~/keys/AuthKey.p8"})

    assert isinstance(source, FileKeySource)
    assert "~" not in str(source.path)


def test_inline_source_is_selected_from_content():
    assert isinstance(
        resolve_key_source({"private_key_content": "-----BEGIN"}), InlineKeySource
    )


def test_no_configured_source_is_an_error_listing_the_options():
    with pytest.raises(PrivateKeyError) as exc:
        resolve_key_source({"team_id": "TEAM123456"})

    message = str(exc.value)
    assert "private_key_op_ref" in message
    assert "private_key_path" in message
    assert "private_key_content" in message


def test_two_configured_sources_are_an_error_naming_the_conflict():
    """No precedence chain: ambiguity fails rather than silently picking one."""
    with pytest.raises(PrivateKeyError) as exc:
        resolve_key_source(
            {"private_key_op_ref": OP_REF, "private_key_path": "/tmp/AuthKey.p8"}
        )

    message = str(exc.value)
    assert "private_key_op_ref" in message
    assert "private_key_path" in message


def test_blank_values_do_not_count_as_configured():
    with pytest.raises(PrivateKeyError, match="No MusicKit private key configured"):
        resolve_key_source({"private_key_op_ref": "   ", "private_key_path": ""})


# ---------------------------------------------------------------- #
#  1Password subprocess                                             #
# ---------------------------------------------------------------- #


def test_op_read_returns_the_secret(tmp_path, ec_private_key_pem):
    op = _fake_op(tmp_path, stdout="PEM-CONTENT")
    assert OnePasswordKeySource(OP_REF, op_binary=op).read() == "PEM-CONTENT"


def test_op_is_invoked_with_read_and_the_reference(tmp_path, monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="PEM", stderr="")

    monkeypatch.setattr(keysource.subprocess, "run", fake_run)
    OnePasswordKeySource(OP_REF, op_binary="/usr/local/bin/op").read()

    assert calls == [["/usr/local/bin/op", "read", OP_REF]]


def test_missing_op_binary_names_the_escape_hatch(tmp_path):
    source = OnePasswordKeySource(OP_REF, op_binary=str(tmp_path / "not-installed"))

    with pytest.raises(PrivateKeyError) as exc:
        source.read()

    assert "op_cli_path" in str(exc.value)
    assert "OP_CLI_PATH" in str(exc.value)


def test_nonzero_exit_surfaces_stderr(tmp_path):
    op = _fake_op(
        tmp_path, stdout="", stderr="could not resolve item", exit_code=1
    )

    with pytest.raises(PrivateKeyError) as exc:
        OnePasswordKeySource(OP_REF, op_binary=op).read()

    assert "could not resolve item" in str(exc.value)
    assert OP_REF in str(exc.value)


def test_nonzero_exit_does_not_echo_stdout(tmp_path):
    """stdout is where secret material would be; only stderr may be reported."""
    op = _fake_op(tmp_path, stdout="SECRET-LEAKED", stderr="boom", exit_code=1)

    with pytest.raises(PrivateKeyError) as exc:
        OnePasswordKeySource(OP_REF, op_binary=op).read()

    assert "SECRET-LEAKED" not in str(exc.value)


def test_silent_failure_still_reports_the_exit_status(tmp_path):
    op = _fake_op(tmp_path, exit_code=7)

    with pytest.raises(PrivateKeyError, match="exit status 7"):
        OnePasswordKeySource(OP_REF, op_binary=op).read()


def test_timeout_is_reported_as_a_locked_vault(monkeypatch):
    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, timeout=60)

    monkeypatch.setattr(keysource.subprocess, "run", fake_run)

    with pytest.raises(PrivateKeyError) as exc:
        OnePasswordKeySource(OP_REF).read()

    assert "Timed out" in str(exc.value)
    assert "locked" in str(exc.value)


def test_timeout_is_bounded_so_a_prompt_cannot_wedge_the_server(monkeypatch):
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["timeout"] = kwargs.get("timeout")
        return subprocess.CompletedProcess(cmd, 0, stdout="PEM", stderr="")

    monkeypatch.setattr(keysource.subprocess, "run", fake_run)
    OnePasswordKeySource(OP_REF).read()

    assert seen["timeout"] == keysource.OP_READ_TIMEOUT_SECONDS
    assert 0 < seen["timeout"] <= 120


def test_op_source_does_not_unescape_newlines(monkeypatch):
    """A file attachment returns real newlines; normalising would hide a fault."""

    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout="a\\nb", stderr="")

    monkeypatch.setattr(keysource.subprocess, "run", fake_run)
    assert OnePasswordKeySource(OP_REF).read() == "a\\nb"


# ---------------------------------------------------------------- #
#  File and inline sources                                          #
# ---------------------------------------------------------------- #


def test_file_source_reads_the_key(tmp_path, ec_private_key_pem):
    p8 = tmp_path / "AuthKey_TEST.p8"
    p8.write_text(ec_private_key_pem)

    assert FileKeySource(p8).read() == ec_private_key_pem


def test_missing_file_fails_loudly(tmp_path):
    with pytest.raises(PrivateKeyError, match="MusicKit private key not found"):
        FileKeySource(tmp_path / "nope.p8").read()


def test_inline_source_unescapes_newlines(ec_private_key_pem):
    """Environment variables routinely carry the PEM escaped."""
    escaped = ec_private_key_pem.replace("\n", "\\n")

    assert InlineKeySource(escaped).read() == ec_private_key_pem


# ---------------------------------------------------------------- #
#  PEM validation                                                   #
# ---------------------------------------------------------------- #


def test_valid_p256_key_passes(ec_private_key_pem):
    assert validate_pem(ec_private_key_pem, "test") == ec_private_key_pem


def test_garbage_is_rejected():
    with pytest.raises(PrivateKeyError, match="not a readable"):
        validate_pem("not a key at all", "test")


def test_truncated_pem_is_rejected(ec_private_key_pem):
    with pytest.raises(PrivateKeyError, match="not a readable"):
        validate_pem(ec_private_key_pem[: len(ec_private_key_pem) // 2], "test")


def test_whitespace_variation_is_tolerated_because_the_key_still_signs(
    ec_private_key_pem,
):
    """OpenSSL's PEM reader is whitespace-tolerant, so a field that turned the
    newlines into spaces still yields a usable key. Validation accepts it
    because rejecting a key that signs correctly would be a false alarm.
    """
    spaced = ec_private_key_pem.replace("\n", " ")

    assert validate_pem(spaced, "test") == spaced
    # Not just parseable — actually usable for the signing we do.
    assert jwt.encode({"iss": "TEAM123456"}, spaced, algorithm="ES256")


def test_corrupted_base64_body_is_rejected(ec_private_key_pem):
    """Whitespace tolerance does not extend to damaged key material."""
    lines = ec_private_key_pem.splitlines()
    lines[2] = "AAAA" + lines[2][4:]

    with pytest.raises(PrivateKeyError):
        validate_pem("\n".join(lines), "test")


def test_rsa_key_is_rejected_with_a_useful_message():
    rsa_pem = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        .decode()
    )

    with pytest.raises(PrivateKeyError, match="elliptic-curve"):
        validate_pem(rsa_pem, "test")


def test_wrong_curve_is_rejected():
    """ES256 is P-256 specifically; another EC curve will not sign correctly."""
    p384 = (
        ec.generate_private_key(ec.SECP384R1())
        .private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        .decode()
    )

    with pytest.raises(PrivateKeyError, match="P-256"):
        validate_pem(p384, "test")


def test_validation_error_names_the_origin_not_the_key(ec_private_key_pem):
    with pytest.raises(PrivateKeyError) as exc:
        validate_pem("garbage", f"1Password reference {OP_REF}")

    assert OP_REF in str(exc.value)


# ---------------------------------------------------------------- #
#  End to end through load_private_key                              #
# ---------------------------------------------------------------- #


def test_load_from_1password_resolves_reads_and_validates(monkeypatch, ec_private_key_pem):
    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout=ec_private_key_pem, stderr="")

    monkeypatch.setattr(keysource.subprocess, "run", fake_run)

    assert load_private_key({"private_key_op_ref": OP_REF}) == ec_private_key_pem


def test_load_from_1password_rejects_a_non_key_payload(monkeypatch):
    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout="hunter2", stderr="")

    monkeypatch.setattr(keysource.subprocess, "run", fake_run)

    with pytest.raises(PrivateKeyError, match="not a readable"):
        load_private_key({"private_key_op_ref": OP_REF})
