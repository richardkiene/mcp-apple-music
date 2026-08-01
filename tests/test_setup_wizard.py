"""Setup wizard: port resolution, HTTP guards, and config file permissions.

The HTTP tests replay attacks that succeeded against the original handler:

    OPTIONS /save_token          -> 501 Unsupported method
    POST text/plain              -> 200 {"ok":true}   token planted
    GET / with Host: evil.com    -> 200, developer token readable in body

Each is now expected to be refused.
"""

import contextlib
import http.client
import json
import os
import stat
import threading
from http.server import HTTPServer

import pytest

from mcp_apple_music import setup

NONCE = "test-nonce-value"
PAGE_BODY = "<html>DEVELOPER_TOKEN_eyJhbGciOiJFUzI1NiJ9.sentinel</html>"


@contextlib.contextmanager
def running_wizard():
    """Start the real handler on an ephemeral loopback port."""
    setup._received_token.clear()
    setup._token_event.clear()

    server = HTTPServer(("127.0.0.1", 0), setup._Handler)
    port = server.server_address[1]

    setup._Handler.html = PAGE_BODY
    setup._Handler.nonce = NONCE
    setup._Handler.allowed_hosts = frozenset(
        {f"127.0.0.1:{port}", f"localhost:{port}"}
    )
    setup._Handler.allowed_origins = frozenset(
        {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}
    )

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _request(port, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


# ---------------------------------------------------------------- #
#  GET / — developer token disclosure                               #
# ---------------------------------------------------------------- #


def test_page_is_served_with_the_correct_nonce():
    with running_wizard() as port:
        status, body = _request(port, "GET", f"/?s={NONCE}")

    assert status == 200
    assert b"sentinel" in body


def test_page_is_withheld_without_the_nonce():
    with running_wizard() as port:
        status, body = _request(port, "GET", "/")

    assert status == 403
    assert b"sentinel" not in body


def test_page_is_withheld_with_a_wrong_nonce():
    with running_wizard() as port:
        status, body = _request(port, "GET", "/?s=guessed")

    assert status == 403
    assert b"sentinel" not in body


def test_foreign_host_header_cannot_read_the_developer_token():
    """DNS rebinding: attacker makes their page same-origin with us.

    Previously returned 200 with the token in the body.
    """
    with running_wizard() as port:
        status, body = _request(
            port, "GET", f"/?s={NONCE}", headers={"Host": "evil.example.com"}
        )

    assert status == 403
    assert b"sentinel" not in body


# ---------------------------------------------------------------- #
#  POST /save_token — token planting                                #
# ---------------------------------------------------------------- #


def test_token_is_accepted_with_a_valid_nonce_and_origin():
    with running_wizard() as port:
        status, _ = _request(
            port,
            "POST",
            "/save_token",
            body=json.dumps({"token": "USER_TOKEN", "nonce": NONCE}),
            headers={
                "Content-Type": "application/json",
                "Origin": f"http://127.0.0.1:{port}",
            },
        )

        assert status == 200
        assert setup._received_token == ["USER_TOKEN"]
        assert setup._token_event.is_set()


def test_simple_request_post_without_nonce_is_refused():
    """The original CSRF: text/plain dodges CORS preflight entirely.

    Previously returned 200 and planted the attacker's token.
    """
    with running_wizard() as port:
        status, _ = _request(
            port,
            "POST",
            "/save_token",
            body=json.dumps({"token": "ATTACKER_TOKEN"}),
            headers={"Content-Type": "text/plain"},
        )

        assert status == 403
        assert setup._received_token == []
        assert not setup._token_event.is_set()


def test_post_from_a_foreign_origin_is_refused_even_with_a_nonce():
    with running_wizard() as port:
        status, _ = _request(
            port,
            "POST",
            "/save_token",
            body=json.dumps({"token": "ATTACKER_TOKEN", "nonce": NONCE}),
            headers={
                "Content-Type": "application/json",
                "Origin": "http://evil.example.com",
            },
        )

        assert status == 403
        assert setup._received_token == []


def test_post_with_foreign_host_is_refused():
    with running_wizard() as port:
        status, _ = _request(
            port,
            "POST",
            "/save_token",
            body=json.dumps({"token": "ATTACKER_TOKEN", "nonce": NONCE}),
            headers={"Host": "evil.example.com", "Content-Type": "application/json"},
        )

        assert status == 403
        assert setup._received_token == []


def test_oversized_body_is_refused():
    with running_wizard() as port:
        status, _ = _request(
            port,
            "POST",
            "/save_token",
            body=json.dumps({"token": "x" * 100_000, "nonce": NONCE}),
            headers={"Content-Type": "application/json"},
        )

        assert status == 400
        assert setup._received_token == []


def test_malformed_json_is_refused_without_raising():
    with running_wizard() as port:
        status, _ = _request(
            port,
            "POST",
            "/save_token",
            body="not json at all",
            headers={"Content-Type": "application/json"},
        )

        assert status == 400
        assert setup._received_token == []


def test_missing_token_field_is_refused():
    with running_wizard() as port:
        status, _ = _request(
            port,
            "POST",
            "/save_token",
            body=json.dumps({"nonce": NONCE}),
            headers={"Content-Type": "application/json"},
        )

        assert status == 400
        assert setup._received_token == []


def test_unknown_routes_are_not_found():
    with running_wizard() as port:
        assert _request(port, "GET", f"/secrets?s={NONCE}")[0] == 404
        assert _request(port, "POST", "/elsewhere")[0] == 404


# ---------------------------------------------------------------- #
#  Port resolution                                                  #
# ---------------------------------------------------------------- #


def test_port_defaults_when_unconfigured(monkeypatch):
    monkeypatch.delenv(setup.PORT_ENV_VAR, raising=False)
    assert setup._resolve_port([]) == setup.DEFAULT_PORT


def test_env_var_overrides_the_default(monkeypatch):
    monkeypatch.setenv(setup.PORT_ENV_VAR, "8899")
    assert setup._resolve_port([]) == 8899


def test_cli_flag_beats_the_env_var(monkeypatch):
    monkeypatch.setenv(setup.PORT_ENV_VAR, "8899")
    assert setup._resolve_port(["--port", "9099"]) == 9099


@pytest.mark.parametrize("bad", ["0", "65536", "-1"])
def test_out_of_range_ports_are_rejected(monkeypatch, bad):
    monkeypatch.delenv(setup.PORT_ENV_VAR, raising=False)
    with pytest.raises(SystemExit):
        setup._resolve_port(["--port", bad])


def test_non_numeric_env_var_is_rejected(monkeypatch):
    monkeypatch.setenv(setup.PORT_ENV_VAR, "not-a-port")
    with pytest.raises(SystemExit):
        setup._resolve_port([])


# ---------------------------------------------------------------- #
#  Config file permissions                                          #
# ---------------------------------------------------------------- #


def test_config_is_created_owner_only_never_widened_later(monkeypatch, tmp_path):
    """The token must not exist on disk world-readable, even momentarily.

    Asserting the final mode would pass against the old chmod-after-write code,
    so this asserts the mode requested at creation time.
    """
    config_dir = tmp_path / "mcp-apple-music"
    config_path = config_dir / "config.json"
    monkeypatch.setattr(setup, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(setup, "CONFIG_PATH", config_path)

    requested_modes = []
    real_open = os.open

    def recording_open(path, flags, mode=0o777, *args, **kwargs):
        if str(path) == str(config_path):
            requested_modes.append(mode)
        return real_open(path, flags, mode, *args, **kwargs)

    monkeypatch.setattr(os, "open", recording_open)

    previous_umask = os.umask(0o000)  # a permissive umask must not widen the file
    try:
        setup._save_config({"music_user_token": "SECRET"})
    finally:
        os.umask(previous_umask)

    assert requested_modes == [0o600], "config must be created with 0600, not chmod'd after"
    assert stat.S_IMODE(config_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(config_dir.stat().st_mode) == 0o700
    assert json.loads(config_path.read_text())["music_user_token"] == "SECRET"


def test_existing_loose_permissions_are_tightened(monkeypatch, tmp_path):
    """O_CREAT's mode is ignored for a file that already exists."""
    config_dir = tmp_path / "mcp-apple-music"
    config_dir.mkdir(mode=0o755)
    config_path = config_dir / "config.json"
    config_path.write_text("{}")
    config_path.chmod(0o644)

    monkeypatch.setattr(setup, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(setup, "CONFIG_PATH", config_path)

    setup._save_config({"music_user_token": "SECRET"})

    assert stat.S_IMODE(config_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(config_dir.stat().st_mode) == 0o700
