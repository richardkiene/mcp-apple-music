"""
Apple Music MCP — One-time Setup Wizard
========================================
Run this script ONCE to:
  1. Enter your Apple Developer credentials (Team ID, Key ID, .p8 path).
  2. Authorise your Apple Music account via a local browser page.
  3. Save everything to ~/.config/mcp-apple-music/config.json

Usage:
    python -m mcp_apple_music.setup
    # or, after installation:
    mcp-apple-music-setup

    # the wizard's local callback port is configurable, for machines where
    # something already owns the default:
    mcp-apple-music-setup --port 8899
    MCP_APPLE_MUSIC_SETUP_PORT=8899 mcp-apple-music-setup
"""

import argparse
import hmac
import json
import os
import secrets
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse

from .auth import generate_developer_token
from .keysource import SOURCE_KEYS, PrivateKeyError, load_private_key

CONFIG_DIR = Path.home() / ".config" / "mcp-apple-music"
CONFIG_PATH = CONFIG_DIR / "config.json"

DEFAULT_PORT = 8888
PORT_ENV_VAR = "MCP_APPLE_MUSIC_SETUP_PORT"

# Loopback only — the served page carries the developer token, so this must
# never be reachable off-host.
BIND_HOST = "127.0.0.1"

# ------------------------------------------------------------------ #
#  HTML page served to the browser                                    #
# ------------------------------------------------------------------ #

_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Apple Music MCP — Setup</title>
  <script src="https://js-cdn.music.apple.com/musickit/v3/musickit.js"
          data-web-components async></script>
  <style>
    * { box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #f5f5f7;
      display: flex; justify-content: center; align-items: center;
      min-height: 100vh; margin: 0; padding: 20px;
    }
    .card {
      background: white; border-radius: 18px; padding: 48px 40px;
      max-width: 480px; width: 100%; text-align: center;
      box-shadow: 0 4px 30px rgba(0,0,0,0.08);
    }
    .logo { font-size: 56px; margin-bottom: 16px; }
    h1 { font-size: 22px; font-weight: 600; margin: 0 0 8px; }
    p  { color: #6e6e73; font-size: 15px; line-height: 1.5; margin: 0 0 32px; }
    button {
      background: #fc3c44; color: white; border: none;
      padding: 14px 32px; border-radius: 980px;
      font-size: 16px; font-weight: 500; cursor: pointer;
      transition: background .2s;
    }
    button:hover:not(:disabled) { background: #d92e35; }
    button:disabled { background: #c7c7cc; cursor: default; }
    #status {
      margin-top: 24px; font-size: 14px; color: #6e6e73; min-height: 20px;
    }
    .ok   { color: #34c759 !important; font-weight: 600; }
    .err  { color: #ff3b30 !important; }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">🎵</div>
    <h1>Apple Music MCP</h1>
    <p>Click the button below to authorise Claude to access your Apple Music library.</p>
    <button id="btn">Authorise Apple Music</button>
    <div id="status">Waiting…</div>
  </div>

  <script>
    document.addEventListener('musickitloaded', async () => {
      try {
        await MusicKit.configure({
          developerToken: '{{DEVELOPER_TOKEN}}',
          app: { name: 'MCP Apple Music', build: '1.0.0' }
        });
        document.getElementById('status').textContent = 'Ready — click the button to continue.';
      } catch (e) {
        document.getElementById('status').textContent = 'Error configuring MusicKit: ' + e.message;
        document.getElementById('status').className = 'err';
        document.getElementById('btn').disabled = true;
      }
    });

    document.getElementById('btn').addEventListener('click', async () => {
      const btn    = document.getElementById('btn');
      const status = document.getElementById('status');
      btn.disabled = true;
      status.textContent = 'Authorising… (sign in with your Apple ID if prompted)';
      status.className   = '';

      try {
        const music     = MusicKit.getInstance();
        const userToken = await music.authorize();

        status.textContent = 'Saving token…';
        // The nonce arrives in this page's own URL; echoing it back proves the
        // request came from the page the wizard opened, not a foreign origin.
        const nonce = new URLSearchParams(location.search).get('s') || '';
        const res = await fetch('/save_token', {
          method:  'POST',
          headers: { 'Content-Type': 'application/json' },
          body:    JSON.stringify({ token: userToken, nonce: nonce })
        });

        if (res.ok) {
          status.textContent = '✅  All done! You can close this tab and return to the terminal.';
          status.className   = 'ok';
        } else {
          throw new Error('Server responded with ' + res.status);
        }
      } catch (e) {
        status.textContent = 'Error: ' + e.message;
        status.className   = 'err';
        btn.disabled       = false;
      }
    });
  </script>
</body>
</html>
"""

# ------------------------------------------------------------------ #
#  Local HTTP server                                                  #
# ------------------------------------------------------------------ #

# A Music User Token is well under a kilobyte; refuse anything that isn't
# plausibly one rather than reading an unbounded body into memory.
_MAX_BODY_BYTES = 64 * 1024

_token_event: threading.Event = threading.Event()
_received_token: list[str] = []


class _Handler(BaseHTTPRequestHandler):
    """Minimal HTTP handler: serves the auth page and receives the token.

    Three checks guard both routes, because this server briefly holds a signed
    developer token and accepts a Music User Token:

      * Host   — a request whose Host header is not our own loopback origin is
                 a DNS-rebinding attempt; without this check a foreign page can
                 become same-origin with us and read the token out of the HTML.
      * nonce  — a per-run secret, delivered only in the URL the wizard opens.
                 An attacker who cannot read our page cannot guess it.
      * Origin — on POST only. A JSON body is not a CORS "simple request", but
                 text/plain is, so a cross-origin form-style POST would
                 otherwise reach us unpreflighted and plant a foreign token.
    """

    html: str = ""            # set on the class before starting the server
    nonce: str = ""           # per-run secret, compared in constant time
    allowed_hosts: frozenset = frozenset()
    allowed_origins: frozenset = frozenset()

    # -------------------------------------------------------------- #
    #  Guards                                                          #
    # -------------------------------------------------------------- #

    def _host_ok(self) -> bool:
        return self.headers.get("Host", "") in self.allowed_hosts

    def _nonce_ok(self, supplied: object) -> bool:
        return isinstance(supplied, str) and hmac.compare_digest(supplied, self.nonce)

    def _deny(self, code: int, reason: str) -> None:
        body = reason.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # -------------------------------------------------------------- #
    #  Routes                                                          #
    # -------------------------------------------------------------- #

    def do_GET(self) -> None:
        if not self._host_ok():
            return self._deny(403, "Forbidden: unexpected Host header.")

        parsed = urlparse(self.path)
        if parsed.path != "/":
            return self._deny(404, "Not found.")

        supplied = parse_qs(parsed.query).get("s", [""])[0]
        if not self._nonce_ok(supplied):
            return self._deny(403, "Forbidden: missing or invalid setup nonce.")

        body = self.html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # The page embeds a signed token; keep it out of caches and referrers.
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        if not self._host_ok():
            return self._deny(403, "Forbidden: unexpected Host header.")

        if urlparse(self.path).path != "/save_token":
            return self._deny(404, "Not found.")

        origin = self.headers.get("Origin")
        if origin is not None and origin not in self.allowed_origins:
            return self._deny(403, "Forbidden: cross-origin request rejected.")

        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return self._deny(400, "Bad request: invalid Content-Length.")
        if length <= 0 or length > _MAX_BODY_BYTES:
            return self._deny(400, "Bad request: unacceptable body size.")

        try:
            data = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return self._deny(400, "Bad request: body is not valid JSON.")
        if not isinstance(data, dict):
            return self._deny(400, "Bad request: expected a JSON object.")

        if not self._nonce_ok(data.get("nonce")):
            return self._deny(403, "Forbidden: missing or invalid setup nonce.")

        token = data.get("token")
        if not isinstance(token, str) or not token:
            return self._deny(400, "Bad request: missing token.")

        _received_token.append(token)

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

        _token_event.set()

    def log_message(self, *_) -> None:  # silence access logs
        pass


# ------------------------------------------------------------------ #
#  Config helpers                                                     #
# ------------------------------------------------------------------ #


def _load_existing() -> dict:
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            return json.load(f)
    return {}


def _save_config(cfg: dict) -> None:
    """Write config.json so it is never briefly readable by other users.

    Creating the file with open(..., "w") applies the process umask (commonly
    0644) and only narrows it afterwards, which leaves the Music User Token
    world-readable for the duration of the write. os.open with an explicit mode
    closes that window.
    """
    CONFIG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(CONFIG_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f, indent=2)
    # mkdir's mode is ignored when the directory already exists, and O_CREAT's
    # mode is ignored when the file does; enforce both for pre-existing paths.
    CONFIG_DIR.chmod(0o700)
    CONFIG_PATH.chmod(0o600)


def _ask(prompt: str, default: str = "") -> str:
    hint = f" [{default}]" if default else ""
    value = input(f"{prompt}{hint}: ").strip()
    return value or default


def _ask_key_source(cfg: dict) -> None:
    """Ask where the .p8 lives and record exactly one source key in cfg."""
    print("\n🔐  Where is your MusicKit .p8 signing key?")
    print("      1) 1Password  — recommended; the key never lands on disk")
    print("      2) A file on this machine")
    choice = _ask("  Choose", default="1")

    # Clear every source first: switching sources must not leave a stale one
    # behind, which would be rejected later as an ambiguous configuration.
    for key in SOURCE_KEYS:
        cfg.pop(key, None)

    if choice == "2":
        cfg["private_key_path"] = _ask(
            "  Path to .p8 file (e.g. ~/Downloads/AuthKey_XXXXXX.p8)"
        )
        return

    print("\n     In 1Password, right-click the .p8 attachment and choose")
    print("     'Copy Secret Reference'. It looks like:")
    print("         op://Private/MusicKit/AuthKey.p8\n")
    cfg["private_key_op_ref"] = _ask("  1Password secret reference")

    print("\n     Leave the next answer blank unless `op` is off your PATH.")
    print("     GUI-launched apps often need its absolute path here.")
    op_path = _ask("  Path to the `op` binary")
    if op_path:
        cfg["op_cli_path"] = op_path


def _resolve_port(argv: Optional[list[str]] = None) -> int:
    """Resolve the wizard's callback port: CLI flag > env var > default.

    The port is configurable because the default is a popular one; anything
    already bound to it (a container publishing 8888, say) would otherwise make
    the wizard unrunnable without editing the source.
    """
    parser = argparse.ArgumentParser(
        prog="mcp-apple-music-setup",
        description="One-time Apple Music authorisation wizard.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help=(
            "Local port for the browser callback "
            f"(default: ${PORT_ENV_VAR} or {DEFAULT_PORT})."
        ),
    )
    args = parser.parse_args(argv)

    if args.port is not None:
        port = args.port
        source = "--port"
    elif os.environ.get(PORT_ENV_VAR, "").strip():
        raw = os.environ[PORT_ENV_VAR].strip()
        try:
            port = int(raw)
        except ValueError:
            parser.error(f"{PORT_ENV_VAR} must be an integer, got {raw!r}")
        source = PORT_ENV_VAR
    else:
        return DEFAULT_PORT

    if not 1 <= port <= 65535:
        parser.error(f"{source} must be between 1 and 65535, got {port}")
    return port


# ------------------------------------------------------------------ #
#  Main                                                               #
# ------------------------------------------------------------------ #


def main() -> None:
    port = _resolve_port()

    print("\n🎵  Apple Music MCP — Setup Wizard\n" + "─" * 42 + "\n")

    cfg = _load_existing()
    if cfg:
        print(f"Found existing config at {CONFIG_PATH}")
        choice = input("  (r) Refresh token only  |  (u) Update all fields  |  (q) Quit  > ").strip().lower()
        if choice == "q":
            sys.exit(0)
        if choice != "r":
            cfg = {}

    # --- Gather credentials ---------------------------------------- #
    if not cfg.get("team_id"):
        print("\n📋  Apple Developer credentials")
        print("    (Find these at developer.apple.com → Account → Membership)\n")
        cfg["team_id"] = _ask("  Team ID")
        cfg["key_id"]  = _ask("  MusicKit Key ID")
        _ask_key_source(cfg)
        cfg["storefront"] = _ask("\n  Storefront country code", default="us")

    # --- Read and validate the signing key --------------------------- #
    # Done once, up front, so a bad path or an unreadable 1Password reference
    # fails here rather than at the first tool call. The key is then reused for
    # the token below, so a vault read prompts at most once per run.
    print("\n🔑  Reading the signing key…")
    try:
        private_key = load_private_key(cfg)
        print("    ✅  Key read and validated")
    except PrivateKeyError as exc:
        print(f"\n❌  {exc}")
        sys.exit(1)

    # --- Generate Developer Token ----------------------------------- #
    print("\n🔑  Generating Developer Token…")
    try:
        developer_token, _expiry = generate_developer_token(
            team_id=cfg["team_id"],
            key_id=cfg["key_id"],
            private_key=private_key,
        )
        print("    ✅  Developer Token OK")
    except Exception as exc:
        print(f"\n❌  Failed to generate Developer Token: {exc}")
        sys.exit(1)

    # --- Start local HTTP server ------------------------------------ #
    # Fresh secret per run. Only the browser we launch ever learns it, so a
    # page on another origin cannot read the developer token from us or plant
    # a token into our config.
    nonce = secrets.token_urlsafe(32)

    _Handler.html = _HTML.replace("{{DEVELOPER_TOKEN}}", developer_token)
    _Handler.nonce = nonce
    _Handler.allowed_hosts = frozenset(
        {f"{BIND_HOST}:{port}", f"localhost:{port}"}
    )
    _Handler.allowed_origins = frozenset(
        {f"http://{BIND_HOST}:{port}", f"http://localhost:{port}"}
    )

    try:
        server = HTTPServer((BIND_HOST, port), _Handler)
    except OSError as exc:
        print(f"\n❌  Cannot listen on {BIND_HOST}:{port} — {exc}")
        print(f"    Choose another port:  mcp-apple-music-setup --port 8899")
        sys.exit(1)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    url = f"http://{BIND_HOST}:{port}/?s={nonce}"
    print(f"\n🌐  Opening browser → {url}")
    print("    If it doesn't open automatically, paste the URL into your browser.")
    print("    The ?s= value is a one-time secret for this run — don't share it.\n")
    webbrowser.open(url)

    print("⏳  Waiting for you to authorise in the browser (timeout: 5 minutes)…\n")
    granted = _token_event.wait(timeout=300)

    server.shutdown()

    if not granted or not _received_token:
        print("❌  Timed out waiting for authorisation. Run the script again.")
        sys.exit(1)

    cfg["music_user_token"] = _received_token[0]
    _save_config(cfg)

    print(f"✅  Config saved to {CONFIG_PATH}")
    print("\n─" * 42)
    print("All done! Add the server to your Claude Desktop config:")
    print("""
  {
    "mcpServers": {
      "apple-music": {
        "command": "uv",
        "args": ["run", "--directory", "/path/to/mcp-apple-music", "mcp-apple-music"]
      }
    }
  }
""")


if __name__ == "__main__":
    main()
