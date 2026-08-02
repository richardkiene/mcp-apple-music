# mcp-apple-music 🎵

mcp-name: io.github.Cifero74/mcp-apple-music

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-compatible-green.svg)](https://modelcontextprotocol.io)

An **MCP (Model Context Protocol) server** that gives Claude full access to your Apple Music account — search the catalog, browse your personal library, manage playlists, and explore your listening history and recommendations.

> **Ask Claude things like:**
> - *"Based on what I've been listening to lately, recommend 15 songs I don't have yet and add them to a new playlist"*
> - *"Show me all my playlists and tell me which artists appear most"*
> - *"Search for albums by Nick Cave and add my three favourites to a playlist called Dark Picks"*

---

## Features

| Tool | Description |
|---|---|
| `search_catalog` | Search Apple Music catalog (songs, albums, artists, playlists) |
| `search_library` | Search within your personal library |
| `get_library_songs` | List songs saved in your library (paginated) |
| `get_library_albums` | List albums in your library (paginated) |
| `get_library_artists` | List artists in your library |
| `get_library_playlists` | List all your playlists with IDs |
| `get_playlist_tracks` | Get tracks inside a specific playlist |
| `create_playlist` | Create a new playlist |
| `add_tracks_to_playlist` | Add songs to a playlist (library or catalog tracks) |
| `get_recently_played` | See recently played albums/playlists/stations |
| `get_recommendations` | Get personalised Apple Music picks |

---

## Requirements

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip
- An **Apple Developer account** (free tier is fine) with a MusicKit key
- An active **Apple Music subscription**

---

## Setup

### 1. Create a MusicKit Key

1. Go to [developer.apple.com](https://developer.apple.com) → **Certificates, Identifiers & Profiles**
2. Under **Keys**, click **+** to create a new key
3. Give it any name, enable **MusicKit**, and click **Continue → Register**
4. **Download** the `.p8` file — you can only download it once, keep it safe!
5. Note your **Key ID** (e.g. `ABC123DEF4`) and your **Team ID** (found under *Membership Details*)

> ⚠️ The Key ID is the alphanumeric code shown next to the key name — **not** the filename of the `.p8` file.

### 2. Clone and install

```bash
git clone https://github.com/marioinghilleri/mcp-apple-music
cd mcp-apple-music

# with uv (recommended)
uv sync

# or with pip
pip install -e .
```

### 3. Run the one-time setup wizard

```bash
# with uv
uv run mcp-apple-music-setup

# or directly
python -m mcp_apple_music.setup
```

The wizard will ask for your **Team ID**, **Key ID**, and where your `.p8` lives — a **1Password reference** or a file path. It then opens a browser page where you click **"Authorise Apple Music"** — this uses Apple's official MusicKit JS to obtain your Music User Token, which is stored at `~/.config/mcp-apple-music/config.json`, created `0600` inside a `0700` directory.

The browser URL carries a `?s=` value: a one-time secret generated for that run. The wizard's local server refuses any request that doesn't present it, so don't share the URL. If you land on a `403`, you almost certainly opened `http://localhost:PORT` by hand instead of the full URL the wizard printed.

**Choosing a port.** The callback server defaults to `8888`. If something already owns that port, pick another:

```bash
uv run mcp-apple-music-setup --port 8899
# or
MCP_APPLE_MUSIC_SETUP_PORT=8899 uv run mcp-apple-music-setup
```

The flag wins over the environment variable. Apple doesn't need the port registered anywhere — MusicKit JS authorises in a popup rather than via a redirect URI.

---

## Keeping the `.p8` in 1Password

The signing key can come from a 1Password vault instead of a file, so it never lands on disk. Store the `.p8` as a file attachment on an item, then right-click the attachment and choose **Copy Secret Reference**:

```json
{
  "team_id": "XXXXXXXXXX",
  "key_id": "XXXXXXXXXX",
  "private_key_op_ref": "op://Private/MusicKit/AuthKey.p8",
  "storefront": "us"
}
```

The server resolves it with `op read` on first use and **caches the key in memory for the process lifetime**, so the hourly developer-token refresh doesn't re-prompt. You'll see at most one authorisation prompt per server start.

Your MCP client config stays a plain `uv run` command — no `op run` wrapper needed.

**Exactly one key source must be configured.** `private_key_op_ref`, `private_key_path`, and `private_key_content` are mutually exclusive; setting none or several is an error rather than a silent precedence decision, and a source that fails never falls through to another.

| Source | Config key | Environment variable |
|---|---|---|
| 1Password | `private_key_op_ref` | `APPLE_PRIVATE_KEY_OP_REF` |
| File on disk | `private_key_path` | — |
| Inline PEM | `private_key_content` | `APPLE_PRIVATE_KEY` |

**If `op` isn't found.** GUI-launched processes don't inherit your shell `PATH`, so Claude Desktop may not see `/opt/homebrew/bin/op`. Set `op_cli_path` in `config.json` or `OP_CLI_PATH` in the environment to its absolute path. Launching via `claude mcp add` inherits your shell PATH and is unaffected.

**Headless and Docker.** Set `OP_SERVICE_ACCOUNT_TOKEN`; `op` reads it directly, so no extra configuration is needed here.

### 4. Add to Claude Desktop

Open your Claude Desktop config:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "apple-music": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/absolute/path/to/mcp-apple-music",
        "mcp-apple-music"
      ]
    }
  }
}
```

Restart Claude Desktop — you should see the apple-music tools available in the toolbar.

---

## How it works

Apple Music requires two separate tokens:

- **Developer Token** — a JWT you sign locally with your `.p8` private key, which can live in [1Password](#keeping-the-p8-in-1password) rather than on disk. Minted with a **1-hour** lifetime and re-signed on demand from the local key. Apple permits up to 6 months, but since the token is regenerated whenever it's needed, a long lifetime buys nothing and only widens the window in which a leaked token stays usable. Your key never leaves your machine.
- **Music User Token** — obtained once via MusicKit JS OAuth in the browser (the setup wizard handles this). Stored locally at `~/.config/mcp-apple-music/config.json`. Apple sets its ~6-month lifetime; it is *not* capped by the developer token's expiry, so the short developer TTL above costs you nothing.

```
Your .p8 key  ──►  Developer Token (JWT, auto-renewed)  ─┐
                                                           ├──► Apple Music API
Browser OAuth ──►  Music User Token (stored locally)    ─┘
```

> ⚠️ **Playback control** (play/pause/skip) is not available via Apple's REST API. It requires native MusicKit frameworks (iOS/macOS app) or MusicKit JS running in a browser context.
>
> For playback control, check out [chrome-relay](https://chrome-relay.kushalsm.com) — a companion CLI that lets an MCP server drive a `music.apple.com` tab already open in Chrome, enabling play/pause/skip without shipping a MusicKit JS shim.

---

## Project structure

```
mcp-apple-music/
├── src/
│   └── mcp_apple_music/
│       ├── __init__.py
│       ├── auth.py      — Developer Token generation + User Token management
│       ├── keysource.py — Resolves the .p8 from 1Password, a file, or inline
│       ├── client.py    — Async HTTP client for api.music.apple.com
│       ├── server.py    — FastMCP server with all 11 tools
│       └── setup.py     — One-time setup wizard (browser-based OAuth)
├── tests/               — pytest suite (auth, wizard guards, URL handling)
├── config.example.json  — Example config structure (no secrets)
├── pyproject.toml
└── README.md
```

Run the tests with:

```bash
uv sync
uv run pytest tests/ -q
```

---

## Security notes

This fork hardens several things against the upstream code. What's covered:

- **The setup wizard's local server** requires a per-run nonce on both routes, validates the `Host` header, and validates `Origin` on the token callback. Without these, a page on another origin could plant a foreign Music User Token via a preflight-dodging `text/plain` POST, and a DNS-rebinding attacker could read the signed developer token out of the served HTML.
- **Developer tokens live 1 hour**, not the 6-month maximum.
- **`config.json` is created `0600`** via `os.open` rather than created at the process umask and narrowed afterwards.
- **Playlist IDs are percent-encoded** before entering the URL path. `httpx` resolves `..` segments, so an unencoded ID could retarget a request at a different Apple Music endpoint.

What is **not** addressed, and worth knowing:

- **Tool output is untrusted input.** Song, album, and playlist names — including playlist descriptions — come from Apple's catalog and flow into the model's context verbatim. Anyone who can get content into that catalog controls text your assistant reads, and this server exposes `create_playlist` and `add_tracks_to_playlist`. There is no delete or purchase tool, so the blast radius is bounded, but treat "read my library and act on it" prompts with the same caution you'd apply to any untrusted input.
- **A Music User Token is library-scoped.** It cannot touch your subscription, Apple ID, or payment methods. Revoking the MusicKit key at developer.apple.com invalidates the pairing.

---

## Example prompts

Once connected, you can ask Claude:

```
"What have I been listening to this week? Based on that, find 10 songs
 I don't own yet that I'd probably enjoy and create a playlist with them."

"Search for all albums by Joni Mitchell and tell me which ones
 I already have in my library."

"List my playlists, pick the one that looks most like a workout mix,
 and add 5 high-energy songs from the catalog to it."

"Create a playlist called 'Rainy Sunday' with the 10 most mellow tracks
 you can find from my library."
```

---

## Authors

Built by **[Cifero74](https://github.com/Cifero74)** and **[Claude](https://claude.ai)** (Anthropic) as part of a personal MCP ecosystem for Claude Desktop.

This project was conceived, designed, debugged, and shipped entirely through a collaborative conversation between Mario and Claude — from API research and auth flow design, through the setup wizard, to live testing with a real Apple Music library.

Contributions, issues and PRs are welcome!

---

## License

[MIT](LICENSE) — use it, fork it, build on it.
