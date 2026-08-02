# Loading the MusicKit private key from 1Password

**Date:** 2026-08-01
**Status:** Approved, not yet implemented

## Problem

The MusicKit `.p8` signing key can only be supplied two ways: a path to a file
on disk (`private_key_path`) or the PEM inline in an environment variable
(`private_key_content`). Both leave the key sitting in cleartext somewhere a
backup or a stray `cat` can reach.

The key should be loadable from a 1Password vault instead, without ever landing
on disk.

## Approach

Add a third key source that resolves an `op://` secret reference through the
1Password CLI at runtime.

Resolution happens once per process. `AppleMusicAuth` already caches the signed
developer token; it will cache the resolved PEM alongside it, so the hourly
token re-sign reuses the in-memory key rather than consulting 1Password again.
One authorisation prompt per server start, not one per hour.

### Rejected alternatives

**`op run` wrapper.** Requires no code, but wraps every launch command and puts
the PEM in the process environment. The setup wizard would need wrapping
separately, and the MCP client config stops being a plain `uv run` invocation.

**Resolve once at setup time and write the PEM into `config.json`.** Simplest,
but the key ends up on disk anyway, which is the thing this is meant to avoid.

## Module layout

`read_private_key()` is currently a precedence chain inside `auth.py`. A third
branch makes it worse, so key resolution moves to its own module.

```
src/mcp_apple_music/
  keysource.py   NEW — config -> validated PEM
  auth.py        token minting only; imports keysource
  setup.py       wizard; prompts for a source, test-reads it
```

`keysource.py` exposes:

```python
class PrivateKeySource(Protocol):
    def read(self) -> str: ...

class InlineKeySource:        # private_key_content
class FileKeySource:          # private_key_path
class OnePasswordKeySource:   # private_key_op_ref

def resolve_key_source(config: dict) -> PrivateKeySource
def load_private_key(config: dict) -> str    # resolve + read + validate
```

Sources are stateless. Caching lives in `AppleMusicAuth`.

`auth.read_private_key()` is removed rather than kept as a re-export — it is
internal API with two call sites, both updated. Its existing tests move from
`tests/test_auth.py` to `tests/test_keysource.py` alongside the code they now
exercise.

## Configuration

Exactly one source must be configured. Zero is an error naming all three
options; two or more is an error naming the conflict. There is no precedence
order — ambiguous config fails rather than silently picking a winner.

| Config key | Environment variable | Value |
|---|---|---|
| `private_key_op_ref` | `APPLE_PRIVATE_KEY_OP_REF` | `op://Private/MusicKit/AuthKey.p8` |
| `private_key_path` | — | `~/Downloads/AuthKey_ABC123.p8` |
| `private_key_content` | `APPLE_PRIVATE_KEY` | `-----BEGIN PRIVATE KEY-----...` |
| `op_cli_path` | `OP_CLI_PATH` | `/opt/homebrew/bin/op` (optional) |

The key is stored as a **file attachment** on a 1Password item, so `op read`
returns the file's bytes with newlines intact.

`OP_SERVICE_ACCOUNT_TOKEN` needs no support in this codebase — `op` reads it
itself, so headless and container use work without further code.

### The PATH caveat

`op` is typically at `/opt/homebrew/bin/op`, which is not on the minimal PATH a
macOS GUI application inherits. Launching the server through `claude mcp add`
inherits the shell PATH and is unaffected. Claude Desktop is not, which is what
`op_cli_path` exists for.

## Invoking `op`

```
<op_cli_path or "op"> read <reference>
```

Run with a **60-second timeout** — long enough for a biometric prompt to be
answered, short enough that an unattended one cannot hang the MCP server
indefinitely on a tool call.

The `op://` reference is not itself a secret and is safe to store in
`config.json` and to name in error messages. The resolved PEM is never logged.

## Error handling

Every failure is loud, distinct, and actionable. Nothing falls back to another
source.

| Condition | Behaviour |
|---|---|
| No source configured | Error listing all three options |
| More than one configured | Error naming which are set |
| `op` binary not found | Error naming `op_cli_path` / `OP_CLI_PATH` |
| `op read` exits non-zero | Error including `op`'s stderr (not stdout) |
| `op read` exceeds timeout | Error saying the call timed out and the vault may be locked |
| Referenced file missing | Surfaces as the non-zero-exit case |
| Retrieved bytes are not a P-256 private key | Validation error, same for all sources |

## PEM validation

Every source's output is validated by loading it and confirming it is an
elliptic-curve private key on P-256, the curve ES256 requires. Truncation,
corrupted key material, an RSA key, and the wrong curve all fail at setup with a
named cause rather than as an opaque signing error later.

Whitespace variation is *not* rejected. OpenSSL's PEM reader is
whitespace-tolerant, so a field that turned the newlines into spaces still
yields a key that signs correctly — rejecting it would be a false alarm. The
test suite asserts this explicitly by signing with such a key.

Escaped-newline normalisation (`\\n` to a real newline) applies **only** to
`private_key_content`, where environment variables routinely carry the PEM
escaped. It does not apply to the 1Password source: a file attachment returns
real newlines, so normalising there would be dead code hiding a real fault.

## Setup wizard

The wizard asks which source to use. Choosing 1Password prompts for the `op://`
reference and immediately test-reads it, so a bad reference, a missing
attachment, or a locked vault fails during setup instead of at the first tool
call. On success it writes `private_key_op_ref` to `config.json`.

## Testing

No test touches a real vault.

- Subprocess wiring is proven against a fake `op` executable written to
  `tmp_path`, covering success, non-zero exit, and a binary that does not exist.
- The timeout path is monkeypatched rather than slept through.
- Source resolution: exactly-one enforcement, with zero and with several set.
- PEM validation rejects garbage, a truncated PEM, and an RSA key.
- Caching: `op` is invoked exactly once across multiple token regenerations.
- Existing suite continues to pass unchanged.
