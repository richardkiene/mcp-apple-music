"""Playlist IDs reach the URL path, so they must not be able to retarget it."""

import httpx
import pytest

from mcp_apple_music.client import BASE_URL
from mcp_apple_music.server import _playlist_tracks_path


def _resolved(playlist_id: str) -> str:
    """Resolve the way httpx will, including dot-segment normalisation."""
    return str(httpx.URL(BASE_URL + _playlist_tracks_path(playlist_id)))


def test_ordinary_playlist_id_is_unchanged():
    assert _resolved("p.AbCdEf123") == (
        f"{BASE_URL}/me/library/playlists/p.AbCdEf123/tracks"
    )


@pytest.mark.parametrize(
    "hostile",
    [
        "p.abc/../../../me/library/songs",
        "../../../../me/recent/played",
        "p.abc/../../me/recommendations",
    ],
)
def test_dot_segments_cannot_escape_the_playlist_endpoint(hostile):
    """Unencoded, 'p.abc/../../../me/library/songs' resolved to
    /v1/me/me/library/songs/tracks — a different endpoint than intended.
    """
    resolved = _resolved(hostile)

    assert resolved.startswith(f"{BASE_URL}/me/library/playlists/")
    assert resolved.endswith("/tracks")
    assert "/../" not in resolved


def test_slashes_and_query_delimiters_are_encoded():
    resolved = _resolved("p.abc/evil?injected=1#frag")

    assert resolved.startswith(f"{BASE_URL}/me/library/playlists/")
    assert resolved.endswith("/tracks")
    assert "%2F" in resolved and "%3F" in resolved

    # raw_path keeps the encoding; URL.path would decode it back and make an
    # escaped separator look like a real one.
    raw_path = httpx.URL(resolved).raw_path.decode()
    benign_path = httpx.URL(_resolved("p.benign")).raw_path.decode()
    assert raw_path.count("/") == benign_path.count("/"), (
        f"ID leaked extra path segments: {raw_path}"
    )


def test_empty_playlist_id_does_not_collapse_the_path():
    assert _resolved("") == f"{BASE_URL}/me/library/playlists//tracks"
