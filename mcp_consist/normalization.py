"""Safe, deterministic normalization helpers for the policy-rules-v1 engine.

No network access, no filesystem access, no code execution. All functions are
pure and deterministic so results are reproducible.
"""

from __future__ import annotations

import json
import os
import re
import unicodedata
from typing import Any, Optional
from urllib.parse import urlparse

# Zero-width and bidirectional control characters (mirrors config for
# self-contained checks but config is the source of truth).
ZERO_WIDTH_CHARS = {
    "\u200b", "\u200c", "\u200d", "\ufeff",
}
BIDI_CONTROL_CHARS = {
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069",
}


def normalize_text(text: str) -> str:
    """Lowercase + whitespace-collapse normalisation used for lexical comparison.

    Mirrors the Stage 1 prototype behaviour (lowercase + split on whitespace)
    so the two engines remain comparable, while also stripping zero-width and
    bidi control characters for detection purposes.
    """
    if not isinstance(text, str):
        return ""
    # Remove zero-width / bidi control characters for the *detection* form.
    cleaned = "".join(ch for ch in text if ch not in ZERO_WIDTH_CHARS and ch not in BIDI_CONTROL_CHARS)
    return cleaned.lower().strip()


def tokenise(text: str) -> set[str]:
    """Whitespace token set (same as Stage 1 prototype)."""
    return set(normalize_text(text).split())


def safe_parse_json(text: str) -> Optional[Any]:
    """Parse JSON safely. Returns None on invalid JSON. Never executes."""
    if not isinstance(text, str) or not text.strip():
        return None
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def detect_zero_width(text: str) -> list[str]:
    """Return list of zero-width characters found in text."""
    found = []
    for ch in text:
        if ch in ZERO_WIDTH_CHARS:
            found.append(ch)
    return found


def detect_bidi(text: str) -> list[str]:
    """Return list of bidirectional control characters found in text."""
    found = []
    for ch in text:
        if ch in BIDI_CONTROL_CHARS:
            found.append(ch)
    return found


def has_long_encoded_payload(text: str, min_len: int = 64) -> bool:
    """Heuristic: detect long base64-like tokens that may hide encoded payloads."""
    if not isinstance(text, str):
        return False
    for token in text.split():
        if len(token) >= min_len and re.fullmatch(r"[A-Za-z0-9+/=]{%d,}" % min_len, token):
            return True
    return False


# ---------------------------------------------------------------------------
# Path normalization (lexical only — NO filesystem access)
# ---------------------------------------------------------------------------

def _expand_user(path: str) -> str:
    """Lexical ~ expansion only (does not touch the filesystem)."""
    if path.startswith("~"):
        home = os.path.expanduser("~")
        path = home + path[1:]
    return path


def normalize_path(path: str) -> str:
    """Lexically normalize a path without accessing the filesystem.

    Handles:
      - ``..`` segments
      - leading ``~`` (lexical expanduser)
      - absolute vs relative
      - Windows-style backslashes (converted to forward slashes)
      - URL-encoded traversal indicators (decoded first)

    Returns a normalized, forward-slash path. Does NOT resolve symlinks and
    does NOT check existence.
    """
    if not isinstance(path, str) or not path:
        return ""

    p = path.strip()

    # Decode common URL encodings used for traversal obfuscation.
    p = p.replace("%2e%2e", "..").replace("%2E%2E", "..")
    p = p.replace("%2e", ".").replace("%2E", ".")
    p = p.replace("%5c", "\\").replace("%5C", "\\")
    p = p.replace("%2f", "/").replace("%2F", "/")

    # Windows backslashes -> forward slashes.
    p = p.replace("\\", "/")

    # Expand leading ~ lexically.
    p = _expand_user(p)

    is_absolute = p.startswith("/")

    # Split into segments, drop empty and "." segments, resolve ".." lexically.
    segments = p.split("/")
    stack: list[str] = []
    for seg in segments:
        if seg == "" or seg == ".":
            continue
        if seg == "..":
            if stack:
                stack.pop()
            # ".." at the root of a relative path stays as traversal marker;
            # for absolute paths it cannot go above root (lexically clamped).
            continue
        stack.append(seg)

    normalized = "/".join(stack)
    if is_absolute:
        normalized = "/" + normalized
    return normalized


def path_within_roots(path: str, allowed_roots: list[str]) -> bool:
    """Check (lexically, no filesystem) whether ``path`` is within any allowed root.

    Uses segment-prefix comparison on normalized paths so that
    ``/workspace/../etc/passwd`` (normalizes to /etc/passwd) is NOT treated as
    within /workspace. Never relies on naïve string-prefix comparison of raw
    input.
    """
    if not path or not allowed_roots:
        return False

    norm_path = normalize_path(path)
    if not norm_path:
        return False

    for root in allowed_roots:
        norm_root = normalize_path(root)
        if not norm_root:
            continue
        # Segment-aware prefix: path == root or path starts with root + "/".
        if norm_path == norm_root:
            return True
        if norm_path.startswith(norm_root.rstrip("/") + "/"):
            return True
    return False


# ---------------------------------------------------------------------------
# URL / host normalization (no network access)
# ---------------------------------------------------------------------------

def _looks_like_host(candidate: str) -> bool:
    """A bare string is only a plausible host if it has a dot (domain-like),
    no spaces, and is not a single segment such as "~" or a drive letter."""
    if not candidate or " " in candidate:
        return False
    c = candidate.strip().strip(".")
    if not c:
        return False
    if c in ("~",):
        return False
    # Must contain a dot to be a domain-like host (avoids flagging file names,
    # single words, or command fragments as hosts).
    if "." not in c:
        return False
    return True


def extract_host(url_or_host: str) -> Optional[str]:
    """Safely extract and normalize a host from a URL or bare host string.

    Returns None if no host can be determined. Does NOT make network requests.
    Bare strings that do not look like hosts (no dot, contains spaces, "~")
    return None.
    """
    if not isinstance(url_or_host, str) or not url_or_host.strip():
        return None

    raw = url_or_host.strip()

    # If it looks like a URL, parse it.
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        try:
            parsed = urlparse(raw)
        except ValueError:
            return None
        host = parsed.hostname
        if not host:
            return None
    else:
        # Bare host candidate: only accept domain-like strings.
        host = raw.split("/")[0].split("?")[0].split("#")[0]
        if not _looks_like_host(host):
            return None

    host = host.lower().strip(".")
    # Strip port.
    host = host.split(":")[0]
    if not host or not _looks_like_host(host):
        return None
    return host


def normalize_domain(domain: str) -> str:
    """Lowercase, strip trailing dot, strip port."""
    if not isinstance(domain, str):
        return ""
    d = domain.lower().strip().strip(".")
    d = d.split(":")[0]
    return d


def host_matches_allowed(host: str, allowed_hosts: list[str]) -> bool:
    """Exact allow-list match for a host.

    Subdomain matching is NOT performed by default: ``example.test`` does not
    match ``sub.example.test``. This avoids the "misleading suffix" problem
    (e.g. ``evil.example.test``). Callers that want subdomain matching must
    opt in explicitly and document it.
    """
    if not host or not allowed_hosts:
        return False
    norm_host = normalize_domain(host)
    for allowed in allowed_hosts:
        if norm_host == normalize_domain(allowed):
            return True
    return False


def host_has_misleading_suffix(host: str, allowed_hosts: list[str]) -> bool:
    """Detect hosts that *end with* an allowed host but are not exact matches.

    e.g. ``evil-example.test`` ends with ``example.test`` but is not allowed.
    """
    if not host or not allowed_hosts:
        return False
    norm_host = normalize_domain(host)
    for allowed in allowed_hosts:
        norm_allowed = normalize_domain(allowed)
        if norm_allowed and norm_host != norm_allowed and norm_host.endswith(norm_allowed):
            # Ensure it's a real suffix boundary (preceded by '.' or the host
            # simply concatenates). Treat any endswith as misleading.
            return True
    return False


def extract_email_host(email_like: str) -> Optional[str]:
    """Extract the host part of an email-like string, if present."""
    if not isinstance(email_like, str) or "@" not in email_like:
        return None
    local, _, domain = email_like.rpartition("@")
    if not local or not domain:
        return None
    return extract_host(domain)
