"""Central configuration for the policy-rules-v1 engine.

All rule weights, severity penalties, detection patterns and canonical formats
live here so the engine is explainable and easy to audit.

Penalties (applied to the layer score: max(0.0, 1.0 - sum(penalties))):
    LOW    = 0.15
    MEDIUM = 0.40
    HIGH   = 0.75
    CRITICAL = 1.00

All layers start with equal weight (1.0) in the overall score average.
"""

from __future__ import annotations

from typing import Final

# ---------------------------------------------------------------------------
# Engine identity
# ---------------------------------------------------------------------------
ENGINE_NAME: Final[str] = "policy-rules-v1"
ENGINE_VERSION: Final[str] = "1.0.0"

DEFAULT_THRESHOLD: Final[float] = 0.8
MAX_INPUT_LENGTH: Final[int] = 20_000

# ---------------------------------------------------------------------------
# Severity penalties
# ---------------------------------------------------------------------------
SEVERITY_PENALTIES: Final[dict[str, float]] = {
    "LOW": 0.15,
    "MEDIUM": 0.40,
    "HIGH": 0.75,
    "CRITICAL": 1.00,
}

# ---------------------------------------------------------------------------
# Layer weights (equal unless justified by documented research)
# ---------------------------------------------------------------------------
LAYER_WEIGHTS: Final[dict[str, float]] = {
    "layer1": 1.0,
    "layer2": 1.0,
    "layer3": 1.0,
    "layer4": 1.0,
    "layer5": 1.0,
}

LAYER_ORDER: Final[list[str]] = [
    "layer1",
    "layer2",
    "layer3",
    "layer4",
    "layer5",
]

# Canonical layer identifiers and display names, in stable order.
LAYER_IDS: Final[list[str]] = LAYER_ORDER.copy()
LAYER_NAMES: Final[dict[str, str]] = {
    "layer1": "Description Integrity",
    "layer2": "Sensitive Resource Protection",
    "layer3": "Schema and Parameter Integrity",
    "layer4": "Capability Policy Compliance",
    "layer5": "Joint Intent and Tool-Call Integrity",
}

# ---------------------------------------------------------------------------
# Rule identifiers
# ---------------------------------------------------------------------------
RULES = {
    # Layer 1 — Description Integrity
    "R-101": "layer1",
    # Layer 2 — Sensitive Resource Protection
    "R-102": "layer2",
    # Layer 3 — Schema and Parameter Integrity
    "R-201": "layer3",
    "R-202": "layer3",
    # Layer 4 — Capability Policy Compliance
    "R-301": "layer4",
    "R-302": "layer4",
    "R-303": "layer4",
    "R-304": "layer4",
    # Layer 5 — Joint Intent and Tool-Call Integrity
    "R-401": "layer5",
    "R-402": "layer5",
    "R-501": "layer5",
}

# ---------------------------------------------------------------------------
# Canonical policy format
# ---------------------------------------------------------------------------
CANONICAL_POLICY_KEYS: Final[list[str]] = [
    "allowed_roots",
    "allowed_hosts",
    "allowed_actions",
    "allowed_tools",
]

# Canonical proposed-call keys
CANONICAL_CALL_KEYS: Final[list[str]] = ["tool", "action", "arguments"]

# ---------------------------------------------------------------------------
# Supported JSON Schema subset (Layer 3, R-201)
# ---------------------------------------------------------------------------
JSON_SCHEMA_TYPES: Final[list[str]] = [
    "object",
    "properties",
    "required",
    "string",
    "integer",
    "number",
    "boolean",
    "array",
    "enum",
    "additionalProperties",
]

UNSUPPORTED_JSON_SCHEMA_NOTE: Final[str] = (
    "This prototype supports a bounded JSON Schema subset only: object, "
    "properties, required, string, integer, number, boolean, array, enum, "
    "additionalProperties. Features such as allOf/anyOf/oneOf, minimum/maximum, "
    "minLength/maxLength, pattern, format, dependencies, if/then/else, "
    "$ref, $id, $schema, definitions/defs are NOT supported and are ignored "
    "with no validation applied to them. Full JSON Schema compliance is not "
    "claimed."
)

# ---------------------------------------------------------------------------
# Layer 1 — Description Integrity (R-101) hidden-instruction indicators
# ---------------------------------------------------------------------------
HIDDEN_INSTRUCTION_PHRASES: Final[list[str]] = [
    "ignore previous instructions",
    "ignore all previous instructions",
    "disregard previous instructions",
    "do not tell the user",
    "do not inform the user",
    "without telling the user",
    "before using this tool first",
    "before you use this tool",
    "first you must",
    "silently perform",
    "silently execute",
    "silently carry out",
    "secretly perform",
    "secretly execute",
    "override all safety",
    "bypass all safety",
    "ignore safety",
    "ignore policies",
    "ignore the policy",
]

# Zero-width Unicode characters (indicators of obfuscation).
ZERO_WIDTH_CHARS: Final[dict[str, str]] = {
    "\u200b": "ZERO_WIDTH_SPACE",
    "\u200c": "ZERO_WIDTH_NON_JOINER",
    "\u200d": "ZERO_WIDTH_JOINER",
    "\ufeff": "ZERO_WIDTH_NO_BREAK_SPACE (BOM)",
}

# Bidirectional control characters (indicators of obfuscation / spoofing).
BIDI_CONTROL_CHARS: Final[dict[str, str]] = {
    "\u202a": "LEFT_TO_RIGHT_EMBEDDING",
    "\u202b": "RIGHT_TO_LEFT_EMBEDDING",
    "\u202c": "POP_DIRECTIONAL_FORMATTING",
    "\u202d": "LEFT_TO_RIGHT_OVERRIDE",
    "\u202e": "RIGHT_TO_LEFT_OVERRIDE",
    "\u2066": "LEFT_TO_RIGHT_ISOLATE",
    "\u2067": "RIGHT_TO_LEFT_ISOLATE",
    "\u2068": "FIRST_STRONG_ISOLATE",
    "\u2069": "POP_DIRECTIONAL_ISOLATE",
}

# Long encoded payload indicators (heuristic: long base64-like tokens).
ENCODED_PAYLOAD_MIN_LEN: Final[int] = 64

# ---------------------------------------------------------------------------
# Layer 2 — Sensitive Resource Protection (R-102)
# ---------------------------------------------------------------------------
SENSITIVE_RESOURCE_PATTERNS: Final[list[tuple[str, str]]] = [
    # (pattern, label)
    ("~/.ssh", "SSH directory reference"),
    (".ssh/", "SSH directory reference"),
    ("id_rsa", "SSH private key reference"),
    ("id_dsa", "SSH private key reference"),
    (".env", "Environment file reference"),
    ("/etc/passwd", "System password file reference"),
    ("/etc/shadow", "System shadow file reference"),
    (".aws/", "AWS credentials directory reference"),
    (".aws", "AWS credentials reference"),
    ("aws_access_key_id", "AWS access key reference"),
    ("aws_secret_access_key", "AWS secret key reference"),
    ("authorization:", "Authentication token reference"),
    ("bearer ", "Bearer token reference"),
    ("api_key", "API key reference"),
    ("apikey", "API key reference"),
    ("secret_key", "Secret key reference"),
    ("access_token", "Access token reference"),
    ("refresh_token", "Refresh token reference"),
    ("session_token", "Session token reference"),
    ("cookie=", "Cookie reference"),
    ("cookie:", "Cookie reference"),
    ("credentials", "Credential material reference"),
    ("credential", "Credential material reference"),
    ("private_key", "Private key reference"),
    ("pem", "PEM key reference"),
    (".pem", "PEM key reference"),
    ("password=", "Password reference"),
    ("passwd=", "Password reference"),
    ("pwd=", "Password reference"),
    ("token=", "Token reference"),
]

# ---------------------------------------------------------------------------
# Layer 3 — Schema and Parameter Integrity (R-201, R-202)
# ---------------------------------------------------------------------------
# Undeclared free-text side-channel parameter names. These are NOT flagged on
# name alone; they are only evaluated when present in a call AND not declared
# in the schema (see rules.R-202).
SIDE_CHANNEL_PARAM_NAMES: Final[list[str]] = [
    "notes",
    "context",
    "metadata",
    "sidenote",
    "side_note",
    "comment",
    "extra",
    "misc",
]

# ---------------------------------------------------------------------------
# Layer 4 — Capability Policy Compliance (R-301, R-302, R-303)
# ---------------------------------------------------------------------------
# Path traversal indicators (lexical only — no filesystem access).
PATH_TRAVERSAL_INDICATORS: Final[list[str]] = [
    "..",
    "~",
    "%2e%2e",  # URL-encoded ..
    "%2e",     # URL-encoded .
    "%5c",     # URL-encoded backslash
    "\\\\",    # backslash
]

# ---------------------------------------------------------------------------
# Layer 5 — Joint Intent and Tool-Call Integrity (R-401, R-402, R-501)
# ---------------------------------------------------------------------------
# Action / resource categories used for deterministic lexical alignment.
ACTION_CATEGORIES: Final[dict[str, list[str]]] = {
    "read": ["read", "fetch", "get", "view", "open", "cat", "display"],
    "write": ["write", "create", "save", "update", "modify", "edit", "put"],
    "delete": ["delete", "remove", "rm", "drop", "destroy"],
    "list": ["list", "enumerate", "ls", "scan", "dir"],
    "execute": ["execute", "run", "launch", "start", "invoke"],
}

RESOURCE_CATEGORIES: Final[dict[str, list[str]]] = {
    "file": ["file", "document", "txt", "pdf", "document"],
    "path": ["path", "directory", "folder", "workspace"],
    "network": ["url", "http", "https", "host", "domain", "endpoint"],
    "email": ["email", "mail", "message"],
}

# Explicit cross-tool pivot markers in proposed-call text.
CROSS_TOOL_PIVOT_MARKERS: Final[list[str]] = [
    "then call",
    "then invoke",
    "then use",
    "followed by",
    "after which",
    "next call",
    "also call",
    "embedded call",
    "nested call",
]
