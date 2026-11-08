"""Input validation for the policy-rules-v1 engine.

All validation is defensive: invalid input yields an ERROR result, never an
exception. No supplied JSON is ever executed.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from .models import AnalysisContext, AnalysisResult, Verdict

MAX_INPUT_LENGTH = 20_000


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def validate_threshold(threshold: Any) -> Optional[float]:
    """Return a validated float threshold in [0, 1], or None if invalid."""
    if not _is_number(threshold):
        return None
    f = float(threshold)
    if not (0.0 <= f <= 1.0):
        return None
    return f


def validate_context(ctx: Any) -> tuple[Optional[AnalysisContext], Optional[str]]:
    """Validate the raw context dict.

    Returns (context, error_message). On success error_message is None.
    On failure context is None and error_message describes the problem.
    """
    if ctx is None:
        return None, "Context is required (None provided)."
    if not isinstance(ctx, dict):
        return None, f"Context must be a dict (got {type(ctx).__name__})."

    def _field(name: str) -> str:
        v = ctx.get(name, "")
        if v is None:
            return ""
        if not isinstance(v, str):
            return f"Context field '{name}' must be a string (got {type(v).__name__})."
        if len(v) > MAX_INPUT_LENGTH:
            return f"Context field '{name}' exceeds {MAX_INPUT_LENGTH:,} characters."
        return v

    # Collect fields; any type/length error short-circuits.
    description = _field("description")
    schema = _field("schema")
    policy = _field("policy")
    task = _field("task")
    call = _field("call")

    # _field returns an error string (non-empty starting with "Context field")
    # when there's a problem. Detect that.
    for fname, fval in (("description", description), ("schema", schema),
                        ("policy", policy), ("task", task), ("call", call)):
        if isinstance(fval, str) and fval.startswith("Context field '"):
            return None, fval

    # A proposed tool call is required to have something to analyse.
    if not call.strip():
        return None, "No proposed tool call to analyse (field 'call' is empty)."

    context = AnalysisContext(
        description=description,
        schema=schema,
        policy=policy,
        task=task,
        call=call,
    )
    return context, None


def parse_json_field(value: str, field_name: str) -> tuple[Optional[Any], Optional[str]]:
    """Parse a JSON string field. Returns (parsed, error)."""
    if not value or not value.strip():
        return None, f"Field '{field_name}' is empty or whitespace-only."
    try:
        return json.loads(value), None
    except (ValueError, TypeError) as exc:
        return None, f"Field '{field_name}' is not valid JSON: {exc}"


def error_result(message: str, latency_ms: float = 0.0) -> AnalysisResult:
    """Build an ERROR AnalysisResult."""
    return AnalysisResult.error_result(message, latency_ms=latency_ms)
