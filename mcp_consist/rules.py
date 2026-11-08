"""Five detection layers for the policy-rules-v1 engine.

Every rule is deterministic, bounded, and analyses static data only. Rules
never execute, follow, decode, or network-fetch anything supplied in the
context. Each rule returns a list of :class:`mcp_consist.models.Finding`
objects.

Rule -> layer mapping (from config):
    R-101  layer1  Description Integrity
    R-102  layer2  Sensitive Resource Protection
    R-201  layer3  Schema and Parameter Integrity (schema validation)
    R-202  layer3  Schema and Parameter Integrity (side-channel parameters)
    R-301  layer4  Capability Policy Compliance (path)
    R-302  layer4  Capability Policy Compliance (host/URL/email)
    R-303  layer4  Capability Policy Compliance (action)
    R-401  layer5  Joint Intent (task vs call)
    R-402  layer5  Joint Intent (description vs call)
    R-501  layer5  Cross-tool pivot detection
"""

from __future__ import annotations

import re
from typing import Any, Optional

from .config import (
    ACTION_CATEGORIES,
    BIDI_CONTROL_CHARS,
    CANONICAL_CALL_KEYS,
    CANONICAL_POLICY_KEYS,
    CROSS_TOOL_PIVOT_MARKERS,
    ENCODED_PAYLOAD_MIN_LEN,
    HIDDEN_INSTRUCTION_PHRASES,
    LAYER_IDS,
    RESOURCE_CATEGORIES,
    SENSITIVE_RESOURCE_PATTERNS,
    SEVERITY_PENALTIES,
    SIDE_CHANNEL_PARAM_NAMES,
    UNSUPPORTED_JSON_SCHEMA_NOTE,
    ZERO_WIDTH_CHARS,
)
from .models import Finding, LayerStatus, Severity
from .normalization import (
    detect_bidi,
    detect_zero_width,
    extract_email_host,
    extract_host,
    has_long_encoded_payload,
    host_has_misleading_suffix,
    host_matches_allowed,
    normalize_domain,
    normalize_path,
    path_within_roots,
    safe_parse_json,
    tokenise,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sev(severity_name: str) -> Severity:
    try:
        return Severity[severity_name]
    except KeyError:
        return Severity.MEDIUM


def _finding(rule_id: str, layer_id: str, severity: Severity,
             description: str, evidence: str = "",
             explanation: str = "") -> Finding:
    return Finding(
        rule_id=rule_id,
        layer_id=layer_id,
        severity=severity,
        description=description,
        evidence=evidence,
        explanation=explanation,
    )


def _redact(value: str, label: str) -> str:
    """Redact a potentially sensitive value; only the label is exposed."""
    return f"[redacted: {label}]"


def _get_call_args(parsed_call: Any) -> Optional[dict]:
    if not isinstance(parsed_call, dict):
        return None
    args = parsed_call.get("arguments")
    return args if isinstance(args, dict) else None


def _category_for_token(token: str, categories: dict[str, list[str]]) -> Optional[str]:
    token = token.lower()
    for cat, kws in categories.items():
        for kw in kws:
            if kw in token:
                return cat
    return None


# ---------------------------------------------------------------------------
# Layer 1 — Description Integrity (R-101)
# ---------------------------------------------------------------------------

def rule_R101_description_integrity(description: str) -> list[Finding]:
    """Detect hidden-instruction / obfuscation indicators in the tool description.

    Never executes or decodes anything. Literal, case-insensitive phrase
    matching avoids flagging normal technical documentation unless a documented
    marker is actually present.
    """
    findings: list[Finding] = []
    if not description:
        return findings

    lower = description.lower()

    # Hidden-instruction phrases.
    for phrase in HIDDEN_INSTRUCTION_PHRASES:
        if phrase in lower:
            findings.append(_finding(
                "R-101", "layer1", Severity.HIGH,
                f"Hidden-instruction marker detected: {phrase!r}",
                evidence=_redact(description, "hidden-instruction phrase"),
                explanation="The description contains an instruction-override "
                            "marker. This is a signal only — the engine never "
                            "follows or executes it.",
            ))
            break  # one finding per class of indicator to avoid double counting

    # Zero-width Unicode characters.
    zw = detect_zero_width(description)
    if zw:
        findings.append(_finding(
            "R-101", "layer1", Severity.MEDIUM,
            f"Zero-width Unicode characters present ({len(zw)}).",
            evidence=_redact("".join(zw), "zero-width characters"),
            explanation="Zero-width characters can be used for text obfuscation "
                        "or fingerprinting. They do not affect execution but "
                        "warrant review.",
        ))

    # Bidirectional control characters.
    bi = detect_bidi(description)
    if bi:
        findings.append(_finding(
            "R-101", "layer1", Severity.MEDIUM,
            f"Bidirectional control characters present ({len(bi)}).",
            evidence=_redact("".join(bi), "bidirectional control characters"),
            explanation="Bidi control characters can be used for visual "
                        "spoofing of text content.",
        ))

    # Long encoded payload indicators.
    if has_long_encoded_payload(description, ENCODED_PAYLOAD_MIN_LEN):
        findings.append(_finding(
            "R-101", "layer1", Severity.HIGH,
            "Long base64-like encoded payload indicator detected in description.",
            evidence=_redact("encoded token", "long encoded payload"),
            explanation="The description contains a long encoded-looking token "
                        "that may conceal instructions. It is never decoded.",
        ))

    return findings


# ---------------------------------------------------------------------------
# Layer 2 — Sensitive Resource Protection (R-102)
# ---------------------------------------------------------------------------

def rule_R102_sensitive_resources(context_parts: dict[str, str]) -> list[Finding]:
    """Scan all context fields for sensitive resource references.

    Evidence is redacted: actual secret values are never exposed.
    """
    findings: list[Finding] = []
    seen_labels: set[str] = set()

    for field_name, text in context_parts.items():
        if not isinstance(text, str) or not text:
            continue
        lower = text.lower()
        for pattern, label in SENSITIVE_RESOURCE_PATTERNS:
            if pattern.lower() in lower:
                # One finding per label to keep output bounded.
                if label in seen_labels:
                    continue
                seen_labels.add(label)
                # Severity: credential/key material is HIGH; generic refs MEDIUM.
                severe = any(k in label.lower() for k in (
                    "private key", "secret key", "access key", "secret key",
                    "aws secret", "ssh private key", "token", "credential",
                    "password",
                ))
                sev = Severity.HIGH if severe else Severity.MEDIUM
                findings.append(_finding(
                    "R-102", "layer2", sev,
                    f"Sensitive resource reference in {field_name}: {label}.",
                    evidence=_redact(pattern, label),
                    explanation="The input references potentially sensitive "
                                "resources or credentials. Actual values are "
                                "redacted and never displayed.",
                ))

    return findings


# ---------------------------------------------------------------------------
# Layer 3 — Schema and Parameter Integrity (R-201, R-202)
# ---------------------------------------------------------------------------

def _type_matches(value: Any, type_name: str) -> bool:
    if type_name == "string":
        return isinstance(value, str)
    if type_name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if type_name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if type_name == "boolean":
        return isinstance(value, bool)
    if type_name == "array":
        return isinstance(value, list)
    if type_name == "object":
        return isinstance(value, dict)
    return True  # unknown type: cannot validate, pass through


def rule_R201_schema_validation(schema_text: str, call_text: str) -> list[Finding]:
    """Validate the proposed call against the declared JSON Schema subset.

    Supported subset: object, properties, required, string, integer, number,
    boolean, array, enum, additionalProperties. Everything else is ignored
    (documented as unsupported).
    """
    findings: list[Finding] = []
    schema = safe_parse_json(schema_text)
    call = safe_parse_json(call_text)

    if schema is None or not isinstance(schema, dict):
        # No usable schema → nothing to validate here (coverage gap handled
        # elsewhere). Return empty; caller decides N/A.
        return findings
    if call is None or not isinstance(call, dict):
        return findings

    args = _get_call_args(call)
    if args is None:
        # No arguments object to validate.
        return findings

    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        properties = {}
    required = schema.get("required", [])
    if not isinstance(required, list):
        required = []
    additional_props = schema.get("additionalProperties", True)

    declared = set(properties.keys())

    # 1. Required arguments present.
    for req in required:
        if not isinstance(req, str):
            continue
        if req not in args:
            findings.append(_finding(
                "R-201", "layer3", Severity.HIGH,
                "Required argument missing.",
                evidence=_redact(req, "required argument"),
                explanation="The schema declares a required argument that the "
                            "proposed call does not supply. The argument name "
                            "is redacted in the evidence field.",
            ))

    # 2. Unknown arguments + type/enum validation for declared args.
    for arg_name, arg_value in args.items():
        if arg_name not in declared:
            # Side-channel parameter names are handled by R-202 at MEDIUM
            # severity; do not double-count them as generic unknown args.
            if arg_name.lower() in SIDE_CHANNEL_PARAM_NAMES:
                continue
            # Unknown argument.
            if additional_props is False:
                findings.append(_finding(
                    "R-201", "layer3", Severity.HIGH,
                    "Unknown argument not declared in schema.",
                    evidence=_redact(arg_name, "unknown argument"),
                    explanation="The schema sets additionalProperties=false, so "
                                "arguments not declared in properties are not "
                                "permitted. The argument name is redacted.",
                ))
            # If additionalProperties is true (default), unknown args are noted
            # but treated as lower severity (side-channel concern handled by R-202).
            continue

        prop_schema = properties.get(arg_name, {})
        if not isinstance(prop_schema, dict):
            continue

        # Type check.
        expected_type = prop_schema.get("type")
        if expected_type and not _type_matches(arg_value, expected_type):
            findings.append(_finding(
                "R-201", "layer3", Severity.HIGH,
                f"Type mismatch for an argument: expected {expected_type}.",
                evidence=_redact(arg_name, "mismatched argument"),
                explanation="The schema declares an argument with a type that "
                            "does not match the supplied value. The argument "
                            "name is redacted.",
            ))
            continue  # don't enum-check a wrongly-typed value

        # Enum check.
        enum_values = prop_schema.get("enum")
        if isinstance(enum_values, list) and arg_value not in enum_values:
            findings.append(_finding(
                "R-201", "layer3", Severity.MEDIUM,
                "Enum violation for an argument: value not in allowed "
                "enumeration.",
                evidence=_redact(arg_name, "enum-violating argument"),
                explanation="The schema restricts an argument to a set of enum "
                            "values and the supplied value is not among them. "
                            "The argument name is redacted.",
            ))

        # Nested object / array type checks are covered by _type_matches.

    return findings


def rule_R202_side_channel(schema_text: str, call_text: str) -> list[Finding]:
    """Detect undeclared free-text side-channel parameters in the call.

    A parameter name like notes/context/metadata/sidenote is only flagged when
    it appears in the call arguments AND is not declared in the schema.
    """
    findings: list[Finding] = []
    schema = safe_parse_json(schema_text)
    call = safe_parse_json(call_text)

    if schema is None or not isinstance(schema, dict):
        return findings
    if call is None or not isinstance(call, dict):
        return findings

    args = _get_call_args(call)
    if args is None:
        return findings

    properties = schema.get("properties", {})
    declared = set(properties.keys()) if isinstance(properties, dict) else set()

    for arg_name in args:
        if arg_name in declared:
            continue
        if arg_name.lower() in SIDE_CHANNEL_PARAM_NAMES:
            findings.append(_finding(
                "R-202", "layer3", Severity.MEDIUM,
                "Undeclared free-text side-channel parameter.",
                evidence=_redact(arg_name, "side-channel parameter"),
                explanation="The call includes an undeclared parameter that "
                            "matches a known side-channel parameter name. "
                            "Free-text fields can carry unintended data. The "
                            "parameter name is redacted.",
            ))

    return findings


# ---------------------------------------------------------------------------
# Layer 4 — Capability Policy Compliance (R-301, R-302, R-303)
# ---------------------------------------------------------------------------

def rule_R301_path_outside_roots(call_text: str, policy_text: str) -> list[Finding]:
    """Detect paths outside allowed roots and path-traversal indicators.

    Purely lexical: no filesystem access, no symlink resolution.
    """
    findings: list[Finding] = []
    policy = safe_parse_json(policy_text)
    call = safe_parse_json(call_text)

    allowed_roots: list[str] = []
    if isinstance(policy, dict):
        roots = policy.get("allowed_roots", [])
        if isinstance(roots, list):
            allowed_roots = [r for r in roots if isinstance(r, str)]

    # Without allowed roots there is nothing to check path compliance against;
    # the coverage gap (R-304) handles missing policy.
    if not allowed_roots:
        return findings

    args = _get_call_args(call) if isinstance(call, dict) else None

    path_values: list[str] = []
    if isinstance(args, dict):
        for key, val in args.items():
            if isinstance(val, str) and ("/" in val or "\\" in val or val.startswith("~")):
                path_values.append(val)
            elif key.lower() in ("path", "file", "folder", "directory", "target"):
                if isinstance(val, str):
                    path_values.append(val)

    if not path_values:
        return findings

    traversal_found = False
    for pv in path_values:
        # Detect traversal indicators in the raw value.
        low = pv.lower()
        for ind in ("..", "~", "%2e%2e", "%5c"):
            if ind in low:
                traversal_found = True
                break

        norm = normalize_path(pv)
        if not path_within_roots(norm, allowed_roots):
            findings.append(_finding(
                "R-301", "layer4", Severity.HIGH,
                "Path target outside allowed roots.",
                evidence=_redact(pv, "path target"),
                explanation="The resolved path is not within any allow-listed "
                            "root. Naïve string-prefix checks are not used; the "
                            "path is normalized lexically first. The raw path "
                            "value is redacted in the evidence field.",
            ))

    if traversal_found and not any(f.rule_id == "R-301" for f in findings):
        findings.append(_finding(
            "R-301", "layer4", Severity.HIGH,
            "Path traversal indicator detected in a path argument.",
            evidence=_redact(".. / ~", "path traversal indicator"),
            explanation="The path contains traversal indicators (.., ~, "
                        "encoded variants). These are normalized lexically and "
                        "checked against allowed roots.",
        ))

    return findings


def rule_R302_host_not_allowlisted(call_text: str, policy_text: str) -> list[Finding]:
    """Detect host/URL/email destinations not on the allowed-hosts list.

    No network requests are made. Exact host matching only; misleading suffixes
    are flagged separately.
    """
    findings: list[Finding] = []
    policy = safe_parse_json(policy_text)
    call = safe_parse_json(call_text)

    allowed_hosts: list[str] = []
    if isinstance(policy, dict):
        hosts = policy.get("allowed_hosts", [])
        if isinstance(hosts, list):
            allowed_hosts = [h for h in hosts if isinstance(h, str)]

    # Without allowed hosts there is nothing to check destination compliance
    # against; the coverage gap (R-304) handles missing policy.
    if not allowed_hosts:
        return findings

    args = _get_call_args(call) if isinstance(call, dict) else None

    candidates: list[str] = []
    if isinstance(args, dict):
        for val in args.values():
            if isinstance(val, str):
                candidates.append(val)
    # Also scan the raw call text for scheme-qualified URLs only. Bare filenames
    # (e.g. example.txt) must not be mistaken for hosts.
    if isinstance(call_text, str):
        candidates.extend(re.findall(r"https?://[^\s\"'<>]+", call_text))

    misleading = False
    for cand in candidates:
        host = extract_host(cand)
        if not host:
            continue
        # Email-like?
        email_host = extract_email_host(cand)
        check_host = email_host or host

        if allowed_hosts and not host_matches_allowed(check_host, allowed_hosts):
            sev = Severity.HIGH
            findings.append(_finding(
                "R-302", "layer4", sev,
                "Destination not allow-listed.",
                evidence=_redact(check_host, "destination host"),
                explanation="The host is not on the allowed-hosts list. Exact "
                            "matching is used; subdomains are not implicitly "
                            "allowed. The raw host value is redacted.",
            ))
        elif allowed_hosts and host_has_misleading_suffix(check_host, allowed_hosts):
            misleading = True

    if misleading:
        findings.append(_finding(
            "R-302", "layer4", Severity.MEDIUM,
            "Destination host has a misleading suffix relative to allowed hosts.",
            evidence=_redact("host suffix", "misleading suffix"),
            explanation="The host ends with an allowed-host string but is not "
                        "an exact match (possible domain-squatting lookalike).",
        ))

    return findings


def rule_R303_action_not_permitted(call_text: str, policy_text: str) -> list[Finding]:
    """Compare the proposed action with explicitly configured allowed actions.

    Missing policy information is visible (coverage gap handled at verdict
    level via the coverage-gap finding).
    """
    findings: list[Finding] = []
    policy = safe_parse_json(policy_text)
    call = safe_parse_json(call_text)

    allowed_actions: list[str] = []
    if isinstance(policy, dict):
        acts = policy.get("allowed_actions", [])
        if isinstance(acts, list):
            allowed_actions = [a for a in acts if isinstance(a, str)]

    # Without allowed actions there is nothing to check action compliance
    # against; the coverage gap (R-304) handles missing policy.
    if not allowed_actions:
        return findings

    action: Optional[str] = None
    if isinstance(call, dict):
        action = call.get("action")
        if not isinstance(action, str):
            action = None

    if action is None:
        # No action field to compare; nothing to flag here.
        return findings

    if action not in allowed_actions:
        findings.append(_finding(
            "R-303", "layer4", Severity.HIGH,
            "Action not permitted by policy.",
            evidence=_redact(action, "proposed action"),
            explanation="The proposed action is not in the policy's "
                        "allowed_actions list. The raw action value is "
                        "redacted in the evidence field.",
        ))

    return findings


def rule_R304_policy_coverage_gap(policy_text: str) -> list[Finding]:
    """Expose missing policy coverage as a finding (verdict-level WARN source).

    This is not a numbered rule in the spec but supports the requirement that
    missing policy information must be visible and result in WARN rather than
    silent permission.
    """
    findings: list[Finding] = []
    policy = safe_parse_json(policy_text)

    missing: list[str] = []
    if isinstance(policy, dict):
        for key in CANONICAL_POLICY_KEYS:
            if key not in policy:
                missing.append(key)
    else:
        missing = list(CANONICAL_POLICY_KEYS)

    if missing:
        findings.append(_finding(
            "R-304", "layer4", Severity.MEDIUM,
            f"Policy coverage gap: missing fields {missing}.",
            evidence=", ".join(missing),
            explanation="Relevant policy fields are unavailable, so the engine "
                        "cannot confirm the action is authorized. The verdict "
                        "will be WARN at minimum rather than ALLOW.",
        ))

    return findings


# ---------------------------------------------------------------------------
# Layer 5 — Joint Intent and Tool-Call Integrity (R-401, R-402, R-501)
# ---------------------------------------------------------------------------

def rule_R401_task_vs_call_misalignment(task: str, call_text: str) -> list[Finding]:
    """Compare user task with proposed call using lexical action/resource
    categories. Deterministic only — no semantics."""
    findings: list[Finding] = []
    call = safe_parse_json(call_text)

    action: Optional[str] = None
    if isinstance(call, dict):
        action = call.get("action")
        if not isinstance(action, str):
            action = None

    if not task or not action:
        return findings

    task_tokens = tokenise(task)
    task_cats: set[str] = set()
    for tok in task_tokens:
        cat = _category_for_token(tok, ACTION_CATEGORIES)
        if cat:
            task_cats.add(cat)
        cat = _category_for_token(tok, RESOURCE_CATEGORIES)
        if cat:
            task_cats.add(cat)

    call_cats: set[str] = {action}
    if action:
        cat = _category_for_token(action, ACTION_CATEGORIES)
        if cat:
            call_cats.add(cat)

    # Misalignment: task suggests one action but the call performs another.
    conflict_pairs = [("read", "write"), ("read", "delete"),
                      ("write", "read"), ("write", "delete"),
                      ("delete", "read"), ("delete", "write"),
                      ("list", "delete"), ("delete", "list")]
    for a, b in conflict_pairs:
        if a in task_cats and b in call_cats:
            findings.append(_finding(
                "R-401", "layer5", Severity.MEDIUM,
                f"Task suggests '{a}' but proposed call performs '{b}'.",
                evidence=_redact(action, "proposed action"),
                explanation="The user task and proposed tool-call action point "
                            "to different intent categories. The raw action "
                            "value is redacted.",
            ))

    return findings


def rule_R402_description_vs_call_misalignment(description: str, call_text: str) -> list[Finding]:
    """Compare advertised tool purpose (description) with proposed operation
    and resource targets."""
    findings: list[Finding] = []
    call = safe_parse_json(call_text)

    action: Optional[str] = None
    target: Optional[str] = None
    if isinstance(call, dict):
        action = call.get("action")
        if not isinstance(action, str):
            action = None
        args = _get_call_args(call)
        if isinstance(args, dict):
            for k in ("path", "url", "target", "file", "resource"):
                if k in args and isinstance(args[k], str):
                    target = args[k]
                    break

    if not description or not action:
        return findings

    desc_tokens = tokenise(description)
    desc_cats: set[str] = set()
    for tok in desc_tokens:
        cat = _category_for_token(tok, ACTION_CATEGORIES)
        if cat:
            desc_cats.add(cat)
        cat = _category_for_token(tok, RESOURCE_CATEGORIES)
        if cat:
            desc_cats.add(cat)

    # If the description advertises read-only but the call writes/deletes.
    if "read" in desc_cats and action in ("write", "delete", "remove"):
        findings.append(_finding(
            "R-402", "layer5", Severity.MEDIUM,
            "Tool description advertises read-only use but the proposed call "
            "performs a write/delete action.",
            evidence=_redact(action, "proposed action"),
            explanation="The advertised tool purpose conflicts with the "
                        "proposed operation. The raw action value is redacted.",
        ))

    # Resource mismatch: description targets a file, call targets network, etc.
    if target and extract_host(target):
        if "file" in desc_cats and "network" not in desc_cats:
            findings.append(_finding(
                "R-402", "layer5", Severity.MEDIUM,
                "Tool description targets a file resource but the proposed call "
                "targets a network destination.",
                evidence=_redact(target, "network target"),
                explanation="The advertised resource type conflicts with the "
                            "proposed call target.",
            ))

    return findings


def rule_R501_cross_tool_pivot(call_text: str) -> list[Finding]:
    """Detect explicitly represented cross-tool call chains or embedded
    follow-up tool invocations. Does NOT invoke other tools."""
    findings: list[Finding] = []
    if not call_text:
        return findings

    lower = call_text.lower()
    for marker in CROSS_TOOL_PIVOT_MARKERS:
        if marker in lower:
            findings.append(_finding(
                "R-501", "layer5", Severity.HIGH,
                f"Cross-tool pivot indicator detected: {marker!r}.",
                evidence=_redact(marker, "cross-tool pivot marker"),
                explanation="The proposed call references an explicit "
                            "follow-up or chained tool invocation. The engine "
                            "does not invoke other tools.",
            ))
            break

    return findings


# ---------------------------------------------------------------------------
# Orchestrator: run all rules
# ---------------------------------------------------------------------------

def run_all_rules(context, parsed_schema, parsed_call, parsed_policy,
                  disabled_layers=None):
    """Run every rule and return {layer_id: [Finding, ...]}.

    ``disabled_layers`` is an optional iterable of layer ids to skip (used by
    the ablation harness for genuine layer switching). Skipped layers yield
    an empty finding list and are treated as N/A by the engine.
    """
    disabled = set(disabled_layers or [])
    context_parts = {
        "description": context.description,
        "schema": context.schema,
        "policy": context.policy,
        "task": context.task,
        "call": context.call,
    }

    results = {lid: [] for lid in ("layer1", "layer2", "layer3", "layer4", "layer5")}

    if "layer1" not in disabled:
        results["layer1"] = rule_R101_description_integrity(context.description)
    if "layer2" not in disabled:
        results["layer2"] = rule_R102_sensitive_resources(context_parts)
    if "layer3" not in disabled:
        results["layer3"] = (
            rule_R201_schema_validation(context.schema, context.call) +
            rule_R202_side_channel(context.schema, context.call)
        )
    if "layer4" not in disabled:
        results["layer4"] = (
            rule_R301_path_outside_roots(context.call, context.policy) +
            rule_R302_host_not_allowlisted(context.call, context.policy) +
            rule_R303_action_not_permitted(context.call, context.policy) +
            rule_R304_policy_coverage_gap(context.policy)
        )
    if "layer5" not in disabled:
        results["layer5"] = (
            rule_R401_task_vs_call_misalignment(context.task, context.call) +
            rule_R402_description_vs_call_misalignment(context.description, context.call) +
            rule_R501_cross_tool_pivot(context.call)
        )
    return results
