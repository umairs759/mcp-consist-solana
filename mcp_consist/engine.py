"""The policy-rules-v1 engine: analyze() entry point.

Orchestrates validation, the five detection layers, scoring, and the verdict
policy. All timing uses a monotonic timer; no performance values are hardcoded.
"""

from __future__ import annotations

import time
from typing import Any, Optional

from .config import (
    DEFAULT_THRESHOLD,
    ENGINE_NAME,
    ENGINE_VERSION,
    LAYER_IDS,
    LAYER_NAMES,
    LAYER_WEIGHTS,
    SEVERITY_PENALTIES,
)
from .models import AnalysisContext, AnalysisResult, Finding, LayerResult, \
    LayerStatus, Severity, Verdict, empty_layer
from .normalization import safe_parse_json
from .rules import run_all_rules
from .validation import error_result, validate_context, validate_threshold


def _monotonic_ms() -> float:
    return time.monotonic() * 1000.0


def _severity_penalty(severity: Severity) -> float:
    return SEVERITY_PENALTIES.get(severity.value, 0.0)


def _layer_score(findings: list[Finding]) -> float:
    """max(0.0, 1.0 - sum(applicable finding penalties))."""
    total = sum(_severity_penalty(f.severity) for f in findings)
    return max(0.0, 1.0 - total)


def _build_layer_results(
    layer_findings: dict[str, list[Finding]],
    applicable: dict[str, bool],
) -> list[LayerResult]:
    """Build LayerResult objects in stable layer order."""
    layers: list[LayerResult] = []
    for layer_id in LAYER_IDS:
        findings = layer_findings.get(layer_id, [])
        app = applicable.get(layer_id, True)
        if not app:
            layers.append(empty_layer(layer_id, LAYER_NAMES[layer_id],
                                      applicable=False))
            continue
        score = _layer_score(findings)
        # Status: PASS if no findings, FAIL if any findings.
        status = LayerStatus.PASS if not findings else LayerStatus.FAIL
        layers.append(LayerResult(
            layer_id=layer_id,
            name=LAYER_NAMES[layer_id],
            status=status,
            score=score,
            findings=findings,
            applicable=True,
        ))
    return layers


def _compute_overall_score(layers: list[LayerResult]) -> float:
    """Weighted average of applicable layer scores. N/A layers excluded."""
    weighted_sum = 0.0
    weight_sum = 0.0
    for layer in layers:
        if not layer.applicable or layer.score is None:
            continue
        w = LAYER_WEIGHTS.get(layer.layer_id, 1.0)
        weighted_sum += layer.score * w
        weight_sum += w
    if weight_sum == 0.0:
        return 0.0
    return weighted_sum / weight_sum


def _has_finding(layers: list[LayerResult], severity: Severity) -> bool:
    for layer in layers:
        if not layer.applicable:
            continue
        for f in layer.findings:
            if f.severity == severity:
                return True
    return False


def _medium_only(layers: list[LayerResult]) -> bool:
    """True if there are findings and the highest severity is MEDIUM or LOW."""
    has_any = False
    for layer in layers:
        if not layer.applicable:
            continue
        for f in layer.findings:
            has_any = True
            if f.severity in (Severity.HIGH, Severity.CRITICAL):
                return False
    return has_any


def _any_applicable_layer_zero(layers: list[LayerResult]) -> bool:
    """Genuine zero score on an applicable layer."""
    for layer in layers:
        if layer.applicable and layer.score is not None and layer.score == 0.0:
            return True
    return False


def _policy_coverage_missing(layers: list[LayerResult]) -> bool:
    """A policy-coverage-gap finding exists (R-304)."""
    for layer in layers:
        if layer.layer_id == "layer4":
            for f in layer.findings:
                if f.rule_id == "R-304":
                    return True
    return False


def analyze(ctx: Any, threshold: float = DEFAULT_THRESHOLD,
           enabled_layers: Any = None) -> dict:
    """Analyse a joint five-input context.

    Parameters
    ----------
    ctx : dict
        Canonical context with keys description, schema, policy, task, call.
    threshold : float
        Decision threshold in [0, 1] (default 0.8).

    Returns
    -------
    dict
        The output contract: verdict, score, engine, latency_ms, layers,
        findings, trace, override.
    """
    start = _monotonic_ms()
    trace: list[str] = []

    # --- 1. Validate inputs ----------------------------------------------
    context, err = validate_context(ctx)
    if err is not None:
        return error_result(err, latency_ms=_monotonic_ms() - start).to_dict()

    thr = validate_threshold(threshold)
    if thr is None:
        return error_result(
            f"Invalid threshold: {threshold!r}. Must be a number in [0, 1].",
            latency_ms=_monotonic_ms() - start,
        ).to_dict()

    trace.append("Inputs validated OK")

    # --- 2. Parse JSON fields (safe, no execution) -----------------------
    parsed_schema = safe_parse_json(context.schema) if context.schema else None
    parsed_call = safe_parse_json(context.call) if context.call else None
    parsed_policy = safe_parse_json(context.policy) if context.policy else None

    if context.schema and parsed_schema is None:
        return error_result("Field 'schema' is not valid JSON.",
                            latency_ms=_monotonic_ms() - start).to_dict()
    if context.call and parsed_call is None:
        return error_result("Field 'call' is not valid JSON.",
                            latency_ms=_monotonic_ms() - start).to_dict()
    if context.policy and parsed_policy is None:
        return error_result("Field 'policy' is not valid JSON.",
                            latency_ms=_monotonic_ms() - start).to_dict()

    trace.append("JSON fields parsed safely")

    # --- 3. Applicability: which layers apply ----------------------------
    if enabled_layers is None:
        enabled_set = set(LAYER_IDS)
    else:
        enabled_set = set(enabled_layers)
    disabled_set = set(LAYER_IDS) - enabled_set

    applicable = {
        "layer1": ("layer1" in enabled_set) and bool(context.description.strip()),
        "layer2": ("layer2" in enabled_set),  # sensitive-resource scan always runs over all fields
        "layer3": ("layer3" in enabled_set) and bool(context.schema.strip()),
        # Layer 4 applies when there is a proposed call to check against policy.
        "layer4": ("layer4" in enabled_set) and bool(context.call.strip()),
        "layer5": ("layer5" in enabled_set) and bool(context.task.strip()) and bool(context.call.strip()),
    }
    trace.append(f"Layer applicability: {applicable}")

    # --- 4. Run all detection rules --------------------------------------
    layer_findings = run_all_rules(context, parsed_schema, parsed_call,
                                   parsed_policy, disabled_layers=disabled_set)
    all_findings: list[Finding] = []
    for layer_id in LAYER_IDS:
        all_findings.extend(layer_findings.get(layer_id, []))
    trace.append(f"Total findings: {len(all_findings)}")

    # --- 5. Build layer results ------------------------------------------
    layers = _build_layer_results(layer_findings, applicable)

    # --- 6. Score --------------------------------------------------------
    score = _compute_overall_score(layers)
    trace.append(f"Overall score: {score:.4f}")

    # --- 7. Verdict policy -----------------------------------------------
    override: Optional[str] = None
    verdict: Verdict

    # 1. Invalid inputs -> ERROR (already handled above).
    # 2. CRITICAL finding -> BLOCK.
    if _has_finding(layers, Severity.CRITICAL):
        verdict = Verdict.BLOCK
        override = "CRITICAL finding present"
    # 3. HIGH finding -> BLOCK.
    elif _has_finding(layers, Severity.HIGH):
        verdict = Verdict.BLOCK
        override = "HIGH finding present"
    # 4. Applicable layer with genuine zero score -> BLOCK (override).
    elif _any_applicable_layer_zero(layers):
        verdict = Verdict.BLOCK
        override = "zero-consistency override: an applicable layer scored 0.0"
    # 5. MEDIUM-only findings -> WARN.
    elif _medium_only(layers):
        verdict = Verdict.WARN
    # 6. Missing policy coverage -> WARN at minimum.
    elif _policy_coverage_missing(layers):
        verdict = Verdict.WARN
        override = "policy coverage gap: action cannot be confirmed authorized"
    # 7. Otherwise threshold-gated ALLOW / WARN.
    elif score >= thr:
        verdict = Verdict.ALLOW
    else:
        verdict = Verdict.WARN

    trace.append(f"Verdict: {verdict.value}" + (f" (override: {override})"
                                                  if override else ""))

    latency_ms = _monotonic_ms() - start

    result = AnalysisResult(
        verdict=verdict,
        score=score,
        engine=ENGINE_NAME,
        engine_version=ENGINE_VERSION,
        latency_ms=latency_ms,
        layers=layers,
        findings=all_findings,
        trace=trace,
        override=override,
    )
    return result.to_dict()
