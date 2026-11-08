"""Report generation for the policy-rules-v1 engine.

Produces downloadable JSON and Markdown reports. All values derive from the
real engine result; no secrets are embedded in findings.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from .models import AnalysisResult


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def report_inputs(context: Any) -> dict[str, str]:
    """SHA-256 hashes for each input (redaction of secrets handled by rules)."""
    return {
        "description_sha256": _sha256(context.description),
        "schema_sha256": _sha256(context.schema),
        "policy_sha256": _sha256(context.policy),
        "task_sha256": _sha256(context.task),
        "call_sha256": _sha256(context.call),
    }


def json_report(result: dict, context: Any, scenario_label: str | None = None) -> str:
    """Serialize a full JSON report."""
    report = {
        "generated_at_utc": _utc_now_iso(),
        "engine": result.get("engine"),
        "engine_version": result.get("engine_version"),
        "scenario": scenario_label,
        "verdict": result.get("verdict"),
        "score": result.get("score"),
        "latency_ms": result.get("latency_ms"),
        "override": result.get("override"),
        "inputs": report_inputs(context),
        "layers": result.get("layers"),
        "findings": result.get("findings"),
        "trace": result.get("trace"),
    }
    return json.dumps(report, indent=2, ensure_ascii=False)


def markdown_report(result: dict, context: Any,
                    scenario_label: str | None = None) -> str:
    """Serialize a human-readable Markdown report."""
    lines: list[str] = []
    lines.append("# MCP-CONSIST — Five-Layer Security Analysis Report")
    lines.append("")
    lines.append(f"- **Generated at (UTC):** {_utc_now_iso()}")
    lines.append(f"- **Engine:** {result.get('engine')} "
                 f"v{result.get('engine_version')}")
    lines.append(f"- **Verdict:** {result.get('verdict')}")
    lines.append(f"- **Score:** {result.get('score')}")
    lines.append(f"- **Latency (ms):** {result.get('latency_ms')}")
    if result.get("override"):
        lines.append(f"- **Override:** {result.get('override')}")
    if scenario_label:
        lines.append(f"- **Scenario:** {scenario_label}")
    lines.append("")
    lines.append("## Input hashes (SHA-256)")
    lines.append("")
    for label, digest in report_inputs(context).items():
        lines.append(f"- {label}: `{digest}`")
    lines.append("")
    lines.append("## Layer results")
    lines.append("")
    lines.append("| Layer | Status | Score | Findings |")
    lines.append("|-------|--------|-------|----------|")
    for layer in result.get("layers", []):
        lines.append(
            f"| {layer['name']} ({layer['layer_id']}) | "
            f"{layer['status']} | {layer['score']} | "
            f"{len(layer['findings'])} |"
        )
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    if not result.get("findings"):
        lines.append("No findings.")
    else:
        lines.append("| Rule | Layer | Severity | Description |")
        lines.append("|------|-------|----------|-------------|")
        for f in result["findings"]:
            lines.append(
                f"| {f['rule_id']} | {f['layer_id']} | "
                f"{f['severity']} | {f['description']} |"
            )
    lines.append("")
    lines.append("## Decision trace")
    lines.append("")
    for entry in result.get("trace", []):
        lines.append(f"- {entry}")
    lines.append("")
    lines.append("## Disclaimer")
    lines.append("")
    lines.append("ALLOW is not proof that the content is safe. BLOCK does not "
                 "mean an actual MCP request was intercepted. This is a "
                 "deterministic research prototype, not a security boundary.")
    return "\n".join(lines) + "\n"
