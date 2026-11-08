"""Data models for the MCP-CONSIST policy-rules-v1 engine.

All models are plain dataclasses / typed dicts so the engine stays dependency
light and trivial to serialize for reporting and the UI.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Optional
from enum import Enum


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"
    ERROR = "ERROR"


class LayerStatus(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    NA = "N/A"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Canonical layer identifiers, in stable order.
LAYER_IDS = [
    "layer1",  # Description Integrity
    "layer2",  # Sensitive Resource Protection
    "layer3",  # Schema and Parameter Integrity
    "layer4",  # Capability Policy Compliance
    "layer5",  # Joint Intent and Tool-Call Integrity
]

LAYER_NAMES = {
    "layer1": "Description Integrity",
    "layer2": "Sensitive Resource Protection",
    "layer3": "Schema and Parameter Integrity",
    "layer4": "Capability Policy Compliance",
    "layer5": "Joint Intent and Tool-Call Integrity",
}

ENGINE_NAME = "policy-rules-v1"
ENGINE_VERSION = "1.0.0"

DEFAULT_THRESHOLD = 0.8
MAX_INPUT_LENGTH = 20_000


@dataclass
class Finding:
    """A single detection finding from one rule."""

    rule_id: str
    layer_id: str
    severity: Severity
    description: str
    evidence: str = ""          # redacted / safe evidence only
    explanation: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "layer_id": self.layer_id,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "explanation": self.explanation,
        }


@dataclass
class LayerResult:
    """Result of analysing one layer."""

    layer_id: str
    name: str
    status: LayerStatus
    score: Optional[float] = None          # null when N/A
    findings: list[Finding] = field(default_factory=list)
    applicable: bool = True

    def to_dict(self) -> dict:
        return {
            "layer_id": self.layer_id,
            "name": self.name,
            "status": self.status.value,
            "score": self.score,
            "findings": [f.to_dict() for f in self.findings],
            "applicable": self.applicable,
        }


@dataclass
class AnalysisContext:
    """The five joint context inputs."""

    description: str = ""
    schema: str = ""
    policy: str = ""
    task: str = ""
    call: str = ""

    def to_dict(self) -> dict:
        return {
            "description": self.description,
            "schema": self.schema,
            "policy": self.policy,
            "task": self.task,
            "call": self.call,
        }


@dataclass
class AnalysisResult:
    """The full engine output contract."""

    verdict: Verdict
    score: float
    engine: str = ENGINE_NAME
    engine_version: str = ENGINE_VERSION
    latency_ms: float = 0.0
    layers: list[LayerResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    trace: list[str] = field(default_factory=list)
    override: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "score": self.score,
            "engine": self.engine,
            "engine_version": self.engine_version,
            "latency_ms": self.latency_ms,
            "layers": [l.to_dict() for l in self.layers],
            "findings": [f.to_dict() for f in self.findings],
            "trace": list(self.trace),
            "override": self.override,
        }

    @classmethod
    def error_result(cls, message: str, latency_ms: float = 0.0) -> "AnalysisResult":
        return cls(
            verdict=Verdict.ERROR,
            score=0.0,
            latency_ms=latency_ms,
            trace=[f"ERROR: {message}"],
        )


def empty_layer(layer_id: str, name: str, applicable: bool = True) -> LayerResult:
    status = LayerStatus.PASS if applicable else LayerStatus.NA
    score: Optional[float] = 1.0 if applicable else None
    return LayerResult(
        layer_id=layer_id,
        name=name,
        status=status,
        score=score,
        applicable=applicable,
    )
