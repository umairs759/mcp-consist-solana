"""MCP-CONSIST policy-rules-v1 engine.

A deterministic, rule-based, five-layer detector for joint-context MCP tool
security analysis. Not a security boundary; not ML; no MCP interception.

Public API:
    analyze(ctx: dict, threshold: float = 0.8) -> dict
"""

from __future__ import annotations

from .engine import analyze, ENGINE_NAME, ENGINE_VERSION, DEFAULT_THRESHOLD
from .models import (AnalysisContext, AnalysisResult, Finding, LayerResult,
                     LayerStatus, Severity, Verdict)

__all__ = [
    "analyze",
    "ENGINE_NAME",
    "ENGINE_VERSION",
    "DEFAULT_THRESHOLD",
    "AnalysisContext",
    "AnalysisResult",
    "Finding",
    "LayerResult",
    "LayerStatus",
    "Severity",
    "Verdict",
]

__version__ = ENGINE_VERSION
