"""Fail-closed five-context gateway for the read-only Solana balance tool."""
from __future__ import annotations

import json
import os
import secrets
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from mcp_consist import analyze

TOOL_NAME = "solana_get_balance"
TOOL_DESCRIPTION = "Read the SOL balance of one Solana account on Devnet. Read-only; no signing or transactions."
TOOL_SCHEMA = {
    "type": "object",
    "properties": {"address": {"type": "string", "description": "Base58 Solana account address"}},
    "required": ["address"],
    "additionalProperties": False,
}
COMPLETE_POLICY = {
    "allowed_roots": [], "allowed_hosts": ["api.devnet.solana.com"],
    "allowed_actions": ["read"], "allowed_tools": [TOOL_NAME],
}


def decode_base58_address(address: str) -> bytes:
    """Decode and validate a 32-byte Solana public key (no external package)."""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    if not isinstance(address, str) or not address or len(address) > 44:
        raise ValueError("address must be a base58-encoded 32-byte public key")
    number = 0
    for char in address:
        try:
            digit = alphabet.index(char)
        except ValueError as exc:
            raise ValueError("address contains a character outside the base58 alphabet") from exc
        number = number * 58 + digit
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    decoded = b"\0" * (len(address) - len(address.lstrip("1"))) + body
    if len(decoded) != 32:
        raise ValueError("address must decode to exactly 32 bytes")
    return decoded


class SolanaDevnetAdapter:
    def __init__(self, endpoint: str | None = None, timeout: float = 8.0):
        self.endpoint = endpoint or os.getenv("SOLANA_RPC_URL", "https://api.devnet.solana.com")
        parsed_endpoint = urlsplit(self.endpoint)
        if parsed_endpoint.scheme != "https" or not parsed_endpoint.hostname:
            raise ValueError("SOLANA_RPC_URL must be an HTTPS endpoint")
        if "mainnet" in parsed_endpoint.hostname.lower():
            raise ValueError("Mainnet endpoints are not supported")
        self.timeout = timeout
        self.dispatch_count = 0

    def get_balance(self, address: str) -> dict[str, Any]:
        decode_base58_address(address)
        self.dispatch_count += 1
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "getBalance", "params": [address]}).encode()
        request = urllib.request.Request(self.endpoint, data=body, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            # Do not echo endpoint URLs, which may contain provider credentials.
            raise RuntimeError(f"Solana RPC request failed ({type(exc).__name__})") from exc
        if not isinstance(payload, dict):
            raise RuntimeError("Solana RPC returned an invalid response")
        if "error" in payload:
            raise RuntimeError(f"Solana RPC error: {payload['error']}")
        result = payload.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("value"), int):
            raise RuntimeError("Solana RPC response did not contain a balance value")
        return {"address": address, "lamports": result["value"], "sol": result["value"] / 1_000_000_000, "context": result.get("context")}


@dataclass
class PendingApproval:
    context: dict[str, str]
    address: str
    analysis: dict[str, Any]


class BalanceGateway:
    """Analyzes all five inputs before a balance adapter can be reached."""
    def __init__(self, adapter: Any | None = None, audit_path: str | Path | None = None):
        self.adapter = adapter or SolanaDevnetAdapter()
        self.audit_path = Path(audit_path) if audit_path else Path(os.getenv("MCP_CONSIST_AUDIT_LOG", "audit.jsonl"))
        self.pending: dict[str, PendingApproval] = {}

    def build_context(self, user_task: str, proposed_call: dict[str, Any], policy: dict[str, Any] | None = None) -> dict[str, str]:
        return {
            "description": TOOL_DESCRIPTION,
            "schema": json.dumps(TOOL_SCHEMA, sort_keys=True),
            "policy": json.dumps(policy if policy is not None else COMPLETE_POLICY, sort_keys=True),
            "task": user_task,
            "call": json.dumps(proposed_call, sort_keys=True),
        }

    def _audit(self, decision: str, findings: list[dict], executed: bool, **extra: Any) -> None:
        record = {"decision": decision, "findings": findings, "executed": executed, **extra}
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self.audit_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, sort_keys=True) + "\n")

    def propose(self, address: str, user_task: str = "Check this account's SOL balance", *, policy: dict[str, Any] | None = None, proposed_call: dict[str, Any] | None = None) -> dict[str, Any]:
        # Reject malformed public keys before any analysis or dispatch.
        decode_base58_address(address)
        call = proposed_call or {"tool": TOOL_NAME, "action": "read", "arguments": {"address": address}}
        context = self.build_context(user_task, call, policy)
        try:
            result = analyze(context)
        except Exception as exc:
            self._audit("ERROR", [], False, analysis_error=type(exc).__name__)
            return {"status": "blocked", "decision": "ERROR", "error": "analysis failed; execution denied"}
        verdict = result.get("verdict", "ERROR")
        findings = result.get("findings", [])
        if verdict == "ALLOW":
            try:
                value = self.adapter.get_balance(address)
                self._audit(verdict, findings, True)
                return {"status": "executed", "decision": verdict, "analysis": result, "result": value}
            except Exception as exc:
                self._audit(verdict, findings, True, rpc_error=str(exc))
                return {"status": "rpc_error", "decision": verdict, "analysis": result, "error": str(exc)}
        if verdict == "WARN":
            approval_id = secrets.token_urlsafe(12)
            self.pending[approval_id] = PendingApproval(context, address, result)
            self._audit(verdict, findings, False, approval_id=approval_id)
            return {"status": "approval_required", "decision": verdict, "approval_id": approval_id, "analysis": result}
        # BLOCK, ERROR, missing verdict, and unknown verdicts all fail closed.
        decision = verdict if verdict in {"BLOCK", "ERROR"} else "ERROR"
        self._audit(decision, findings, False)
        return {"status": "blocked", "decision": decision, "analysis": result}

    def approve(self, approval_id: str) -> dict[str, Any]:
        """Explicit local approval for a previously WARNed balance lookup."""
        pending = self.pending.pop(approval_id, None)
        if pending is None:
            raise ValueError("unknown or already used approval id")
        # Revalidate address and constrain the approved operation to this tool.
        decode_base58_address(pending.address)
        call = json.loads(pending.context["call"])
        if call.get("tool") != TOOL_NAME or call.get("action") != "read":
            self._audit("WARN", pending.analysis.get("findings", []), False, approval_id=approval_id, approval_rejected=True)
            return {"status": "blocked", "decision": "WARN", "analysis": pending.analysis}
        try:
            value = self.adapter.get_balance(pending.address)
            self._audit("WARN", pending.analysis.get("findings", []), True, approval_id=approval_id, approved=True)
            return {"status": "executed_after_approval", "decision": "WARN", "analysis": pending.analysis, "result": value}
        except Exception as exc:
            self._audit("WARN", pending.analysis.get("findings", []), True, approval_id=approval_id, approved=True, rpc_error=str(exc))
            return {"status": "rpc_error", "decision": "WARN", "analysis": pending.analysis, "error": str(exc)}

