import gateway as gateway_module
import pytest
from gateway import BalanceGateway, TOOL_NAME

ADDRESS = "11111111111111111111111111111111"


class MockAdapter:
    def __init__(self):
        self.dispatch_count = 0

    def get_balance(self, address):
        self.dispatch_count += 1
        return {"address": address, "lamports": 123, "sol": 0.000000123}


def test_allow_hits_adapter(tmp_path):
    adapter = MockAdapter()
    result = BalanceGateway(adapter, tmp_path / "audit.jsonl").propose(ADDRESS)
    assert result["decision"] == "ALLOW"
    assert result["status"] == "executed"
    assert adapter.dispatch_count == 1


def test_warn_waits_for_explicit_approval(tmp_path):
    adapter = MockAdapter()
    gateway = BalanceGateway(adapter, tmp_path / "audit.jsonl")
    policy = {"allowed_roots": [], "allowed_actions": ["read"], "allowed_tools": [TOOL_NAME]}
    pending = gateway.propose(ADDRESS, policy=policy)
    assert pending["decision"] == "WARN"
    assert pending["status"] == "approval_required"
    assert adapter.dispatch_count == 0
    approved = gateway.approve(pending["approval_id"])
    assert approved["status"] == "executed_after_approval"
    assert adapter.dispatch_count == 1


def test_block_dispatch_count_is_zero(tmp_path):
    adapter = MockAdapter()
    gateway = BalanceGateway(adapter, tmp_path / "audit.jsonl")
    result = gateway.propose(
        ADDRESS,
        user_task="Check this account's SOL balance",
        proposed_call={"tool": TOOL_NAME, "action": "write", "arguments": {"address": ADDRESS, "destination": ADDRESS, "amount": 1}},
    )
    assert result["decision"] == "BLOCK"
    assert adapter.dispatch_count == 0


def test_error_fails_closed(tmp_path, monkeypatch):
    adapter = MockAdapter()
    monkeypatch.setattr(gateway_module, "analyze", lambda ctx: {"verdict": "ERROR", "findings": [], "trace": ["bad context"]})
    result = BalanceGateway(adapter, tmp_path / "audit.jsonl").propose(ADDRESS)
    assert result["decision"] == "ERROR"
    assert adapter.dispatch_count == 0


def test_invalid_address_rejected_before_adapter(tmp_path):
    adapter = MockAdapter()
    with pytest.raises(ValueError):
        BalanceGateway(adapter, tmp_path / "audit.jsonl").propose("not a public key")
    assert adapter.dispatch_count == 0
