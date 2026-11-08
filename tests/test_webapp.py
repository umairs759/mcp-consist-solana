import pytest
from fastapi.testclient import TestClient

import webapp


ADDRESS = "11111111111111111111111111111111"


class MockAdapter:
    def __init__(self):
        self.dispatch_count = 0

    def get_balance(self, address):
        self.dispatch_count += 1
        return {"address": address, "lamports": 7, "sol": 0.000000007}


@pytest.fixture
def client(tmp_path, monkeypatch):
    adapter = MockAdapter()
    monkeypatch.setattr(webapp, "adapter", adapter)
    monkeypatch.setattr(webapp.gateway, "adapter", adapter)
    monkeypatch.setattr(webapp.gateway, "audit_path", tmp_path / "audit.jsonl")
    return TestClient(webapp.app), adapter


def test_health_and_dashboard(client):
    test_client, _ = client
    health = test_client.get("/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    page = test_client.get("/")
    assert page.status_code == 200
    assert "BLOCK → ZERO DISPATCHES" in page.text
    assert "Five-context evaluation" in page.text


def test_allow_scenario_uses_gateway_and_adapter(client):
    test_client, adapter = client
    response = test_client.post("/api/scenarios/allow", json={"address": ADDRESS})
    payload = response.json()
    assert response.status_code == 200
    assert payload["outcome"]["decision"] == "ALLOW"
    assert payload["adapter_dispatches"] == 1
    assert payload["outcome"]["result"]["lamports"] == 7
    assert set(payload["context"]) == {"description", "schema", "policy", "task", "call"}
    assert adapter.dispatch_count == 1


def test_block_scenario_never_dispatches(client):
    test_client, adapter = client
    response = test_client.post("/api/scenarios/block", json={"address": ADDRESS})
    payload = response.json()
    assert response.status_code == 200
    assert payload["outcome"]["decision"] == "BLOCK"
    assert payload["adapter_dispatches"] == 0
    assert adapter.dispatch_count == 0


def test_warn_requires_explicit_approval(client):
    test_client, adapter = client
    response = test_client.post("/api/scenarios/warn", json={"address": ADDRESS})
    payload = response.json()
    assert payload["outcome"]["decision"] == "WARN"
    assert payload["outcome"]["status"] == "approval_required"
    assert payload["adapter_dispatches"] == 0
    assert adapter.dispatch_count == 0
    approved = test_client.post("/api/approve", json={"approval_id": payload["outcome"]["approval_id"]})
    assert approved.status_code == 200
    assert approved.json()["outcome"]["status"] == "executed_after_approval"
    assert approved.json()["adapter_dispatches"] == 1
    assert adapter.dispatch_count == 1


def test_invalid_address_is_rejected(client):
    test_client, adapter = client
    response = test_client.post("/api/scenarios/allow", json={"address": "bad public key"})
    assert response.status_code == 422
    assert adapter.dispatch_count == 0
