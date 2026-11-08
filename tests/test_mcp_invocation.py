"""Exercise an MCP tool call with the official SDK and a mocked adapter."""
import asyncio

from mcp.shared.memory import create_connected_server_and_client_session

import server

ADDRESS = "11111111111111111111111111111111"


class MockAdapter:
    def __init__(self):
        self.dispatch_count = 0

    def get_balance(self, address):
        self.dispatch_count += 1
        return {"address": address, "lamports": 9, "sol": 0.000000009}


def test_mcp_call_executes_through_gateway_with_mock(tmp_path, monkeypatch):
    adapter = MockAdapter()
    monkeypatch.setattr(server.gateway, "adapter", adapter)
    monkeypatch.setattr(server.gateway, "audit_path", tmp_path / "audit.jsonl")

    async def call_tool():
        async with create_connected_server_and_client_session(server.mcp) as session:
            listed = await session.list_tools()
            assert [tool.name for tool in listed.tools] == ["solana_get_balance"]
            return await session.call_tool("solana_get_balance", {"address": ADDRESS})

    result = asyncio.run(call_tool())
    assert not result.isError
    assert adapter.dispatch_count == 1
