"""Real MCP stdio handshake and tool discovery through the official SDK."""
import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def test_stdio_mcp_server_lists_balance_tool():
    project = Path(__file__).resolve().parents[1]
    params = StdioServerParameters(command=sys.executable, args=[str(project / "server.py")], cwd=str(project))

    async def check():
        async with stdio_client(params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                tools = await session.list_tools()
                assert [tool.name for tool in tools.tools] == ["solana_get_balance"]

    asyncio.run(check())
