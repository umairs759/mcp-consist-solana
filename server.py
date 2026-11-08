"""Official MCP Python SDK stdio server exposing one read-only tool."""
from mcp.server.fastmcp import FastMCP

from gateway import BalanceGateway

mcp = FastMCP("MCP-Consist Solana Devnet")
gateway = BalanceGateway()


@mcp.tool()
def solana_get_balance(address: str) -> dict:
    """Read a Solana account balance on Devnet. This tool cannot sign or transfer."""
    result = gateway.propose(address)
    if result["status"] == "approval_required":
        return {"status": "approval required", "approval_id": result["approval_id"], "decision": result["decision"], "findings": result["analysis"].get("findings", [])}
    return result


if __name__ == "__main__":
    mcp.run(transport="stdio")
