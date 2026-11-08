# MCP-Consist Solana Devnet Gateway

The core MCP-Consist detection engine predates this hackathon and is available in the original repository: https://github.com/umairs759/mcp-consist. This submission transparently distinguishes that existing engine from the new work completed during the hackathon.

This small research prototype demonstrates pre-execution analysis for one read-only MCP tool, `solana_get_balance(address)`. The engine is copied into `mcp_consist/` unchanged. New code adds a gateway, the official Python MCP SDK stdio server, a Devnet JSON-RPC adapter, an audit log, tests, and a CLI demonstration.

## How it works

Each request is assembled into the engine's five inputs: tool description, JSON schema, capability policy, user task, and proposed tool call. The existing `analyze()` function produces the decision. `ALLOW` dispatches one `getBalance` request. `WARN` records a pending request and returns an approval ID without calling the adapter; local code can call `BalanceGateway.approve(id)` to explicitly approve it. `BLOCK`, `ERROR`, and unknown outcomes fail closed. Audit records contain the decision, findings, and whether the adapter was dispatched.

The adapter uses `https://api.devnet.solana.com` by default; set `SOLANA_RPC_URL` to configure another endpoint. Addresses are base58-decoded and required to be 32 bytes. Requests have a timeout and RPC failures are returned as errors. No keys, signing, transactions, transfers, or Mainnet endpoint are included.

## Setup and run

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python server.py                 # MCP over stdio
python demo.py                   # CLI scenarios; legitimate case makes a real Devnet call
```

The MCP server exposes only `solana_get_balance(address)`. Its tool result reports `approval required` with an approval ID for a WARN. Approval is intentionally an in-process gateway API; this server does not expose a second MCP approval tool.

## Tests

```bash
pytest -q                       # complete suite, including the live Devnet smoke test
pytest -q tests/test_gateway.py   # deterministic unit tests with a mocked adapter
pytest -q tests/test_devnet.py    # separate live Devnet smoke test; requires network
```

Verified in this environment: `pytest -q` — 8 passed, including five mocked-gateway tests, an MCP tool invocation through the official SDK with a mocked adapter, an MCP stdio handshake/tool listing, and one separate real Devnet `getBalance` smoke test. `python demo.py` also completed an ALLOW balance lookup against Devnet and showed BLOCK with zero dispatches and WARN with no pre-approval dispatch.

## Limitations

This is a research prototype, not a production security boundary. The engine is deterministic and rule-based; it is not an LLM, does not guarantee detection, and does not provide complete JSON Schema validation. The approval API is local/in-process and has no persistent approval workflow. RPC availability and returned balances depend on Devnet. The MCP server uses stdio transport and does not provide a browser UI or hosted demo.
