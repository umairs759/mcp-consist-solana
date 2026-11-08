"""CLI demonstration using actual engine verdicts and the Devnet adapter."""
from gateway import BalanceGateway, SolanaDevnetAdapter, TOOL_NAME

ADDRESS = "11111111111111111111111111111111"  # valid 32-byte system address


def show(label: str, result: dict, dispatches: int, task: str, call: dict) -> None:
    analysis = result.get("analysis", {})
    print(f"\n{label}: {result.get('decision')} | status={result.get('status')} | adapter dispatches={dispatches}")
    print(f"  User task: {task}")
    print(f"  Proposed call: {call}")
    for finding in analysis.get("findings", []):
        print(f"  {finding['rule_id']} {finding['severity']}: {finding['description']}")
    if "result" in result:
        print(f"  Devnet result: {result['result']}")
    if result.get("approval_id"):
        print("  Explicit approval is required; no RPC request was sent.")


def main() -> None:
    adapter = SolanaDevnetAdapter()
    gateway = BalanceGateway(adapter=adapter)
    before = adapter.dispatch_count
    legit = gateway.propose(ADDRESS)
    show("Legitimate balance lookup", legit, adapter.dispatch_count - before,
         "Check this account's SOL balance", {"tool": TOOL_NAME, "action": "read", "arguments": {"address": ADDRESS}})

    before = adapter.dispatch_count
    transfer = gateway.propose(
        ADDRESS,
        user_task="Check this account's SOL balance",
        proposed_call={"tool": TOOL_NAME, "action": "write", "arguments": {"address": ADDRESS, "destination": ADDRESS, "amount": 1}},
    )
    show("Transfer attempt under balance-only task", transfer, adapter.dispatch_count - before,
         "Check this account's SOL balance", {"tool": TOOL_NAME, "action": "write", "arguments": {"address": ADDRESS, "destination": ADDRESS, "amount": 1}})
    print(f"  BLOCK adapter dispatch count: {adapter.dispatch_count - before}")

    incomplete_policy = {"allowed_roots": [], "allowed_actions": ["read"], "allowed_tools": [TOOL_NAME]}
    before = adapter.dispatch_count
    warn = gateway.propose(ADDRESS, policy=incomplete_policy)
    show("Policy coverage warning", warn, adapter.dispatch_count - before,
         "Check this account's SOL balance", {"tool": TOOL_NAME, "action": "read", "arguments": {"address": ADDRESS}})


if __name__ == "__main__":
    main()
