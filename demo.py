"""CLI demonstration using actual engine verdicts and the Devnet adapter."""
from gateway import BalanceGateway, SolanaDevnetAdapter, TOOL_NAME

ADDRESS = "11111111111111111111111111111111"  # valid 32-byte system address
BALANCE_TASK = "Check this account's SOL balance"
WARN_POLICY = {"allowed_roots": [], "allowed_actions": ["read"], "allowed_tools": [TOOL_NAME]}


def balance_call(address: str) -> dict:
    return {"tool": TOOL_NAME, "action": "read", "arguments": {"address": address}}


def transfer_call(address: str) -> dict:
    return {"tool": TOOL_NAME, "action": "write", "arguments": {"address": address, "destination": address, "amount": 1}}


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
    legit = gateway.propose(ADDRESS, user_task=BALANCE_TASK, proposed_call=balance_call(ADDRESS))
    show("Legitimate balance lookup", legit, adapter.dispatch_count - before,
         BALANCE_TASK, balance_call(ADDRESS))

    before = adapter.dispatch_count
    transfer = gateway.propose(
        ADDRESS,
        user_task=BALANCE_TASK,
        proposed_call=transfer_call(ADDRESS),
    )
    show("Transfer attempt under balance-only task", transfer, adapter.dispatch_count - before,
         BALANCE_TASK, transfer_call(ADDRESS))
    print(f"  BLOCK adapter dispatch count: {adapter.dispatch_count - before}")

    before = adapter.dispatch_count
    warn = gateway.propose(ADDRESS, user_task=BALANCE_TASK, policy=WARN_POLICY, proposed_call=balance_call(ADDRESS))
    show("Policy coverage warning", warn, adapter.dispatch_count - before,
         BALANCE_TASK, balance_call(ADDRESS))


if __name__ == "__main__":
    main()
