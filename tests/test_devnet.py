"""Separate live smoke test; requires network access to Solana Devnet."""
from gateway import SolanaDevnetAdapter


def test_real_devnet_get_balance():
    result = SolanaDevnetAdapter(timeout=12).get_balance("11111111111111111111111111111111")
    assert result["address"] == "11111111111111111111111111111111"
    assert isinstance(result["lamports"], int)
    assert result["lamports"] >= 0
