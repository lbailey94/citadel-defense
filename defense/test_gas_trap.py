"""Unit tests for violet_gas_trap.py."""
import unittest

import violet_gas_trap as gas_trap


class TestGasTrapHoneypot(unittest.TestCase):
    def setUp(self):
        self.treasury = "0xCitadelDefenseTreasury888888888888888888"
        self.trap_engine = gas_trap.GasTrapHoneypot(treasury_address=self.treasury)

    def test_trap_deployment(self):
        trap = self.trap_engine.deploy_trap("solana_liquidity_bait", "USDC", 2500.0)
        self.assertTrue(trap["address"].startswith("0x"))
        self.assertTrue(trap["private_key"].startswith("0x"))
        self.assertEqual(trap["native_gas_balance_wei"], 0)
        self.assertEqual(trap["token_balance"], 2500.0)

    def test_counter_sweep_captures_attacker_gas(self):
        trap = self.trap_engine.deploy_trap("whale_wallet_bait", "stETH", 10.0)
        attacker = "0xBadActorBot99999999999999999999999999999"
        deposit_wei = int(0.01 * 1e18)  # 0.01 ETH deposit

        receipt = self.trap_engine.simulate_attacker_deposit_and_counter_sweep(
            trap["address"], attacker, deposit_wei
        )

        self.assertEqual(receipt["result"], "ATTACKER_FUNDS_CAPTURED")
        self.assertEqual(receipt["treasury_destination"], self.treasury)
        self.assertGreater(receipt["bounty_extracted_wei"], 0)
        # Attacker withdrawal must have reverted
        self.assertEqual(receipt["attacker_reverted_tx"]["status"], "reverted_out_of_gas")
        self.assertGreater(self.trap_engine.captured_revenue_wei, 0)
        self.assertEqual(len(self.trap_engine.forensic_ledger), 1)


if __name__ == "__main__":
    unittest.main()
