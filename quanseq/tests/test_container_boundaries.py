"""Regression tests for the Phase 1 process and privilege boundaries."""

import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import host_policy_agent


class HostPolicyAgentTests(unittest.TestCase):
    def test_ipsec_changes_only_allowlisted_proposals(self):
        original = """connections {
  pqc-tunnel {
    proposals = old-ike
    local_addrs = 10.0.0.1
    children { net {
      esp_proposals = old-esp
      local_ts = 10.0.0.1/32
    } }
  }
}
secrets { ike-1 { secret = never-change-this } }
"""
        with tempfile.TemporaryDirectory() as directory:
            config = pathlib.Path(directory) / "swanctl.conf"
            config.write_text(original)
            with (
                patch.object(host_policy_agent, "SWANCTL_CONFIG", config),
                patch.object(host_policy_agent.shutil, "which", return_value="/usr/sbin/swanctl"),
                patch.object(host_policy_agent, "_run", return_value="loaded"),
            ):
                result = host_policy_agent.apply_ipsec({"policy_name": "pqc-level5"})
            updated = config.read_text()
        self.assertIn("proposals = aes256-sha256-mlkem1024", updated)
        self.assertIn("esp_proposals = aes256-sha256", updated)
        self.assertIn("secret = never-change-this", updated)
        self.assertIn("local_addrs = 10.0.0.1", updated)
        self.assertEqual(result["daemon"], "strongswan")

    def test_unknown_policy_is_rejected_before_write(self):
        with tempfile.TemporaryDirectory() as directory:
            config = pathlib.Path(directory) / "swanctl.conf"
            config.write_text("unchanged")
            with patch.object(host_policy_agent, "SWANCTL_CONFIG", config):
                with self.assertRaises(ValueError):
                    host_policy_agent.apply_ipsec({"policy_name": "anything-goes"})
            self.assertEqual(config.read_text(), "unchanged")

    def test_policy_modules_contain_no_simulation_or_sudo(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        for relative in ("protocols/ipsec/policy.py", "protocols/ssh/policy.py"):
            source = (root / relative).read_text()
            self.assertNotIn("/tmp/quanseq", source)
            self.assertNotIn('"sudo"', source)
            self.assertNotIn('"pkill"', source)

    def test_api_entrypoint_does_not_start_collectors(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        source = (root / "services/api.py").read_text()
        self.assertNotIn("collect_loop", source)
        self.assertNotIn("create_task", source)

    def test_ssh_collector_does_not_claim_port_policy_as_negotiated_kex(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        source = (root / "protocols/ssh/collector.py").read_text()
        self.assertIn('kex = kex_map.get(peer) or "unknown"', source)


if __name__ == "__main__":
    unittest.main()
