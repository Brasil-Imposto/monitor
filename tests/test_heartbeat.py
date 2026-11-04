"""checks/heartbeat.py: the comment counts each check's runs and alarms, and says so when nothing ran."""
import importlib.util
import unittest
from pathlib import Path

_spec = importlib.util.spec_from_file_location("heartbeat", Path(__file__).resolve().parents[1] / "checks" / "heartbeat.py")
hb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hb)


class HeartbeatTest(unittest.TestCase):
    def test_counts_runs_and_alarms(self):
        runs = [{"path": ".github/workflows/chain.yml", "conclusion": "success"}] * 95 + [{"path": ".github/workflows/chain.yml", "conclusion": "failure"}]
        text = hb.comment(runs, "2026-11-04")
        self.assertIn("- chain: 96 rodadas, 1 com alarme", text)
        self.assertNotIn("Nenhuma rodada", text)

    def test_control_no_run_is_said(self):
        self.assertIn("Nenhuma rodada nas últimas 24 horas", hb.comment([], "2026-11-04"))


if __name__ == "__main__":
    unittest.main()
