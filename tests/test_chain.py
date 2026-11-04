"""checks/chain.py (spec seguranca-doacoes, section 14, attacks C1 and C5), on the nodes' real answers for the five addresses recorded on
2026-11-03 (no transaction yet), with each send planted into a copy of them."""
import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("chain", ROOT / "checks" / "chain.py")
chain = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(chain)
PINS = json.loads((ROOT / "pins.json").read_text(encoding="utf-8"))
FX = {n: json.loads((ROOT / "tests" / "fixtures" / f"{n}.json").read_text(encoding="utf-8")) for n in PINS["networks"]}


def node(answers, solana_tx=None):
    """A fake fetch: each node's recorded answer, or the planted one."""
    def get(url, body=None):
        if "mempool.space" in url: return answers["bitcoin"]
        if "ethereum-rpc" in url: return answers["ethereum"]
        if "bsc-rpc" in url: return answers["bsc"]
        if "trongrid" in url: return answers["tron"]
        if "xrplcluster" in url: return answers["xrp-ledger"]
        if body and body["method"] == "getTransaction": return {"jsonrpc": "2.0", "id": 1, "result": (solana_tx or {})[body["params"][0]]}
        return answers["solana"]
    return get


def run(state, answers, solana_tx=None):
    get = node(answers, solana_tx)
    results = {n: chain.read(n, PINS["addresses"][g], state.get(n, {}).get("marker"), get) for n, g in PINS["networks"].items()}
    return chain.step(state, results)


class ChainTest(unittest.TestCase):
    def setUp(self):
        self.base, alarms = run({}, FX)
        self.assertEqual(alarms, [], "the first run only sets the markers")

    def test_control_the_same_answers_raise_nothing(self):
        self.assertEqual(run(self.base, FX)[1], [])

    def test_c1_a_send_on_each_network_is_an_alarm(self):
        sol = PINS["addresses"][PINS["networks"]["solana"]]
        plants = {
            "bitcoin": lambda a: a["bitcoin"]["chain_stats"].__setitem__("spent_txo_count", 1),
            "ethereum": lambda a: a["ethereum"].__setitem__("result", "0x1"),
            "bsc": lambda a: a["bsc"].__setitem__("result", "0x1"),
            "tron": lambda a: a["tron"].__setitem__("data", [{"txID": "ab" * 32}]),
            "solana": lambda a: a["solana"].__setitem__("result", [{"signature": "S1"}]),
        }
        tx = {"S1": {"transaction": {"message": {"accountKeys": [{"pubkey": sol, "signer": True}]}}}}
        for network, plant in plants.items():
            with self.subTest(network=network):
                answers = copy.deepcopy(FX); plant(answers)
                alarms = run(self.base, answers, tx)[1]
                self.assertEqual([a.split(":")[0] for a in alarms], [f"C1 {network}"])

    def test_xrp_only_a_rise_of_the_sequence_after_the_account_exists_is_a_send(self):
        made = copy.deepcopy(FX); made["xrp-ledger"] = {"result": {"account_data": {"Sequence": 100}}}
        state, alarms = run(self.base, made)
        self.assertEqual(alarms, [], "the account appearing with its first payment is no send")
        sent = copy.deepcopy(made); sent["xrp-ledger"]["result"]["account_data"]["Sequence"] = 101
        self.assertEqual([a.split(":")[0] for a in run(state, sent)[1]], ["C1 xrp-ledger"])

    def test_control_an_incoming_solana_signature_is_no_send(self):
        answers = copy.deepcopy(FX); answers["solana"]["result"] = [{"signature": "S2"}]
        tx = {"S2": {"transaction": {"message": {"accountKeys": [{"pubkey": "SomeoneElse", "signer": True}]}}}}
        self.assertEqual(run(self.base, answers, tx)[1], [])

    def test_c5_a_node_silent_three_runs_is_an_alarm_two_are_not(self):
        state = self.base
        for i in range(1, 4):
            results = {n: (RuntimeError("down") if n == "ethereum" else chain.read(n, PINS["addresses"][g], state.get(n, {}).get("marker"), node(FX)))
                       for n, g in PINS["networks"].items()}
            state, alarms = chain.step(state, results)
            self.assertEqual([a.split(":")[0] for a in alarms], ["C5 ethereum"] if i == 3 else [], f"run {i}")
        state, alarms = run(state, FX)
        self.assertEqual((alarms, state["ethereum"]["misses"]), ([], 0), "an answer resets the count")

    def test_the_log_never_carries_an_address(self):
        answers = copy.deepcopy(FX); answers["ethereum"]["result"] = "0x1"
        alarms = run(self.base, answers)[1]
        for a in PINS["addresses"].values():
            self.assertNotIn(a, " ".join(alarms))


if __name__ == "__main__":
    unittest.main()
