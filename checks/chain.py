"""The five donation addresses on their chains (spec seguranca-doacoes, section 9, attacks C1 and C5): every 15 minutes, through the
free public nodes and with no key, any transaction LEAVING an address is an alarm, as Lido's open watcher alerts on every transaction
of its treasury multisig. A token approval is a transaction leaving the address, so it is seen too. A node that does not answer three
runs in a row is an alarm too ("could not check"), never a green.

Each network keeps a marker in state/chain.json that only grows when the address sends: Bitcoin, the outputs it spent; Ethereum and
BNB Smart Chain, the nonce; Tron, its newest outgoing transaction; the XRP Ledger, the account's Sequence; Solana, the signatures the
address signed. The first run sets the markers. The log carries types, networks and transaction hashes, never an address or a value.

Run: python3 checks/chain.py   (exit 1 when there is an alarm; the GitHub e-mail of a failed run is the alarm, D216)
"""
import json
import os
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = Path(os.environ.get("MONITOR_STATE") or ROOT / "state" / "chain.json")   # the workflow points it at the state branch
NODES = {"bitcoin": "https://mempool.space/api/address/{a}", "ethereum": "https://ethereum-rpc.publicnode.com",
         "bsc": "https://bsc-rpc.publicnode.com", "tron": "https://api.trongrid.io/v1/accounts/{a}/transactions?only_from=true&limit=1",
         "xrp-ledger": "https://xrplcluster.com", "solana": "https://api.mainnet-beta.solana.com"}
MISSES = 3


def fetch(url, body=None):
    req = urllib.request.Request(url, json.dumps(body).encode() if body is not None else None,
                                 {"content-type": "application/json", "user-agent": "brasil-imposto-monitor"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def rpc(url, method, params, get=fetch):
    out = get(url, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    if "result" not in out:
        raise RuntimeError(f"node error on {method}")
    return out["result"]


def read(network, address, previous, get=fetch):
    """(marker, outgoing transaction hashes found now) for one network; raises when the node gives no usable answer."""
    if network == "bitcoin":
        r = get(NODES["bitcoin"].format(a=address))
        return r["chain_stats"]["spent_txo_count"] + r["mempool_stats"]["spent_txo_count"], []
    if network in ("ethereum", "bsc"):
        return int(rpc(NODES[network], "eth_getTransactionCount", [address, "pending"], get), 16), []
    if network == "tron":
        data = get(NODES["tron"].format(a=address)).get("data")
        if data is None:
            raise RuntimeError("tron: no data")
        newest = data[0]["txID"] if data else ""
        return newest, [newest] if newest and newest != previous else []
    if network == "xrp-ledger":
        r = get(NODES["xrp-ledger"], {"method": "account_info", "params": [{"account": address, "ledger_index": "validated"}]})["result"]
        if r.get("error") == "actNotFound":
            return None, []
        if "account_data" not in r:
            raise RuntimeError("xrp: no account data")
        return r["account_data"]["Sequence"], []
    if network == "solana":
        sigs = rpc(NODES["solana"], "getSignaturesForAddress", [address, {"limit": 25}], get)
        newest = sigs[0]["signature"] if sigs else previous or ""
        mine = []
        for s in sigs:
            if s["signature"] == previous:
                break
            tx = rpc(NODES["solana"], "getTransaction", [s["signature"], {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}], get)
            keys = (tx or {}).get("transaction", {}).get("message", {}).get("accountKeys", [])
            if any(k.get("pubkey") == address and k.get("signer") for k in keys):
                mine.append(s["signature"])
        return newest, mine
    raise ValueError(network)


def grew(network, before, now):
    """Whether the marker shows a transaction sent since the last run (the first run only sets it)."""
    if before is None and network != "xrp-ledger":
        return False
    if network in ("bitcoin", "ethereum", "bsc"):
        return now > before
    if network == "xrp-ledger":   # the account appears with its first incoming payment; only a later rise is a send
        return isinstance(before, int) and isinstance(now, int) and now > before
    return False                  # tron and solana report their outgoing hashes directly


def step(state, results):
    """results: {network: (marker, outgoing) or an Exception}. Returns the new state and the alarms."""
    new, alarms = {}, []
    for network, r in results.items():
        old = state.get(network, {"marker": None, "misses": 0, "set": False})
        if isinstance(r, Exception):
            misses = old.get("misses", 0) + 1
            new[network] = {**old, "misses": misses}
            if misses == MISSES:
                alarms.append(f"C5 {network}: the node did not answer {MISSES} runs in a row; the address could not be checked")
            continue
        marker, outgoing = r
        if old.get("set") and (outgoing or grew(network, old.get("marker"), marker)):
            alarms.append(f"C1 {network}: a transaction left the project's address" + (f" ({', '.join(outgoing)})" if outgoing else ""))
        new[network] = {"marker": marker, "misses": 0, "set": True}
    return new, alarms


def main():
    pins = json.loads((ROOT / "pins.json").read_text(encoding="utf-8"))
    state = json.loads(STATE.read_text(encoding="utf-8")) if STATE.exists() else {}
    results = {}
    for network, group in pins["networks"].items():
        try:
            results[network] = read(network, pins["addresses"][group], state.get(network, {}).get("marker"))
        except Exception as e:   # noqa: BLE001  any failure of a node counts as no answer
            results[network] = e
    new, alarms = step(state, results)
    STATE.write_text(json.dumps(new, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    for network, r in results.items():
        print(f"{network}: {'no answer' if isinstance(r, Exception) else 'checked'}")
    for a in alarms:
        print(f"::error::{a}")
    return 1 if alarms else 0


if __name__ == "__main__":
    sys.exit(main())
