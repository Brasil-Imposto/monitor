"""The files the site serves (spec seguranca-doacoes, sections 6 and 7, attacks B1 and L1, and the CSP of section 8). Each run:

1. The publication: the newest GitHub Pages deployment with a success status, the run behind it (the site's own publishing
   workflow, on its branch, for the deployment's commit) and the one line of that run's build log with the set hash that
   build-manifest.py printed (Safe publishes a checksum with each release). So a manifest swapped together with a file does not
   fool the check: the served manifest must hash to what GitHub recorded when the site was published.
2. The served manifest (build-manifest.json): its set hash and, in production, its commit must match the publication.
3. Every file in the manifest, as D222 (2) decided: every 5 minutes each file is asked "did it change?" (If-None-Match) and only
   downloaded and hashed when it did; the four address pages are downloaded in full on every run; the first run of each UTC day
   downloads and hashes everything. GitHub Pages' ETag is the deploy time and the size, so a new deployment changes them all.
4. The address block (#bi-cripto-data) of every page downloaded: each address and token contract equal to pins.json, this
   repository's own copy (L1); every HTML page carries a CSP whose script-src lets no inline code run.

A site that does not answer three runs in a row is an alarm ("could not be checked"), never a green. The log carries paths,
networks and hashes, never an address. Exit 1 when there is an alarm: the GitHub e-mail of a failed run is the alarm (D216).

Run: python3 checks/served.py --target production|staging       (the monitor's run; needs GH_TOKEN to read the deployment)
     python3 checks/served.py --base URL --commit SHA --set-hash HEX [--full]
                                                        (the main repository's ci, on its local build, until the production batch)
     --state PATH (default MONITOR_STATE or state/served.json); --control b1|manifest|l1|csp plants that defect into what was
     fetched and exits 0 only when the check catches it and nothing else.
"""
import argparse
import concurrent.futures
import datetime
import gzip
import hashlib
import http.client
import json
import os
import re
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    "production": {"base": "https://brasil-imposto.github.io/", "repo": "Brasil-Imposto/brasil-imposto.github.io",
                   "workflow": ".github/workflows/pages.yml", "branch": "main", "job": "build", "commit_is_deployment": True},
    # the staging site is published by its own repository from the main repository's staging branch, so its manifest names
    # that branch's commit, not the deployment's
    "staging": {"base": "https://brasil-imposto.github.io/staging/", "repo": "Brasil-Imposto/staging",
                "workflow": ".github/workflows/deploy.yml", "branch": "main", "job": "build", "commit_is_deployment": False},
}
MANIFEST = "build-manifest.json"
SET_LINE = re.compile(r"\bthe set's sha256: ([0-9a-f]{64})\s*$")
BLOCK = re.compile(r'<script type="application/json" id="bi-cripto-data">(.*?)</script>', re.S)
CSP_META = re.compile(r'<meta http-equiv="Content-Security-Policy" content="([^"]*)"')
MISSES = 3
WORKERS = 16


def set_hash(listing):
    """The hash of the whole set, exactly as docs/superpowers/tools/build-manifest.py computes it in the site's repository."""
    return hashlib.sha256(json.dumps(listing, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


# --- 1. the publication, from GitHub's record ----------------------------------------------------------------------------------
def publication(target, api, known):
    """(publication, alarms). known: what an earlier run read; the same deployment needs no more calls (its log expires)."""
    repo = target["repo"]
    deployments = api(f"repos/{repo}/deployments?environment=github-pages&per_page=5")
    for dep in deployments:
        if known.get("deployment") == dep["id"]:
            return known, []
        statuses = api(f"repos/{repo}/deployments/{dep['id']}/statuses")
        if not statuses or statuses[0]["state"] != "success":
            continue                          # still publishing, or failed: the site serves an older one
        m = re.search(r"/actions/runs/(\d+)/job/(\d+)", statuses[0]["log_url"])
        if not m:
            return {}, [f"B1 publication: deployment {dep['id']} names no workflow run"]
        run = api(f"repos/{repo}/actions/runs/{m.group(1)}")
        wrong = [what for what, ok in (
            ("repository", run["repository"]["full_name"] == repo), ("workflow", run["path"] == target["workflow"]),
            ("branch", run["head_branch"] == target["branch"]), ("commit", run["head_sha"] == dep["sha"]),
            ("conclusion", run["conclusion"] == "success")) if not ok]
        if wrong:
            return {}, [f"B1 publication: deployment {dep['id']} came from run {run['id']} with another {', '.join(wrong)} "
                        f"than {target['workflow']} on {target['branch']}"]
        jobs = [j for j in api(f"repos/{repo}/actions/runs/{run['id']}/jobs")["jobs"] if j["name"] == target["job"]]
        lines = [SET_LINE.search(line) for line in api(f"repos/{repo}/actions/jobs/{jobs[0]['id']}/logs").splitlines()] if jobs else []
        found = [m.group(1) for m in lines if m]
        if len(found) != 1:
            return {}, [f"B1 publication: the build log of run {run['id']} has {'no set hash' if not found else 'more than one set hash'}"]
        return {"deployment": dep["id"], "sha": dep["sha"], "run": run["id"], "set_hash": found[0],
                "commit_is_deployment": target["commit_is_deployment"]}, []
    return {}, ["B1 publication: no successful GitHub Pages deployment"]


# --- 2 to 4. what is served ------------------------------------------------------------------------------------------------------
def body_of(headers, body):
    return gzip.decompress(body) if headers.get("content-encoding", "").lower() == "gzip" else body


def l1(page, html, pins):
    m = BLOCK.search(html)
    if not m:
        return [f"L1 {page}: the address block is missing"]
    try:
        networks = json.loads(m.group(1)).get("networks", [])
    except (ValueError, AttributeError):
        return [f"L1 {page}: the address block is not valid JSON"]
    out = []
    for net in networks:
        family = pins["networks"].get(net.get("id"))
        if family is None:
            out.append(f"L1 {page} {net.get('id')}: a network that pins.json does not know")
            continue
        if net.get("address") != pins["addresses"][family]:
            out.append(f"L1 {page} {net['id']}: the address differs from pins.json")
        for coin, c in sorted((net.get("coins") or {}).items()):
            if c.get("contract") and c["contract"] != pins["contracts"].get(f"{net['id']}/{coin}"):
                out.append(f"L1 {page} {net['id']} {coin}: the token contract differs from pins.json")
    return out


def csp(page, html):
    m = CSP_META.search(html)
    if not m:
        return [f"CSP {page}: no Content-Security-Policy meta"]
    script = next((d.split()[1:] for d in m.group(1).split(";") if d.split()[:1] == ["script-src"]), None)
    if script is None or {"'unsafe-inline'", "'unsafe-eval'"} & set(script):
        return [f"CSP {page}: script-src lets inline code run"]
    return []


def check(base, pub, pins, state, get, full=False, today=None, plant=None):
    """(new state, alarms). get(url, etag) returns (status, headers, body) or raises when the site does not answer."""
    today = today or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    # a new publication is downloaded whole, whatever its ETags say
    full = full or state.get("last_full") != today or state.get("publication", {}).get("set_hash") != pub.get("set_hash")
    etags = dict(state.get("etags", {}))
    alarms = []
    try:
        status, headers, raw = get(base + MANIFEST, None)
        if status != 200:
            raise OSError(f"the manifest answered HTTP {status}")
        man = json.loads(body_of(headers, raw))
        if plant:
            plant("manifest", man)
        if set_hash(man["files"]) != pub["set_hash"]:
            alarms.append(f"B1 {MANIFEST}: its set hash {set_hash(man['files'])[:16]} differs from {pub['set_hash'][:16]}, "
                          f"recorded by run {pub['run']}")
        if pub.get("commit_is_deployment") and man.get("commit") != pub["sha"]:
            alarms.append(f"B1 {MANIFEST}: it names commit {str(man.get('commit'))[:12]}, the deployment is {pub['sha'][:12]}")
        pages = set(pins["address_pages"])
        alarms += [f"L1 {p}: the address page is not in the publication" for p in sorted(pages - set(man["files"]))]

        def one(path):
            whole = full or path in pages or path not in etags
            status, headers, raw = get(base + urllib.parse.quote(path), None if whole else etags[path])
            if status == 304:
                return path, etags[path], []
            if status != 200:
                return path, None, [f"B1 {path}: not served (HTTP {status})"]
            data = body_of(headers, raw)
            if plant:
                data = plant(path, data)
            out = []
            got = hashlib.sha256(data).hexdigest()
            if got != man["files"][path]:
                out.append(f"B1 {path}: served sha256 {got[:16]} differs from the manifest's {man['files'][path][:16]}")
            if path.endswith(".html"):
                html = data.decode("utf-8", "replace")
                out += csp(path, html)
                if path in pages or 'id="bi-cripto-data"' in html:
                    out += l1(path, html, pins)
            return path, headers.get("etag"), out

        with concurrent.futures.ThreadPoolExecutor(WORKERS) as pool:
            for path, etag, found in pool.map(one, sorted(man["files"])):
                alarms += found
                if etag:
                    etags[path] = etag
                else:
                    etags.pop(path, None)
    except (OSError, ValueError, KeyError) as e:    # the site or its manifest gave no usable answer
        misses = state.get("misses", 0) + 1
        new = {**state, "misses": misses}
        return new, ([f"B1: the served files could not be checked {MISSES} runs in a row ({type(e).__name__})"]
                     if misses == MISSES else [])
    new = {"etags": etags, "misses": 0, "last_full": today if full else state.get("last_full"),
           "publication": {k: pub[k] for k in ("deployment", "sha", "run", "set_hash", "commit_is_deployment") if k in pub}}
    return new, sorted(alarms)


# --- the network ---------------------------------------------------------------------------------------------------------------
_conns = threading.local()


def fetch(url, etag=None):
    """One kept-alive connection per worker thread (thousands of "did it change?" requests a run, so no new handshake each)."""
    u = urllib.parse.urlsplit(url)
    headers = {"accept-encoding": "gzip", "user-agent": "brasil-imposto-monitor"}
    if etag:
        headers["if-none-match"] = etag
    key = (u.scheme, u.netloc)
    for attempt in (1, 2):
        conn = getattr(_conns, "map", {}).get(key)
        if conn is None:
            cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
            conn = cls(u.netloc, timeout=60)
            _conns.map = {**getattr(_conns, "map", {}), key: conn}
        try:
            conn.request("GET", u.path + (f"?{u.query}" if u.query else ""), headers=headers)
            r = conn.getresponse()
            body = r.read()
            if r.status in (200, 304, 403, 404, 410):
                return r.status, {k.lower(): v for k, v in r.getheaders()}, body
            raise OSError(f"HTTP {r.status}")
        except (http.client.HTTPException, ConnectionError, TimeoutError):
            conn.close()
            _conns.map.pop(key, None)
            if attempt == 2:
                raise OSError("the connection failed twice")
    raise OSError("unreachable")


def github(path):
    req = urllib.request.Request(f"https://api.github.com/{path}", headers={
        "accept": "application/vnd.github+json", "x-github-api-version": "2022-11-28", "user-agent": "brasil-imposto-monitor"})
    if os.environ.get("GH_TOKEN"):
        req.add_unredirected_header("authorization", f"Bearer {os.environ['GH_TOKEN']}")   # never sent on to the log's storage
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read().decode("utf-8", "replace")
    return data if path.endswith("/logs") else json.loads(data)


# --- the controls: each plants one defect into what was fetched -----------------------------------------------------------------
def planter(kind):
    chosen = {}

    def plant(path, data):
        if path == "manifest":               # called first, with the served manifest: choose the file to change
            chosen["js"] = sorted(p for p in data["files"] if p.endswith(".js"))[0]
            if kind == "manifest":           # the attacker's manifest, rewritten to match the changed file
                data["files"][chosen["js"]] = hashlib.sha256(b"planted").hexdigest()
            return data
        if kind == "manifest" and path == chosen["js"]:
            return b"planted"
        if kind == "b1" and path == chosen["js"]:
            return data[:-1] + bytes([data[-1] ^ 1])
        if kind == "l1" and path == "index.html":
            html = data.decode("utf-8")
            m = BLOCK.search(html)
            block = json.loads(m.group(1))
            block["networks"][0]["address"] = block["networks"][0]["address"][::-1]
            return (html[:m.start(1)] + json.dumps(block) + html[m.end(1):]).encode("utf-8")
        if kind == "csp" and path == "index.html":
            return CSP_META.sub("", data.decode("utf-8"), count=1).encode("utf-8")
        return data
    return plant


EXPECT = {"b1": "B1 assets/", "manifest": f"B1 {MANIFEST}", "l1": "L1 index.html", "csp": "CSP index.html"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", choices=sorted(TARGETS))
    ap.add_argument("--base")
    ap.add_argument("--commit")
    ap.add_argument("--set-hash")
    ap.add_argument("--full", action="store_true")
    ap.add_argument("--state", default=os.environ.get("MONITOR_STATE") or str(ROOT / "state" / "served.json"))
    ap.add_argument("--control", choices=sorted(EXPECT))
    args = ap.parse_args()
    state_file = Path(args.state)
    state = json.loads(state_file.read_text(encoding="utf-8")) if state_file.exists() else {}
    if args.target:
        target = TARGETS[args.target]
        base = target["base"]
        try:
            pub, alarms = publication(target, github, state.get("publication", {}))
        except (OSError, ValueError, KeyError) as e:
            pub, alarms = {}, [f"B1 publication: GitHub's record could not be read ({type(e).__name__})"]
    elif args.base and args.commit and args.set_hash:
        base = args.base.rstrip("/") + "/"
        pub, alarms = {"sha": args.commit, "set_hash": args.set_hash, "run": "of this build", "commit_is_deployment": True}, []
    else:
        ap.error("--target, or --base with --commit and --set-hash")
    if pub:
        pins = json.loads((ROOT / "pins.json").read_text(encoding="utf-8"))
        new, found = check(base, pub, pins, json.loads(json.dumps(state)), fetch, full=args.full or bool(args.control),
                           plant=planter(args.control) if args.control else None)
        alarms += found
        if not args.control:
            state_file.parent.mkdir(parents=True, exist_ok=True)
            state_file.write_text(json.dumps(new, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        files = len(new.get("etags", {}))
        print(f"served: {files} files known, last full pass {new.get('last_full')}, {len(alarms)} alarm(s)")
    for a in alarms:
        print(f"::error::{a}")
    if args.control:
        caught = [a for a in alarms if a.startswith(EXPECT[args.control])]
        # a planted page also stops matching its hash in the manifest: that B1 line is the same plant
        other = [a for a in alarms if not a.startswith(EXPECT[args.control])
                 and not (args.control in ("l1", "csp") and a.startswith("B1 index.html:"))]
        ok = bool(caught) and not other
        print(f"control {args.control}: {'caught' if ok else 'NOT caught'} ({len(caught)} planted, {len(other)} other)")
        return 0 if ok else 1
    return 1 if alarms else 0


if __name__ == "__main__":
    sys.exit(main())
