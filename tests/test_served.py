"""checks/served.py (spec seguranca-doacoes, sections 6, 7 and 14, attacks B1 and L1, and the CSP of section 8), on a small site
that carries the real address block of the staging build (recorded 2026-11-04) and a manifest made the way build-manifest.py makes
it, served by a fake host that answers "did it change?" (If-None-Match, 304) as GitHub Pages does; and on GitHub's real answers
for the staging and production Pages deployments (recorded 2026-11-04), each defect planted into a copy of them."""
import copy
import gzip
import hashlib
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("served", ROOT / "checks" / "served.py")
served = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(served)
PINS = json.loads((ROOT / "pins.json").read_text(encoding="utf-8"))
BLOCK = json.loads((ROOT / "tests" / "fixtures" / "served" / "block.json").read_text(encoding="utf-8"))
API = json.loads((ROOT / "tests" / "fixtures" / "served" / "github-api.json").read_text(encoding="utf-8"))
BASE = "https://site.test/"
CSP = ("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; script-src 'self'; style-src 'self' "
       "'unsafe-inline'; object-src 'none'; base-uri 'none'\">")
ADDRESSES = [a for a in PINS["addresses"].values()]


def page(block=BLOCK, csp=CSP):
    data = "" if block is None else f'<script type="application/json" id="bi-cripto-data">{json.dumps(block)}</script>'
    return f"<!doctype html><html><head>{csp}</head><body><main>Apoie</main>{data}</body></html>".encode()


def site():
    files = {p: page() for p in PINS["address_pages"]}
    files["BRASIL-IMPOSTO_DESIGN_old-round_2026-10-21.html"] = page(block=None)
    files["assets/bi-cripto.js"] = b"export const send = () => 1;\n"
    files["assets/bi-data.js"] = b"window.BI = {};\n" * 50
    return files


def manifest(files, commit="c0ffee"):
    listing = {p: hashlib.sha256(b).hexdigest() for p, b in sorted(files.items())}
    return {"commit": commit, "built_at": "2026-11-04T00:00:00Z", "files": listing}, served.set_hash(listing)


class Host:
    """GitHub Pages as the check sees it: gzip on request, an ETag per file, 304 when the ETag still matches."""

    def __init__(self, files, man, version=1, down=False):
        self.files, self.man, self.version, self.down = dict(files), man, version, down
        self.full, self.asked = [], []

    def etag(self, path):
        return f'"v{self.version}-{len(self.files[path])}"'

    def __call__(self, url, etag=None):
        if self.down:
            raise OSError("connection refused")
        path = url[len(BASE):]
        self.asked.append(path)
        if path == "build-manifest.json":
            self.full.append(path)
            return 200, {}, json.dumps(self.man).encode()
        if path not in self.files:
            return 404, {}, b"not found"
        if etag is not None and etag == self.etag(path):
            return 304, {"etag": etag}, b""
        self.full.append(path)
        return 200, {"etag": self.etag(path)}, self.files[path]


def anchor(set_hash, commit="c0ffee"):
    return {"sha": commit, "set_hash": set_hash, "commit_is_deployment": True, "run": 1}


def check(host, pub, state=None, full=False, today="2026-11-04"):
    return served.check(BASE, pub, PINS, state or {}, host, full=full, today=today)


class ServedTest(unittest.TestCase):
    def setUp(self):
        self.files = site()
        self.man, self.set_hash = manifest(self.files)

    def run_on(self, files=None, man=None, pub=None, **kw):
        host = Host(files or self.files, man or self.man)
        state, alarms = check(host, pub or anchor(self.set_hash), **kw)
        return host, state, alarms

    # --- the controls: the right site gives no alarm -----------------------------------------------------------------
    def test_control_the_right_site_gives_no_alarm(self):
        host, state, alarms = self.run_on(full=True)
        self.assertEqual(alarms, [])
        self.assertEqual(sorted(host.full), sorted(list(self.files) + ["build-manifest.json"]), "a full pass downloads every file")
        self.assertEqual(state["last_full"], "2026-11-04")

    def test_control_a_paused_network_has_no_address_and_no_alarm(self):
        block = copy.deepcopy(BLOCK)
        block["networks"] = [n for n in block["networks"] if n["id"] != "tron"]
        files = {**self.files, "index.html": page(block)}
        man, sh = manifest(files)
        self.assertEqual(self.run_on(files, man, anchor(sh), full=True)[2], [])

    # --- B1: a served file differs from the manifest of the commit in the air ------------------------------------------
    def test_b1_a_changed_byte_is_an_alarm_with_the_path_and_both_hashes(self):
        files = dict(self.files)
        files["assets/bi-cripto.js"] = files["assets/bi-cripto.js"].replace(b"1", b"2")
        _, _, alarms = self.run_on(files, full=True)
        self.assertEqual(len(alarms), 1, alarms)
        self.assertIn("B1 assets/bi-cripto.js", alarms[0])
        self.assertIn(hashlib.sha256(files["assets/bi-cripto.js"]).hexdigest()[:16], alarms[0])
        self.assertIn(self.man["files"]["assets/bi-cripto.js"][:16], alarms[0])

    def test_b1_the_manifest_changed_together_with_the_file_does_not_fool_it(self):
        files = dict(self.files)
        files["assets/bi-cripto.js"] = b"export const send = () => steal();\n"
        man, _ = manifest(files)                     # the attacker serves a manifest that matches the new file
        _, _, alarms = self.run_on(files, man, anchor(self.set_hash), full=True)
        self.assertEqual(len(alarms), 1, alarms)
        self.assertIn("B1 build-manifest.json", alarms[0])
        self.assertIn("run 1", alarms[0])

    def test_b1_a_manifest_with_another_commit_is_an_alarm(self):
        man = {**self.man, "commit": "deadbeef"}
        alarms = self.run_on(man=man, full=True)[2]
        self.assertEqual(len(alarms), 1, alarms)
        self.assertIn("B1 build-manifest.json", alarms[0])
        self.assertIn("commit", alarms[0])

    def test_b1_a_file_no_longer_served_is_an_alarm(self):
        files = dict(self.files)
        del files["assets/bi-data.js"]
        alarms = self.run_on(files, full=True)[2]
        self.assertEqual(alarms, ["B1 assets/bi-data.js: not served (HTTP 404)"])

    # --- L1: an address or a contract changed in the served block --------------------------------------------------------
    def plant(self, block, page_name="index.html"):
        files = {**self.files, page_name: page(block)}
        man, sh = manifest(files)                    # the planted page in the manifest too: L1 must stand on its own
        return self.run_on(files, man, anchor(sh), full=True)[2]

    def test_l1_a_changed_address_names_the_network_never_the_address(self):
        block = copy.deepcopy(BLOCK)
        evil = "0x" + "ab" * 20
        for n in block["networks"]:
            if n["id"] == "bsc":
                n["address"] = evil
        alarms = self.plant(block)
        self.assertEqual(len(alarms), 1, alarms)
        self.assertIn("L1 index.html bsc", alarms[0])
        self.assertNotIn(evil, alarms[0])
        for a in ADDRESSES:
            self.assertNotIn(a, alarms[0])

    def test_l1_a_changed_token_contract(self):
        block = copy.deepcopy(BLOCK)
        for n in block["networks"]:
            if n["id"] == "ethereum":
                n["coins"]["USDT"]["contract"] = "0x" + "cd" * 20
        alarms = self.plant(block, "os-3-poderes.html")
        self.assertEqual(len(alarms), 1, alarms)
        self.assertIn("L1 os-3-poderes.html ethereum USDT", alarms[0])

    def test_l1_a_network_unknown_to_the_pins(self):
        block = copy.deepcopy(BLOCK)
        extra = copy.deepcopy(block["networks"][1])
        extra["id"] = "polygon"
        block["networks"].append(extra)
        alarms = self.plant(block)
        self.assertEqual(len(alarms), 1, alarms)
        self.assertIn("L1 index.html polygon", alarms[0])

    def test_l1_an_address_page_without_its_block(self):
        alarms = self.plant(None, "como-ler-o-mapa.html")
        self.assertEqual(alarms, ["L1 como-ler-o-mapa.html: the address block is missing"])

    # --- the CSP must be on every page ---------------------------------------------------------------------------------
    def test_csp_missing_from_a_page(self):
        files = {**self.files, "BRASIL-IMPOSTO_DESIGN_old-round_2026-10-21.html": page(block=None, csp="")}
        man, sh = manifest(files)
        alarms = self.run_on(files, man, anchor(sh), full=True)[2]
        self.assertEqual(alarms, ["CSP BRASIL-IMPOSTO_DESIGN_old-round_2026-10-21.html: no Content-Security-Policy meta"])

    def test_csp_that_lets_inline_code_run(self):
        files = {**self.files, "index.html": page(csp=CSP.replace("script-src 'self'", "script-src 'self' 'unsafe-inline'"))}
        man, sh = manifest(files)
        alarms = self.run_on(files, man, anchor(sh), full=True)[2]
        self.assertEqual(alarms, ["CSP index.html: script-src lets inline code run"])

    # --- D222 (2): every 5 minutes only "did it change?", the four address pages in full, everything once a day ---------
    def test_quick_run_downloads_only_the_address_pages_and_what_changed(self):
        host, state, alarms = self.run_on(full=True)
        self.assertEqual(alarms, [])
        host2 = Host(self.files, self.man)
        state2, alarms2 = check(host2, anchor(self.set_hash), state=state)
        self.assertEqual(alarms2, [])
        self.assertEqual(sorted(host2.full), sorted(PINS["address_pages"] + ["build-manifest.json"]))
        self.assertEqual(sorted(host2.asked), sorted(list(self.files) + ["build-manifest.json"]), "every file is still asked")

    def test_quick_run_downloads_and_catches_a_changed_file(self):
        _, state, _ = self.run_on(full=True)
        files = dict(self.files)
        files["assets/bi-data.js"] = b"window.BI = {evil: 1};\n" * 50
        host = Host(files, self.man, version=2)           # a new ETag, as a new deployment gives every file
        _, alarms = check(host, anchor(self.set_hash), state=state)
        self.assertIn("assets/bi-data.js", host.full)
        self.assertEqual(len(alarms), 1, alarms)
        self.assertIn("B1 assets/bi-data.js", alarms[0])

    def test_the_first_run_of_a_day_is_the_full_pass(self):
        _, state, _ = self.run_on(full=True, today="2026-11-03")
        host = Host(self.files, self.man)
        state2, alarms = check(host, anchor(self.set_hash), state=state, today="2026-11-04")
        self.assertEqual(alarms, [])
        self.assertEqual(len(host.full), len(self.files) + 1)
        self.assertEqual(state2["last_full"], "2026-11-04")

    def test_a_new_publication_is_downloaded_whole(self):
        _, state, _ = self.run_on(full=True)
        files = dict(self.files)
        files["assets/bi-cripto.js"] = b"export const send = () => 3;\n"
        man, sh = manifest(files)
        host = Host(files, man)                           # same ETags: the check must not trust them across publications
        state2, alarms = check(host, anchor(sh), state=state)
        self.assertEqual(alarms, [])
        self.assertEqual(len(host.full), len(files) + 1)

    def test_l1_a_block_that_is_not_json(self):
        files = {**self.files, "index.html": page().replace(b'"networks"', b'networks', 1)}
        man, sh = manifest(files)
        self.assertEqual(self.run_on(files, man, anchor(sh), full=True)[2], ["L1 index.html: the address block is not valid JSON"])

    # --- a site that does not answer: "could not check" on the third run, never a green ------------------------------------
    def test_unreachable_site_alarms_on_the_third_run_only(self):
        state = {}
        for n in range(1, 4):
            state, alarms = check(Host(self.files, self.man, down=True), anchor(self.set_hash), state=state)
            if n < 3:
                self.assertEqual(alarms, [], f"run {n}")
        self.assertEqual(len(alarms), 1)
        self.assertIn("could not be checked 3 runs in a row", alarms[0])
        state, alarms = check(Host(self.files, self.man), anchor(self.set_hash), state=state, full=True)
        self.assertEqual(alarms, [])
        self.assertEqual(state["misses"], 0)

    def test_gzip_answers_are_hashed_after_unzipping(self):
        files = dict(self.files)

        class Gz(Host):
            def __call__(self, url, etag=None):
                status, headers, body = super().__call__(url, etag)
                if status == 200:
                    return status, {**headers, "content-encoding": "gzip"}, gzip.compress(body)
                return status, headers, body
        state, alarms = check(Gz(files, self.man), anchor(self.set_hash), full=True)
        self.assertEqual(alarms, [])


class PublicationTest(unittest.TestCase):
    """The commit and the set hash come from GitHub's record of the deployment being served, never only from the served manifest."""

    def api(self, answers):
        calls = []

        def get(path):
            calls.append(path)
            if "/statuses" in path:
                return answers["statuses"]
            if "/deployments" in path:
                return answers["deployments"]
            if path.endswith("/jobs"):
                return answers["jobs"]
            if "/actions/jobs/" in path and path.endswith("/logs"):
                return answers["build_log"]
            if "/actions/runs/" in path:
                return answers["run"]
            raise AssertionError(path)
        return get, calls

    def publication(self, name, answers=None, known=None):
        get, calls = self.api(answers or API[name])
        pub, alarms = served.publication(served.TARGETS[name], get, known or {})
        return pub, alarms, calls

    def test_control_the_staging_deployment_gives_its_recorded_set_hash(self):
        pub, alarms, _ = self.publication("staging")
        self.assertEqual(alarms, [])
        self.assertEqual(pub["set_hash"], "91a08d89085ab5e20e40def060eb1f39c28c2655988ace4de28dacdaef61b2ce")
        self.assertEqual(pub["deployment"], API["staging"]["deployments"][0]["id"])
        self.assertFalse(pub["commit_is_deployment"])

    def test_production_today_has_no_set_hash_in_its_log(self):
        pub, alarms, _ = self.publication("production")
        self.assertEqual(len(alarms), 1, alarms)
        self.assertIn("no set hash", alarms[0])

    def test_a_deployment_from_another_workflow_is_an_alarm(self):
        a = copy.deepcopy(API["staging"])
        a["run"]["path"] = ".github/workflows/evil.yml"
        alarms = self.publication("staging", a)[1]
        self.assertEqual(len(alarms), 1, alarms)
        self.assertIn("B1 publication", alarms[0])
        self.assertIn("workflow", alarms[0])

    def test_a_deployment_from_another_branch_is_an_alarm(self):
        a = copy.deepcopy(API["staging"])
        a["run"]["head_branch"] = "attacker"
        self.assertIn("branch", " ".join(self.publication("staging", a)[1]))

    def test_a_run_for_another_commit_is_an_alarm(self):
        a = copy.deepcopy(API["staging"])
        a["run"]["head_sha"] = "0" * 40
        self.assertIn("commit", " ".join(self.publication("staging", a)[1]))

    def test_two_set_hash_lines_are_an_alarm(self):
        a = copy.deepcopy(API["staging"])
        a["build_log"] += "2026-11-04T03:51:22Z 1 files; the set's sha256: " + "e" * 64 + "\n"
        self.assertIn("set hash", " ".join(self.publication("staging", a)[1]))

    def test_an_unfinished_newest_deployment_falls_back_to_the_last_successful_one(self):
        a = copy.deepcopy(API["staging"])
        a["deployments"] = [{**a["deployments"][0], "id": 1}] + a["deployments"]

        def get(path):
            if path.endswith("/deployments/1/statuses"):
                return [{"state": "in_progress", "log_url": "", "environment_url": "", "created_at": ""}]
            return self.api(a)[0](path)
        pub, alarms = served.publication(served.TARGETS["staging"], get, {})
        self.assertEqual(alarms, [])
        self.assertEqual(pub["deployment"], API["staging"]["deployments"][0]["id"])

    def test_a_known_deployment_needs_no_more_calls(self):
        pub, _, _ = self.publication("staging")
        again, alarms, calls = self.publication("staging", known=pub)
        self.assertEqual(alarms, [])
        self.assertEqual(again, pub)
        self.assertEqual(len(calls), 1, calls)


if __name__ == "__main__":
    unittest.main()
