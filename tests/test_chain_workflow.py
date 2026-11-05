"""chain.yml and its watcher (D224, spec seguranca-doacoes, section 3 and attack A1): every chain run pings healthchecks.io, the plain
ping URL when the run succeeds and "/fail" when it fails, as healthchecks.io's GitHub Actions page shows. A late ping is the alarm that
the monitor stopped. The steps' own shell scripts run here against a fake curl, so the test checks what they do, not only their text."""
import os
import re
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "chain.yml"
STEP_INDENT = "      - "


def steps(text):
    """The chain job's steps, in order, each as its block of lines."""
    lines = text.split("\n")
    start = next(i for i, line in enumerate(lines) if line.strip() == "steps:")
    blocks, current = [], None
    for line in lines[start + 1:]:
        if line.strip().startswith("#"):
            continue
        if line.startswith(STEP_INDENT):
            current = [line]
            blocks.append(current)
        elif current is not None and (line.startswith("        ") or not line.strip()):
            current.append(line)
        elif line.strip():
            break
    return ["\n".join(b) for b in blocks]


def field(block, name):
    m = re.search(rf"^\s+(?:- )?{name}: (.+)$", block, flags=re.M)
    return m.group(1).strip() if m else None


def run_script(block):
    """The step's `run: |` body, without its indentation."""
    lines = block.split("\n")
    i = next(i for i, line in enumerate(lines) if re.match(r"^\s+run: \|\s*$", line))
    body = [line for line in lines[i + 1:]]
    indent = min(len(line) - len(line.lstrip()) for line in body if line.strip())
    return "\n".join(line[indent:] for line in body)


def ping_steps(text):
    """(success step, failure step) or None for each: steps that read the ping URL from the secret."""
    found = {"success()": None, "failure()": None}
    for block in steps(text):
        if "secrets.HC_PING_URL" in block:
            cond = field(block, "if")
            if cond in found:
                found[cond] = block
    return found["success()"], found["failure()"]


def call(block, url):
    """Runs the step's script with a fake curl; returns (exit code, the URLs curl was asked for)."""
    with tempfile.TemporaryDirectory() as tmp:
        log = Path(tmp) / "curl.log"
        fake = Path(tmp) / "curl"
        fake.write_text(f'#!/bin/sh\nfor a in "$@"; do case "$a" in http*) echo "$a" >> "{log}";; esac; done\nexit 0\n')
        fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
        env = {"PATH": f"{tmp}:{os.environ['PATH']}", "HC_PING_URL": url}
        proc = subprocess.run(["bash", "-e", "-c", run_script(block)], env=env, capture_output=True, text=True)
        urls = log.read_text().split() if log.exists() else []
        return proc.returncode, urls


class ChainWorkflowTest(unittest.TestCase):
    URL = "https://hc-ping.example/00000000-0000-0000-0000-000000000000"

    def setUp(self):
        self.text = WORKFLOW.read_text()

    def test_success_pings_the_plain_url(self):
        ok, _ = ping_steps(self.text)
        self.assertIsNotNone(ok, "no step pings healthchecks.io when the run succeeds")
        self.assertEqual(call(ok, self.URL), (0, [self.URL]))

    def test_failure_pings_fail(self):
        _, bad = ping_steps(self.text)
        self.assertIsNotNone(bad, "no step pings healthchecks.io /fail when the run fails")
        self.assertEqual(call(bad, self.URL), (0, [self.URL + "/fail"]))

    def test_missing_secret_fails_loudly(self):
        """A run without the secret must fail, never pass in silence (a workflow can exit 0 on a missing secret)."""
        for block in ping_steps(self.text):
            self.assertIsNotNone(block)
            code, urls = call(block, "")
            self.assertNotEqual(code, 0)
            self.assertEqual(urls, [])

    def test_pings_come_after_the_alarm(self):
        """The pings are the last steps, so the alarm's exit 1 decides which one runs."""
        names = [field(b, "name") for b in steps(self.text)]
        ok, bad = ping_steps(self.text)
        self.assertIsNotNone(ok)
        self.assertIsNotNone(bad)
        order = steps(self.text)
        self.assertGreater(order.index(ok), names.index("Alarm"))
        self.assertGreater(order.index(bad), names.index("Alarm"))

    def test_secret_reaches_only_the_pings(self):
        """The check itself never sees the ping URL: it enters through the ping steps' own env, never inline in a script."""
        for block in steps(self.text):
            if "secrets.HC_PING_URL" in block:
                self.assertIn(block, ping_steps(self.text))
                self.assertNotIn("secrets.HC_PING_URL", run_script(block))
        self.assertNotIn("HC_PING_URL", self.text.split("steps:")[0])


if __name__ == "__main__":
    unittest.main()
