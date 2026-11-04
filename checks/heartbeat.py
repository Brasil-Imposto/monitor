"""The daily all-clear (spec seguranca-doacoes, section 3; Prometheus Operator's "Watchdog": a signal that always fires, so its absence
is the alarm): at 9h in Brasília, one comment on the pinned issue "Sinal de vida" with the day's runs of each check and how many
alarmed. If it does not arrive by 10h, that silence is the alarm.

Run: python3 checks/heartbeat.py <runs.json>   (prints the comment; the workflow posts it)
"""
import json
import sys

WORKFLOWS = ("chain",)   # the served-files and settings checks join here when they exist


def comment(runs, day):
    """runs: the workflow runs of the last 24 hours, as the Actions API lists them."""
    lines = [f"Sinal de vida, {day}: o monitor rodou."]
    for name in WORKFLOWS:
        mine = [r for r in runs if r.get("path", "").endswith(f"/{name}.yml")]
        alarms = sum(1 for r in mine if r.get("conclusion") == "failure")
        lines.append(f"- {name}: {len(mine)} rodadas, {alarms} com alarme")
    if not any(r.get("path", "").endswith(f"/{n}.yml") for n in WORKFLOWS for r in runs):
        lines.append("Nenhuma rodada nas últimas 24 horas: confira os agendamentos.")
    return "\n".join(lines)


if __name__ == "__main__":
    data = json.load(open(sys.argv[1], encoding="utf-8"))
    print(comment(data.get("workflow_runs", []), sys.argv[2] if len(sys.argv) > 2 else ""))
