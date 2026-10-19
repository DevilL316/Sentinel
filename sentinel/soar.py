"""SOAR: YAML playbooks, an action registry, and approval gates.

Actions are simulated (dry-run) in this prototype: they record what *would* happen. A real
deployment replaces the bodies in ACTIONS with connector calls (firewall, EDR, IdP, ticketing).
With SENTINEL_DRY_RUN=0 an action with no connector refuses to run rather than pretending.

Safety model: steps marked `requires_approval` pause the run until a person approves or denies.
Containment that can disrupt the business (blocking, disabling, isolating) should always be gated.
"""

import ipaddress
import re
import zlib
from pathlib import Path
from typing import Any, Callable

import yaml

from . import cases, config, db, triage
from .db import new_id, now_ms

# --------------------------------------------------------------------------- simulated world

_INTEL_BAD = [ipaddress.ip_network("203.0.113.0/24"), ipaddress.ip_network("198.51.100.0/24")]  # documentation ranges
_INTERNAL = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10")]
_PRIVILEGED = {"root", "administrator", "admin"}


def is_internal(addr: "ipaddress.IPv4Address | ipaddress.IPv6Address") -> bool:
    """Explicit internal-range check. ipaddress.is_private is too broad here: it also flags the
    RFC 5737 documentation ranges, which this prototype uses as stand-ins for external attackers."""
    return any(addr in n for n in _INTERNAL)
FIREWALL: set[str] = set()
DISABLED_USERS: set[str] = set()
ISOLATED_HOSTS: set[str] = set()


def _live_guard(name: str) -> None:
    if not config.SOAR_DRY_RUN:
        raise RuntimeError(f"action '{name}' has no connector configured; refusing to simulate in live mode")


def a_enrich_ip(p: dict, ctx: dict) -> dict:
    ip = p.get("ip")
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        return {"ip": ip, "reputation": "unknown", "note": "not a valid IP"}
    private = is_internal(addr)
    bad = any(addr in n for n in _INTEL_BAD)
    return {"ip": str(addr), "private": private, "source": "local-intel",
            "reputation": "malicious" if bad else ("internal" if private else "unknown")}


def a_enrich_user(p: dict, ctx: dict) -> dict:
    u = str(p.get("user", ""))
    return {"user": u, "privileged": u.lower() in _PRIVILEGED, "source": "local-directory"}


def a_block_ip(p: dict, ctx: dict) -> dict:
    _live_guard("block_ip")
    ip = str(p.get("ip", ""))
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"blocked": False, "reason": "refusing to block an invalid address"}
    if is_internal(addr):
        return {"blocked": False, "reason": "refusing to block an internal address"}
    FIREWALL.add(ip)
    return {"blocked": True, "ip": ip, "simulated": True}


def a_disable_user(p: dict, ctx: dict) -> dict:
    _live_guard("disable_user")
    DISABLED_USERS.add(str(p.get("user")))
    return {"disabled": True, "user": p.get("user"), "simulated": True}


def a_isolate_host(p: dict, ctx: dict) -> dict:
    _live_guard("isolate_host")
    ISOLATED_HOSTS.add(str(p.get("host")))
    return {"isolated": True, "host": p.get("host"), "simulated": True}


def a_reset_credentials(p: dict, ctx: dict) -> dict:
    _live_guard("reset_credentials")
    return {"reset_required": True, "user": p.get("user"), "simulated": True}


def a_create_ticket(p: dict, ctx: dict) -> dict:
    return {"ticket": f"SEC-{zlib.crc32(ctx['alert']['id'].encode()) % 9000 + 1000}", "title": p.get("title"), "simulated": True}


def a_notify(p: dict, ctx: dict) -> dict:
    return {"channel": p.get("channel", "#soc"), "message": p.get("message", ""), "simulated": True}


def a_add_note(p: dict, ctx: dict) -> dict:
    cases.add_note(ctx["case_id"], "playbook", str(p.get("text", "")))
    return {"noted": True}


def a_ai_triage(p: dict, ctx: dict) -> dict:
    intel = ctx["steps"].get(p.get("intel_step", ""), {}).get("output")
    result = triage.analyze(ctx["alert"], intel)
    cases.set_triage(ctx["case_id"], result)
    return result


ACTIONS: dict[str, Callable[[dict, dict], dict]] = {
    "enrich_ip": a_enrich_ip, "enrich_user": a_enrich_user, "block_ip": a_block_ip,
    "disable_user": a_disable_user, "isolate_host": a_isolate_host, "reset_credentials": a_reset_credentials,
    "create_ticket": a_create_ticket, "notify": a_notify, "add_case_note": a_add_note, "ai_triage": a_ai_triage,
}

# --------------------------------------------------------------------------- templating and conditions

_TPL = re.compile(r"\{\{\s*([\w.\-]+)\s*\}\}")


def _lookup(path: str, ctx: dict) -> Any:
    cur: Any = ctx
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def render(value: Any, ctx: dict) -> Any:
    if isinstance(value, str):
        whole = _TPL.fullmatch(value.strip())
        if whole:
            return _lookup(whole[1], ctx)
        return _TPL.sub(lambda m: str(_lookup(m[1], ctx) if _lookup(m[1], ctx) is not None else ""), value)
    if isinstance(value, dict):
        return {k: render(v, ctx) for k, v in value.items()}
    if isinstance(value, list):
        return [render(v, ctx) for v in value]
    return value


def check(spec: dict | None, ctx: dict) -> bool:
    """`when:` conditions are data, not code: all / any / not plus leaf comparisons on a path."""
    if not spec:
        return True
    if "all" in spec:
        return all(check(s, ctx) for s in spec["all"])
    if "any" in spec:
        return any(check(s, ctx) for s in spec["any"])
    if "not" in spec:
        return not check(spec["not"], ctx)
    val = _lookup(spec["path"], ctx)
    if "equals" in spec:
        return val == spec["equals"]
    if "in" in spec:
        return val in spec["in"]
    if "gte" in spec:
        return val is not None and val >= spec["gte"]
    if "lte" in spec:
        return val is not None and val <= spec["lte"]
    if "exists" in spec:
        return (val is not None) == bool(spec["exists"])
    return False


# --------------------------------------------------------------------------- playbooks

class Playbooks:
    def __init__(self, directory: Path | None = None):
        self.items: dict[str, dict] = {}
        for p in sorted(Path(directory or config.PLAYBOOKS_DIR).glob("*.y*ml")):
            pb = yaml.safe_load(p.read_text())
            self._validate(pb, p.name)
            self.items[pb["id"]] = pb

    @staticmethod
    def _validate(pb: dict, name: str) -> None:
        for key in ("id", "name", "trigger", "steps"):
            if key not in pb:
                raise ValueError(f"{name}: playbook missing '{key}'")
        ids = set()
        for s in pb["steps"]:
            if s["action"] not in ACTIONS:
                raise ValueError(f"{name}: unknown action '{s['action']}'")
            if s["id"] in ids:
                raise ValueError(f"{name}: duplicate step id '{s['id']}'")
            ids.add(s["id"])

    def matching(self, alert: dict) -> list[dict]:
        out = []
        for pb in self.items.values():
            t = pb["trigger"]
            if t.get("rule_ids") and alert["rule_id"] not in t["rule_ids"]:
                continue
            if t.get("tactics") and not (set(t["tactics"]) & {x["name"] for a in alert["attack"] for x in a.get("tactics", [])}):
                continue
            if alert["severity"] < t.get("min_severity", 0):
                continue
            out.append(pb)
        return out

    def catalog(self) -> list[dict]:
        return [{"id": p["id"], "name": p["name"], "trigger": p["trigger"],
                 "steps": [{"id": s["id"], "action": s["action"], "requires_approval": bool(s.get("requires_approval"))}
                           for s in p["steps"]]} for p in self.items.values()]

    # ---- execution
    def start(self, pb: dict, alert: dict, case_id: str) -> dict:
        run = {"id": new_id("run"), "ts": now_ms(), "playbook_id": pb["id"], "playbook": pb["name"],
               "alert_id": alert["id"], "case_id": case_id, "status": "running", "cursor": 0,
               "steps": [{"id": s["id"], "action": s["action"], "status": "pending", "output": None,
                          "requires_approval": bool(s.get("requires_approval"))} for s in pb["steps"]]}
        db.audit("playbook", "run_started", run=run["id"], playbook=pb["id"], alert=alert["id"])
        return self._advance(run, pb)

    def _ctx(self, run: dict, alert: dict) -> dict:
        return {"alert": alert, "case_id": run["case_id"],
                "steps": {s["id"]: {"output": s["output"], "status": s["status"]} for s in run["steps"]}}

    def _advance(self, run: dict, pb: dict) -> dict:
        alert = db.get("alerts", run["alert_id"])
        run["status"] = "running"
        while run["cursor"] < len(pb["steps"]):
            spec, st = pb["steps"][run["cursor"]], run["steps"][run["cursor"]]
            ctx = self._ctx(run, alert)
            if st["status"] == "pending":
                if not check(spec.get("when"), ctx):
                    st["status"] = "skipped"
                    run["cursor"] += 1
                    continue
                if spec.get("requires_approval"):
                    st["status"] = "awaiting_approval"
                    st["approval"] = {"approvers": spec.get("approvers", ["soc_lead"]),
                                      "proposed": render(spec.get("params", {}), ctx)}
                    run["status"] = "awaiting_approval"
                    db.audit("playbook", "approval_requested", run=run["id"], step=st["id"], proposed=st["approval"]["proposed"])
                    break
            if st["status"] in ("pending", "approved"):
                try:
                    st["output"] = ACTIONS[spec["action"]](render(spec.get("params", {}), ctx), ctx)
                    st["status"] = "done"
                except Exception as exc:
                    st["status"], st["output"] = "failed", {"error": str(exc)}
                    if spec.get("on_error") != "continue":
                        run["status"] = "failed"
                        db.put("runs", run, ts=run["ts"], status=run["status"])
                        return run
                db.audit("playbook", "step_" + st["status"], run=run["id"], step=st["id"])
            run["cursor"] += 1
        if run["status"] == "running":
            run["status"] = "completed"
            cases.add_note(run["case_id"], "playbook", f"Playbook '{run['playbook']}' finished.")
        db.put("runs", run, ts=run["ts"], status=run["status"])
        return run

    def decide(self, run_id: str, approver: str, approve: bool, comment: str = "") -> dict:
        run = db.get("runs", run_id)
        if not run:
            raise KeyError("run not found")
        if run["status"] != "awaiting_approval":
            raise ValueError(f"run is {run['status']}, not awaiting approval")
        st = run["steps"][run["cursor"]]
        allowed = st["approval"]["approvers"]
        if approver not in allowed:
            raise PermissionError(f"'{approver}' is not an approver for this step (allowed: {', '.join(allowed)})")
        st["status"] = "approved" if approve else "denied"
        st["decision"] = {"by": approver, "approved": approve, "comment": comment, "ts": now_ms()}
        db.audit(approver, "approval_" + ("granted" if approve else "denied"), run=run_id, step=st["id"], comment=comment)
        cases.add_note(run["case_id"], approver, f"{'Approved' if approve else 'Denied'} step '{st['id']}'. {comment}".strip())
        if not approve:
            run["cursor"] += 1
        return self._advance(run, self.items[run["playbook_id"]])
