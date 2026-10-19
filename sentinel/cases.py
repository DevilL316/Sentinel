"""Case management. Related alerts are grouped into one case so analysts see an incident, not 30 alerts."""

from . import db
from .db import new_id, now_ms

GROUP_WINDOW_MS = 60 * 60 * 1000  # alerts sharing an entity within an hour join the same open case


def _shares_entity(case: dict, alert: dict) -> bool:
    for key in ("src_ip", "user", "host"):
        v = alert["entities"].get(key)
        if v and case["entities"].get(key) == v:
            return True
    return False


def attach_or_create(alert: dict) -> dict:
    for case in db.list_("cases", 50, "WHERE status != 'closed'"):
        if now_ms() - case["ts"] < GROUP_WINDOW_MS and _shares_entity(case, alert):
            case["alerts"].append(alert["id"])
            case["severity"] = max(case["severity"], alert["severity"])
            for k, v in alert["entities"].items():
                case["entities"].setdefault(k, v)
            case["timeline"].append({"ts": now_ms(), "text": f"Alert added: {alert['title']}"})
            db.put("cases", case, ts=case["ts"], status=case["status"])
            return case
    case = {
        "id": new_id("case"), "ts": now_ms(), "status": "open", "title": alert["title"],
        "severity": alert["severity"], "alerts": [alert["id"]], "entities": dict(alert["entities"]),
        "notes": [], "timeline": [{"ts": now_ms(), "text": f"Case opened from alert: {alert['title']}"}],
        "triage": None, "assignee": None,
    }
    db.put("cases", case, ts=case["ts"], status="open")
    return case


def add_note(case_id: str, author: str, text: str) -> dict | None:
    case = db.get("cases", case_id)
    if not case:
        return None
    case["notes"].append({"ts": now_ms(), "author": author, "text": text})
    case["timeline"].append({"ts": now_ms(), "text": f"Note by {author}"})
    db.put("cases", case, ts=case["ts"], status=case["status"])
    return case


def update(case_id: str, **fields) -> dict | None:
    case = db.get("cases", case_id)
    if not case:
        return None
    for k in ("status", "assignee"):
        if k in fields and fields[k] is not None:
            case[k] = fields[k]
            case["timeline"].append({"ts": now_ms(), "text": f"{k} set to {fields[k]}"})
    if "triage" in fields:
        case["triage"] = fields["triage"]
    db.put("cases", case, ts=case["ts"], status=case["status"])
    return case


def set_triage(case_id: str, result: dict) -> dict | None:
    """A case holds several alerts; keep the triage of the highest-priority one rather than the latest."""
    case = db.get("cases", case_id)
    if not case:
        return None
    current = case.get("triage")
    if current and current.get("priority_score", 0) > result.get("priority_score", 0):
        return case
    return update(case_id, triage=result)
