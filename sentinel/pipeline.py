"""Glue: raw record -> OCSF event -> detections -> alerts -> cases -> playbooks."""

import logging

from . import cases, db
from .detection import Engine
from .ocsf import detection_finding, normalize
from .soar import Playbooks

log = logging.getLogger("sentinel.pipeline")

engine: Engine | None = None
playbooks: Playbooks | None = None

MAX_BATCH = 5000


def init() -> None:
    global engine, playbooks
    engine, playbooks = Engine(), Playbooks()


def ingest(source: str, records: list) -> dict:
    if engine is None:
        init()
    if len(records) > MAX_BATCH:
        raise ValueError(f"batch too large ({len(records)} > {MAX_BATCH})")
    stored, rejected, new_alerts = 0, [], []
    for i, raw in enumerate(records):
        try:
            ev = normalize(source, raw)
        except Exception as exc:
            rejected.append({"index": i, "error": str(exc)})
            continue
        db.put("events", ev, ts=ev["time"], class_uid=ev["class_uid"])
        stored += 1
        for alert in engine.process(ev):
            new_alerts.append(_handle_alert(alert))
    return {"stored": stored, "rejected": rejected, "alerts": [a["id"] for a in new_alerts]}


def _handle_alert(alert: dict) -> dict:
    case = cases.attach_or_create(alert)
    alert["case_id"] = case["id"]
    db.put("alerts", alert, ts=alert["ts"], rule_id=alert["rule_id"], severity=alert["severity"], status=alert["status"], case_id=case["id"])
    db.put("events", detection_finding(alert), ts=alert["ts"], class_uid=2004)  # findings are OCSF events too
    for pb in playbooks.matching(alert):
        try:
            playbooks.start(pb, alert, case["id"])
        except Exception:
            log.exception("playbook %s failed to start for %s", pb["id"], alert["id"])
    return alert
