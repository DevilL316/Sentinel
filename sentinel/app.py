"""FastAPI service: ingestion, query, cases, playbook approvals, ATT&CK coverage, and the web console."""

import hmac
from contextlib import asynccontextmanager
from typing import Any, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from . import __version__, attack, cases, config, db, pipeline, simulate, triage


@asynccontextmanager
async def lifespan(app: FastAPI):
    pipeline.init()
    yield


app = FastAPI(title="Sentinel SIEM/SOAR", version=__version__, lifespan=lifespan)


def auth(x_api_key: str = Header(default="")) -> str:
    """Optional shared-secret auth. Set SENTINEL_API_KEY to enable. Use a real IdP/SSO in production."""
    if config.API_KEY and not hmac.compare_digest(x_api_key, config.API_KEY):
        raise HTTPException(401, "missing or invalid X-API-Key")
    return "api-user"


class IngestBody(BaseModel):
    source: Literal["syslog", "winevent", "json"]
    records: list[Any] = Field(max_length=pipeline.MAX_BATCH)


class NoteBody(BaseModel):
    author: str = Field(min_length=1, max_length=64)
    text: str = Field(min_length=1, max_length=4000)


class CasePatch(BaseModel):
    status: Literal["open", "investigating", "closed"] | None = None
    assignee: str | None = Field(default=None, max_length=64)


class Decision(BaseModel):
    approver: str = Field(min_length=1, max_length=64)
    comment: str = Field(default="", max_length=1000)


@app.get("/api/meta", dependencies=[Depends(auth)])
def meta():
    return {"version": __version__, "ocsf": config.OCSF_VERSION, "attack": config.ATTACK_VERSION,
            "sigma_spec": config.SIGMA_SPEC, "dry_run": config.SOAR_DRY_RUN,
            "ai_triage": "llm" if config.ANTHROPIC_API_KEY else "heuristic",
            "counts": {t: db.count(t) for t in ("events", "alerts", "cases", "runs")},
            "rules": len(pipeline.engine.rules), "correlations": len(pipeline.engine.correlations),
            "playbooks": len(pipeline.playbooks.items)}


@app.post("/api/ingest", dependencies=[Depends(auth)])
def ingest(body: IngestBody):
    try:
        return pipeline.ingest(body.source, body.records)
    except ValueError as exc:
        raise HTTPException(413, str(exc))


@app.get("/api/events", dependencies=[Depends(auth)])
def events(limit: int = Query(100, ge=1, le=1000), class_uid: int | None = None):
    where, args = ("WHERE class_uid=?", (class_uid,)) if class_uid is not None else ("", ())
    return db.list_("events", limit, where, args)


@app.get("/api/alerts", dependencies=[Depends(auth)])
def alerts(limit: int = Query(100, ge=1, le=1000), min_severity: int = Query(0, ge=0, le=6)):
    return db.list_("alerts", limit, "WHERE severity>=?", (min_severity,))


@app.get("/api/alerts/{alert_id}", dependencies=[Depends(auth)])
def alert(alert_id: str):
    a = db.get("alerts", alert_id)
    if not a:
        raise HTTPException(404, "alert not found")
    a["events"] = [e for e in (db.get("events", i) for i in a["event_ids"]) if e]
    return a


@app.post("/api/alerts/{alert_id}/triage", dependencies=[Depends(auth)])
def run_triage(alert_id: str):
    a = db.get("alerts", alert_id)
    if not a:
        raise HTTPException(404, "alert not found")
    result = triage.analyze(a)
    if a.get("case_id"):
        cases.set_triage(a["case_id"], result)
    db.audit("api", "triage_requested", alert=alert_id, source=result["source"])
    return result


@app.get("/api/cases", dependencies=[Depends(auth)])
def list_cases(limit: int = Query(50, ge=1, le=500)):
    return db.list_("cases", limit)


@app.get("/api/cases/{case_id}", dependencies=[Depends(auth)])
def get_case(case_id: str):
    c = db.get("cases", case_id)
    if not c:
        raise HTTPException(404, "case not found")
    c["alert_docs"] = [x for x in (db.get("alerts", i) for i in c["alerts"]) if x]
    c["runs"] = [r for r in db.list_("runs", 200) if r["case_id"] == case_id]
    return c


@app.post("/api/cases/{case_id}/notes", dependencies=[Depends(auth)])
def case_note(case_id: str, body: NoteBody):
    c = cases.add_note(case_id, body.author, body.text)
    if not c:
        raise HTTPException(404, "case not found")
    return c


@app.patch("/api/cases/{case_id}", dependencies=[Depends(auth)])
def patch_case(case_id: str, body: CasePatch):
    c = cases.update(case_id, status=body.status, assignee=body.assignee)
    if not c:
        raise HTTPException(404, "case not found")
    return c


@app.get("/api/rules", dependencies=[Depends(auth)])
def rules():
    return pipeline.engine.catalog()


@app.get("/api/coverage", dependencies=[Depends(auth)])
def coverage():
    return attack.coverage(pipeline.engine.catalog())


@app.get("/api/playbooks", dependencies=[Depends(auth)])
def playbooks():
    return pipeline.playbooks.catalog()


@app.get("/api/runs", dependencies=[Depends(auth)])
def runs(status: str | None = None, limit: int = Query(50, ge=1, le=500)):
    where, args = ("WHERE status=?", (status,)) if status else ("", ())
    return db.list_("runs", limit, where, args)


@app.post("/api/runs/{run_id}/approve", dependencies=[Depends(auth)])
def approve(run_id: str, body: Decision):
    return _decide(run_id, body, True)


@app.post("/api/runs/{run_id}/deny", dependencies=[Depends(auth)])
def deny(run_id: str, body: Decision):
    return _decide(run_id, body, False)


def _decide(run_id: str, body: Decision, ok: bool):
    try:
        return pipeline.playbooks.decide(run_id, body.approver, ok, body.comment)
    except KeyError:
        raise HTTPException(404, "run not found")
    except PermissionError as exc:
        raise HTTPException(403, str(exc))
    except ValueError as exc:
        raise HTTPException(409, str(exc))


@app.get("/api/audit", dependencies=[Depends(auth)])
def audit_log(limit: int = Query(100, ge=1, le=1000)):
    return db.list_("audit", limit)


@app.get("/api/simulate", dependencies=[Depends(auth)])
def scenario_list():
    return list(simulate.scenarios())


@app.post("/api/simulate/{name}", dependencies=[Depends(auth)])
def simulate_scenario(name: str):
    try:
        return simulate.run(name)
    except KeyError as exc:
        raise HTTPException(404, str(exc.args[0]))


@app.get("/")
def console():
    return FileResponse(config.UI_DIR / "index.html")
