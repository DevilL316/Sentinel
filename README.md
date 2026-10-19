# Sentinel: a compact SIEM + SOAR prototype

Sentinel ingests logs, normalizes them to **OCSF**, detects threats with **Sigma** rules (including
Sigma 2.0 correlation), tags findings with **MITRE ATT&CK**, groups alerts into cases, and runs
**SOAR playbooks** with human approval gates and **AI-assisted triage**.

It is a working prototype for learning, demos and as a starting point. It is not a drop-in
replacement for a production SIEM (see "What this is not" below).

## Standards this build targets (checked October 2026)

| Standard | Version | What it means here |
|---|---|---|
| OCSF | 1.9.0 (released Aug 3, 2026) | Every event is stored as an OCSF event; alerts are exported as Detection Finding (class 2004). |
| MITRE ATT&CK | v19.x (v19.0 Apr 2026, v19.2 Aug 2026) | 15 Enterprise tactics. **Defense Evasion was retired and split into Stealth and Defense Impairment.** Rules still tagged `attack.defense-evasion` are flagged in the coverage view instead of silently ignored. |
| Sigma | Specification 2.0 | Rules, filters, and correlation types `event_count`, `value_count`, `temporal`, `temporal_ordered`. |

Rules use OCSF field paths (`process.cmd_line`, `src_endpoint.ip`) directly, so there is no
per-backend field-mapping layer. That is the practical benefit of normalizing first.

## Trends it reflects

- **Open schemas over proprietary formats** (OCSF) so detections and data move between tools.
- **Detection-as-code**: rules are versioned YAML with tests, filters and ATT&CK mapping.
- **Correlation over single-log alerts**, and **case grouping** so analysts see incidents.
- **SOAR as an execution layer with bounded autonomy**: playbooks do the mechanical work; anything
  disruptive (block, disable, isolate) waits for a named approver and is audited.
- **AI-assisted triage that recommends but never acts**, restricted to an action allowlist, with
  attacker-controlled log content treated as untrusted input to the model.

## Quick start

```bash
pip install -r requirements.txt
python -m pytest                              # 51 tests
uvicorn sentinel.app:app --port 8000          # console at http://localhost:8000
```

Open the console, go to **Overview**, run a scenario (for example *phishing to ransomware*), then
look at **Alerts**, **Cases**, **Approvals** (approve or deny the proposed containment) and
**Coverage** (ATT&CK heatmap). Or use the API:

```bash
curl -X POST localhost:8000/api/ingest -H 'content-type: application/json' -d '{
  "source": "syslog",
  "records": ["Oct 12 15:01:02 web01 sshd[9]: Failed password for root from 203.0.113.50 port 22 ssh2"]}'
```

Docker: `docker build -t sentinel . && docker run -p 8000:8000 sentinel`

Single-file Windows executable: see [`packaging/BUILD.md`](packaging/BUILD.md) (build locally with
`packaging\build-windows.ps1`, or let the GitHub Actions workflow build and release it).

## Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `SENTINEL_DB` | `./sentinel.db` | SQLite path (`:memory:` for tests) |
| `SENTINEL_API_KEY` | unset | If set, every `/api` call needs header `X-API-Key` |
| `ANTHROPIC_API_KEY` | unset | Enables LLM triage; otherwise a deterministic heuristic is used |
| `SENTINEL_TRIAGE_MODEL` | `claude-sonnet-5-5` | Model for triage |
| `SENTINEL_DRY_RUN` | `1` | Response actions are simulated. With `0`, actions that lack a connector refuse to run |
| `SENTINEL_RULES`, `SENTINEL_PLAYBOOKS` | `./rules`, `./playbooks` | Custom rule and playbook folders |

## Layout

```
sentinel/ocsf.py       parsers (syslog, Windows/Sysmon, JSON) -> OCSF events
sentinel/sigma.py      Sigma evaluator: modifiers, conditions, quantifiers
sentinel/detection.py  rule loading, filters, correlation windows, alert building
sentinel/attack.py     ATT&CK v19 tactics, technique catalog, coverage
sentinel/cases.py      case grouping, notes, timeline
sentinel/soar.py       playbook runner, actions, approval gates
sentinel/triage.py     LLM triage with offline heuristic fallback
sentinel/app.py        FastAPI service and console host
rules/*.yml            20 detections (16 rules + 4 correlations + 1 filter)
playbooks/*.yml        credential-attack and endpoint-containment playbooks
```

## Writing a rule

```yaml
title: Encoded PowerShell command
id: proc_encoded_powershell
level: high
tags: [attack.execution, attack.t1059.001]
logsource: {category: process_creation}
detection:
  image:   {process.name: [powershell.exe, pwsh.exe]}
  encoded: {process.cmd_line|contains: [' -enc ', ' -encodedcommand ']}
  condition: image and encoded
```

A correlation rule references other rules by `name`:

```yaml
correlation:
  type: value_count          # event_count | value_count | temporal | temporal_ordered
  rules: [auth_failure]
  group-by: [src_endpoint.ip]
  timespan: 10m
  condition: {field: user.name, gte: 4}
```

## Writing a playbook

Steps run in order. `when:` is data (`all`/`any`/`not` plus `path` with `equals`/`in`/`gte`/`lte`/`exists`),
not code. `requires_approval: true` pauses the run until an approver listed in `approvers` approves or
denies it. Params use `{{ alert.entities.src_ip }}`-style templates. Playbooks are validated at load, so
an unknown action fails fast.

## What this is not (read before production use)

- **Scale**: SQLite and in-process correlation windows handle thousands of events per second at best, and
  correlation state is lost on restart. Production needs a streaming pipeline and a columnar store
  (ClickHouse, a data lake) behind the same OCSF model.
- **Response actions are simulated.** Replace the bodies in `soar.ACTIONS` with connectors to your firewall,
  EDR, IdP and ticketing system. Keep the approval gates.
- **Auth is a shared API key.** Put it behind SSO, and map approvers to real identities and roles.
  Today the approver name is a string the caller supplies, which is fine for a demo and not for an audit.
- **Parsers cover a few sources.** Add parsers for your own (cloud audit logs, EDR, proxies) in `ocsf.py`.
- **ATT&CK catalog is a curated subset** (23 techniques). Load the official STIX bundle from
  `mitre-attack/attack-stix-data` to cover the whole matrix, and re-check technique-to-tactic placement
  against v19 transition guidance.
- **Sigma support is a subset** of the spec (no `fieldref`, `base64`/`windash` modifiers, or `temporal` with
  numeric thresholds). Use pySigma if you need full compatibility with the SigmaHQ rule corpus.
- **Threat intel is a stub** (two documentation IP ranges). Plug in your TI platform in `a_enrich_ip`.
