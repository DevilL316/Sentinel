"""Detection engine: Sigma rules, Sigma 2.0 correlation rules, filters, ATT&CK enrichment."""

import logging
from collections import defaultdict, deque
from pathlib import Path

import yaml

from . import attack, config
from .db import new_id, now_ms
from .ocsf import SEV
from .sigma import evaluate, get_values, logsource_matches, parse_timespan

log = logging.getLogger("sentinel.detection")


def _entities(ev: dict) -> dict:
    def first(path: str):
        v = get_values(ev, path)
        return v[0] if v else None

    return {k: v for k, v in {
        "src_ip": first("src_endpoint.ip"),
        "user": first("user.name") or first("actor.user.name"),
        "host": first("device.hostname") or first("dst_endpoint.hostname") or first("src_endpoint.hostname"),
        "dst_ip": first("dst_endpoint.ip"),
        "process": first("process.name"),
        "cmd_line": first("process.cmd_line"),
    }.items() if v}


class Engine:
    def __init__(self, rules_dir: Path | None = None):
        self.rules: dict[str, dict] = {}        # detection rules by id
        self.correlations: dict[str, dict] = {}
        self.filters: list[dict] = []
        self._windows: dict[tuple, deque] = defaultdict(deque)
        self.load(rules_dir or config.RULES_DIR)

    # ------------------------------------------------------------------ loading
    def load(self, rules_dir: Path) -> None:
        self.rules.clear(); self.correlations.clear(); self.filters.clear(); self._windows.clear()
        for path in sorted(Path(rules_dir).glob("*.y*ml")):
            for doc in yaml.safe_load_all(path.read_text()):
                if not doc:
                    continue
                try:
                    self._register(doc, path.name)
                except Exception as exc:  # a bad rule must not take the engine down
                    log.error("skipping rule in %s: %s", path.name, exc)

    def _register(self, doc: dict, source: str) -> None:
        if "filter" in doc:
            self.filters.append(doc["filter"])
            return
        rid = doc.get("id") or doc.get("name")
        if not rid or "title" not in doc:
            raise ValueError("rule needs 'id' and 'title'")
        rule = {
            "id": rid, "name": doc.get("name", rid), "title": doc["title"],
            "description": doc.get("description", ""), "level": doc.get("level", "medium"),
            "severity": SEV.get(doc.get("level", "medium"), 3), "tags": doc.get("tags", []),
            "attack": attack.resolve_tags(doc.get("tags", [])), "source": source,
            "status": doc.get("status", "experimental"),
        }
        if "correlation" in doc:
            c = doc["correlation"]
            if c["type"] not in ("event_count", "value_count", "temporal", "temporal_ordered"):
                raise ValueError(f"unsupported correlation type {c['type']}")
            rule.update(kind="correlation", correlation=c, timespan=parse_timespan(c["timespan"]),
                        generate=bool(c.get("generate", False)))
            self.correlations[rid] = rule
        else:
            if "detection" not in doc:
                raise ValueError("rule needs 'detection'")
            rule.update(kind="rule", detection=doc["detection"], logsource=doc.get("logsource"))
            self.rules[rid] = rule

    def catalog(self) -> list[dict]:
        out = []
        for r in [*self.rules.values(), *self.correlations.values()]:
            out.append({k: r[k] for k in ("id", "title", "description", "level", "severity", "tags",
                                          "attack", "kind", "status", "source")})
        return out

    # ------------------------------------------------------------------ matching
    def _filtered(self, rule: dict, ev: dict) -> bool:
        for f in self.filters:
            targets = f.get("rules", [])
            if targets and rule["id"] not in targets and rule["name"] not in targets:
                continue
            body = {k: v for k, v in f.items() if k != "rules"}
            if evaluate(body, ev):
                return True
        return False

    def _suppressed_base(self) -> set[str]:
        """Base rules referenced by a correlation with generate:false do not alert on their own."""
        hidden = set()
        for c in self.correlations.values():
            if not c["generate"]:
                hidden.update(c["correlation"]["rules"])
        return hidden

    def process(self, ev: dict) -> list[dict]:
        alerts: list[dict] = []
        hidden = self._suppressed_base()
        matched: list[dict] = []
        for rule in self.rules.values():
            if not logsource_matches(rule["logsource"], ev):
                continue
            try:
                if evaluate(rule["detection"], ev) and not self._filtered(rule, ev):
                    matched.append(rule)
            except Exception as exc:
                log.error("rule %s failed: %s", rule["id"], exc)
        for rule in matched:
            if rule["id"] not in hidden and rule["name"] not in hidden:
                alerts.append(self._alert(rule, [ev]))
        alerts.extend(self._correlate(matched, ev))
        return alerts

    # ------------------------------------------------------------------ correlation
    def _correlate(self, matched: list[dict], ev: dict) -> list[dict]:
        out = []
        for crule in self.correlations.values():
            c = crule["correlation"]
            refs = set(c["rules"])
            hits = [m for m in matched if m["id"] in refs or m["name"] in refs]
            if not hits:
                continue
            group = tuple(str((get_values(ev, g) or [None])[0]) for g in c.get("group-by", []))
            win = self._windows[(crule["id"], group)]
            t = ev["time"]
            for m in hits:
                value = None
                if c["type"] == "value_count":
                    fld = c["condition"]["field"]
                    value = (get_values(ev, fld) or [None])[0]
                win.append((t, m["id"], value, ev["id"], ev))
            while win and win[0][0] < t - crule["timespan"]:
                win.popleft()
            if self._triggered(c, win, refs):
                evs = [w[4] for w in win]
                out.append(self._alert(crule, evs, group_by=dict(zip(c.get("group-by", []), group))))
                win.clear()  # suppress until the pattern builds again
        return out

    def _triggered(self, c: dict, win: deque, refs: set) -> bool:
        cond = c.get("condition", {})
        typ = c["type"]
        if typ == "event_count":
            return self._cmp(len(win), cond)
        if typ == "value_count":
            return self._cmp(len({w[2] for w in win if w[2] is not None}), cond)
        names = [w[1] for w in win]
        wanted = c["rules"]
        id_to_name = {r["id"]: r["name"] for r in self.rules.values()}
        seen = {n for n in names} | {id_to_name.get(n, n) for n in names}
        if not all(r in seen or r in names for r in wanted):
            return False
        if typ == "temporal":
            return True
        pos = -1  # temporal_ordered: rules must first-occur in listed order
        for r in wanted:
            idx = next((i for i, n in enumerate(names) if n == r or id_to_name.get(n) == r), None)
            if idx is None or idx < pos:
                return False
            pos = idx
        return True

    @staticmethod
    def _cmp(n: int, cond: dict) -> bool:
        return all(op(n, cond[k]) for k, op in (("gte", lambda a, b: a >= b), ("gt", lambda a, b: a > b),
                                                ("lte", lambda a, b: a <= b), ("lt", lambda a, b: a < b),
                                                ("eq", lambda a, b: a == b)) if k in cond)

    # ------------------------------------------------------------------ alert construction
    def _alert(self, rule: dict, events: list[dict], group_by: dict | None = None) -> dict:
        ent: dict = {}
        for e in events:
            for k, v in _entities(e).items():
                ent.setdefault(k, v)
        return {
            "id": new_id("alr"), "ts": now_ms(), "rule_id": rule["id"], "title": rule["title"],
            "description": rule["description"], "severity": rule["severity"], "level": rule["level"],
            "status": "open", "kind": rule["kind"], "attack": rule["attack"], "tags": rule["tags"],
            "entities": ent, "group_by": group_by or {}, "event_ids": [e["id"] for e in events][-20:],
            "event_count": len(events), "case_id": None,
        }
