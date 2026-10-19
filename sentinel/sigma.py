"""Evaluator for the Sigma rule format (spec 2.0 subset), run natively against OCSF events.

Supported: selections (maps, lists of maps, keyword lists), value modifiers
(contains, startswith, endswith, re, all, cidr, gt/gte/lt/lte, exists), boolean conditions with
`not`, parentheses and `1 of` / `all of` quantifiers (with wildcards and `them`), and filters.
Correlation rules (event_count, value_count, temporal, temporal_ordered) live in detection.py.

Field names are OCSF paths (e.g. `process.cmd_line`), so no per-backend field-mapping pipeline
is needed. That is the practical payoff of normalizing to OCSF first.
"""

import fnmatch
import ipaddress
import re
from typing import Any


def get_values(event: dict, path: str) -> list[Any]:
    """Resolve a dotted path; lists are traversed so any element can match."""
    cur: list[Any] = [event]
    for part in path.split("."):
        nxt: list[Any] = []
        for item in cur:
            if isinstance(item, dict) and part in item:
                nxt.append(item[part])
            elif isinstance(item, list):
                nxt.extend(i[part] for i in item if isinstance(i, dict) and part in i)
        cur = [x for v in nxt for x in (v if isinstance(v, list) else [v])]
        if not cur:
            return []
    return cur


def _str(v: Any) -> str:
    return str(v).lower()


def _match_one(value: Any, pattern: Any, mods: list[str]) -> bool:
    if "re" in mods:
        return re.search(str(pattern), str(value), re.IGNORECASE) is not None
    if "cidr" in mods:
        try:
            return ipaddress.ip_address(str(value)) in ipaddress.ip_network(str(pattern), strict=False)
        except ValueError:
            return False
    for op, fn in (("gte", lambda a, b: a >= b), ("gt", lambda a, b: a > b),
                   ("lte", lambda a, b: a <= b), ("lt", lambda a, b: a < b)):
        if op in mods:
            try:
                return fn(float(value), float(pattern))
            except (TypeError, ValueError):
                return False
    if isinstance(pattern, (int, float)) and not isinstance(pattern, bool) and isinstance(value, (int, float)):
        return value == pattern
    v, p = _str(value), _str(pattern)
    if "contains" in mods:
        return p in v
    if "startswith" in mods:
        return v.startswith(p)
    if "endswith" in mods:
        return v.endswith(p)
    if "*" in p or "?" in p:
        return fnmatch.fnmatchcase(v, p)
    return v == p


def _match_field(event: dict, key: str, expected: Any) -> bool:
    path, *mods = key.split("|")
    values = get_values(event, path)
    if "exists" in mods:
        return bool(values) == bool(expected)
    if expected is None:
        return not values
    pats = expected if isinstance(expected, list) else [expected]
    if "all" in mods:
        return all(any(_match_one(v, p, mods) for v in values) for p in pats)
    return any(_match_one(v, p, mods) for v in values for p in pats)


def _match_selection(event: dict, sel: Any) -> bool:
    if isinstance(sel, dict):
        return all(_match_field(event, k, v) for k, v in sel.items())
    if isinstance(sel, list):
        if all(isinstance(i, dict) for i in sel):
            return any(_match_selection(event, i) for i in sel)
        text = " ".join(_str(x) for x in _flatten_values(event))  # keyword search
        return any(_str(k) in text for k in sel)
    return False


def _flatten_values(obj: Any) -> list[Any]:
    if isinstance(obj, dict):
        return [x for v in obj.values() for x in _flatten_values(v)]
    if isinstance(obj, list):
        return [x for v in obj for x in _flatten_values(v)]
    return [obj]


# ----------------------------------------------------------------------------- condition parser

_TOKEN = re.compile(r"\(|\)|[^\s()]+")


class _Cond:
    def __init__(self, text: str, names: list[str], results: dict[str, bool]):
        self.toks = _TOKEN.findall(text)
        self.i = 0
        self.names = names
        self.results = results

    def peek(self) -> str | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def eat(self) -> str:
        t = self.toks[self.i]
        self.i += 1
        return t

    def parse(self) -> bool:
        v = self.or_()
        if self.peek() is not None:
            raise ValueError(f"unexpected token '{self.peek()}' in condition")
        return v

    def or_(self) -> bool:
        v = self.and_()
        while (self.peek() or "").lower() == "or":
            self.eat()
            r = self.and_()
            v = v or r
        return v

    def and_(self) -> bool:
        v = self.not_()
        while (self.peek() or "").lower() == "and":
            self.eat()
            r = self.not_()
            v = v and r
        return v

    def not_(self) -> bool:
        if (self.peek() or "").lower() == "not":
            self.eat()
            return not self.not_()
        return self.atom()

    def atom(self) -> bool:
        t = self.peek()
        if t is None:
            raise ValueError("unexpected end of condition")
        if t == "(":
            self.eat()
            v = self.or_()
            if self.peek() != ")":
                raise ValueError("missing ')'")
            self.eat()
            return v
        if (t.lower() == "1" or t.lower() == "all") and self.i + 1 < len(self.toks) and self.toks[self.i + 1].lower() == "of":
            quant = self.eat().lower()
            self.eat()
            target = self.eat()
            names = self.names if target.lower() == "them" else fnmatch.filter(self.names, target)
            vals = [self.results[n] for n in names]
            return (any(vals) if quant == "1" else (all(vals) and bool(vals)))
        self.eat()
        if t not in self.results:
            raise ValueError(f"condition references unknown selection '{t}'")
        return self.results[t]


def evaluate(detection: dict, event: dict) -> bool:
    """Evaluate a Sigma `detection:` block against one OCSF event."""
    names = [k for k in detection if k not in ("condition", "timeframe")]
    results = {n: _match_selection(event, detection[n]) for n in names}
    cond = detection["condition"]
    if isinstance(cond, list):
        return any(_Cond(c, names, results).parse() for c in cond)
    return _Cond(cond, names, results).parse()


# logsource.category -> OCSF class_uid
CATEGORY_CLASS = {
    "process_creation": 1007,
    "authentication": 3002,
    "network_connection": 4001,
    "dns": 4003,
    "proxy": 4002,
    "account_change": 3001,
}


def logsource_matches(logsource: dict | None, event: dict) -> bool:
    if not logsource:
        return True
    cls = CATEGORY_CLASS.get(logsource.get("category", ""))
    return cls is None or event.get("class_uid") == cls


_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_timespan(s: str) -> int:
    """'5m' -> milliseconds."""
    m = re.fullmatch(r"(\d+)([smhd])", str(s).strip())
    if not m:
        raise ValueError(f"bad timespan '{s}' (use e.g. 30s, 5m, 1h, 1d)")
    return int(m[1]) * _UNITS[m[2]] * 1000
