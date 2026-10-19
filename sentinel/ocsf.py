"""Parsers and OCSF normalization.

Every inbound record becomes an OCSF-shaped event (schema 1.9.0). Detection rules, correlation,
cases and playbooks all work on this one shape, which is the main point of adopting OCSF.
"""

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any

from . import config
from .db import new_id, now_ms

SEV = {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5, "fatal": 6}
SEV_NAME = {v: k.capitalize() for k, v in SEV.items()}

CLASSES = {
    0: ("Base Event", 0, "Uncategorized"),
    1007: ("Process Activity", 1, "System Activity"),
    3001: ("Account Change", 3, "Identity & Access Management"),
    3002: ("Authentication", 3, "Identity & Access Management"),
    4001: ("Network Activity", 4, "Network Activity"),
    4002: ("HTTP Activity", 4, "Network Activity"),
    4003: ("DNS Activity", 4, "Network Activity"),
    2004: ("Detection Finding", 2, "Findings"),
}


def _valid_ip(v: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(str(v)))
    except ValueError:
        return None


def _base(class_uid: int, activity_id: int, *, severity: int = 1, status_id: int = 1,
          time_ms: int | None = None, product: str = "unknown", raw: Any = None) -> dict:
    name, cat_uid, cat_name = CLASSES[class_uid]
    return {
        "id": new_id("evt"),
        "class_uid": class_uid,
        "class_name": name,
        "category_uid": cat_uid,
        "category_name": cat_name,
        "activity_id": activity_id,
        "type_uid": class_uid * 100 + activity_id,
        "severity_id": severity,
        "status_id": status_id,
        "time": time_ms or now_ms(),
        "metadata": {"version": config.OCSF_VERSION, "product": {"name": product}},
        "raw_data": raw if isinstance(raw, str) else None,
    }


# ----------------------------------------------------------------------------- syslog

_SYSLOG = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s[\d:]{8})\s(?P<host>\S+)\s(?P<proc>[\w\-/.]+)(?:\[(?P<pid>\d+)\])?:\s(?P<msg>.*)$"
)
_SSH_FAIL = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_SSH_OK = re.compile(r"Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_SUDO = re.compile(r"(?P<user>\S+)\s*: .*COMMAND=(?P<cmd>.*)$")
_USERADD = re.compile(r"new user: name=(?P<user>[^,]+)")


def _syslog_time(s: str) -> int:
    try:
        dt = datetime.strptime(f"{datetime.now().year} {' '.join(s.split())}", "%Y %b %d %H:%M:%S")
        return int(dt.replace(tzinfo=timezone.utc).timestamp() * 1000)
    except ValueError:
        return now_ms()


def parse_syslog(line: str) -> dict:
    m = _SYSLOG.match(line.strip())
    if not m:
        ev = _base(0, 99, raw=line, product="syslog")
        ev["unmapped"] = {"message": line}
        return ev
    host, proc, msg, t = m["host"], m["proc"], m["msg"], _syslog_time(m["ts"])
    if (f := _SSH_FAIL.search(msg)) or (f := _SSH_OK.search(msg)):
        failed = "Failed" in msg
        ev = _base(3002, 1, status_id=2 if failed else 1, severity=2 if failed else 1,
                   time_ms=t, product=proc, raw=line)
        ev["user"] = {"name": f["user"]}
        ev["src_endpoint"] = {"ip": _valid_ip(f["ip"]), "port": int(f["port"])}
        ev["dst_endpoint"] = {"hostname": host}
        ev["auth_protocol"] = "ssh"
        return ev
    if proc == "sudo" and (s := _SUDO.search(msg)):
        ev = _base(1007, 1, time_ms=t, product="sudo", raw=line)
        ev["actor"] = {"user": {"name": s["user"]}}
        ev["process"] = {"name": s["cmd"].split()[0] if s["cmd"].split() else "", "cmd_line": s["cmd"]}
        ev["device"] = {"hostname": host}
        return ev
    if (u := _USERADD.search(msg)):
        ev = _base(3001, 1, time_ms=t, product=proc, raw=line)
        ev["user"] = {"name": u["user"]}
        ev["device"] = {"hostname": host}
        return ev
    ev = _base(0, 99, time_ms=t, product=proc, raw=line)
    ev["device"] = {"hostname": host}
    ev["unmapped"] = {"message": msg}
    return ev


# ----------------------------------------------------------------------------- Windows / Sysmon

def parse_winevent(rec: dict) -> dict:
    eid = int(rec.get("EventID", 0))
    host = rec.get("Computer", "")
    t = now_ms()
    if eid in (4624, 4625):
        failed = eid == 4625
        ev = _base(3002, 1, status_id=2 if failed else 1, severity=2 if failed else 1,
                   time_ms=t, product="windows-security")
        ev["user"] = {"name": rec.get("TargetUserName", ""), "domain": rec.get("TargetDomainName", "")}
        ev["src_endpoint"] = {"ip": _valid_ip(rec.get("IpAddress")), "hostname": rec.get("WorkstationName")}
        ev["dst_endpoint"] = {"hostname": host}
        ev["logon_type_id"] = int(rec.get("LogonType", 0) or 0)
        return ev
    if eid in (4688, 1):  # process creation (Security 4688 / Sysmon 1)
        ev = _base(1007, 1, time_ms=t, product="windows-security" if eid == 4688 else "sysmon")
        image = rec.get("NewProcessName") or rec.get("Image", "")
        parent = rec.get("ParentProcessName") or rec.get("ParentImage", "")
        ev["process"] = {
            "name": image.replace("\\", "/").split("/")[-1].lower(),
            "file": {"path": image},
            "cmd_line": rec.get("CommandLine", ""),
            "parent_process": {"name": parent.replace("\\", "/").split("/")[-1].lower(), "file": {"path": parent}},
        }
        ev["actor"] = {"user": {"name": rec.get("SubjectUserName") or rec.get("User", "")}}
        ev["device"] = {"hostname": host}
        return ev
    if eid in (4720, 4732, 4728):
        ev = _base(3001, 1 if eid == 4720 else 7, time_ms=t, product="windows-security")
        ev["user"] = {"name": rec.get("TargetUserName", "")}
        ev["actor"] = {"user": {"name": rec.get("SubjectUserName", "")}}
        ev["group"] = {"name": rec.get("GroupName", "")} if rec.get("GroupName") else None
        ev["device"] = {"hostname": host}
        return ev
    if eid == 3:  # Sysmon network connect
        ev = _base(4001, 1, time_ms=t, product="sysmon")
        ev["src_endpoint"] = {"ip": _valid_ip(rec.get("SourceIp")), "hostname": host}
        ev["dst_endpoint"] = {"ip": _valid_ip(rec.get("DestinationIp")), "port": int(rec.get("DestinationPort", 0) or 0)}
        ev["process"] = {"name": (rec.get("Image", "").replace("\\", "/").split("/")[-1]).lower()}
        return ev
    ev = _base(0, 99, time_ms=t, product="windows")
    ev["device"] = {"hostname": host}
    ev["unmapped"] = {"event_id": eid, **{k: v for k, v in rec.items() if k not in ("EventID", "Computer")}}
    if eid == 1102:
        ev["unmapped"]["event"] = "audit_log_cleared"
        ev["actor"] = {"user": {"name": rec.get("SubjectUserName", "")}}
    return ev


# ----------------------------------------------------------------------------- generic JSON

def parse_json(rec: dict) -> dict:
    """Pass-through for records already in OCSF, otherwise a flat convention:
    {"type": "network|dns|http|auth|process", ...}"""
    if "class_uid" in rec and rec["class_uid"] in CLASSES:
        ev = _base(rec["class_uid"], rec.get("activity_id", 0), severity=rec.get("severity_id", 1),
                   status_id=rec.get("status_id", 1), time_ms=rec.get("time"), product="ocsf")
        ev.update({k: v for k, v in rec.items() if k not in ev})
        return ev
    kind = rec.get("type", "")
    t = rec.get("time")
    if kind == "network":
        ev = _base(4001, 6, time_ms=t, product=rec.get("product", "netflow"))
        ev["src_endpoint"] = {"ip": _valid_ip(rec.get("src_ip")), "port": rec.get("src_port")}
        ev["dst_endpoint"] = {"ip": _valid_ip(rec.get("dst_ip")), "port": rec.get("dst_port")}
        ev["traffic"] = {"bytes_out": rec.get("bytes_out", 0), "bytes_in": rec.get("bytes_in", 0)}
        ev["connection_info"] = {"protocol_name": rec.get("protocol", "tcp")}
        return ev
    if kind == "dns":
        ev = _base(4003, 1, time_ms=t, product=rec.get("product", "dns"))
        ev["src_endpoint"] = {"ip": _valid_ip(rec.get("src_ip"))}
        ev["query"] = {"hostname": rec.get("query", ""), "type": rec.get("qtype", "A")}
        return ev
    if kind == "http":
        ev = _base(4002, 1, time_ms=t, product=rec.get("product", "proxy"))
        ev["src_endpoint"] = {"ip": _valid_ip(rec.get("src_ip"))}
        ev["http_request"] = {"url": {"hostname": rec.get("host", ""), "path": rec.get("path", "")},
                              "http_method": rec.get("method", "GET"), "user_agent": rec.get("user_agent", "")}
        ev["http_response"] = {"code": rec.get("status", 200)}
        return ev
    if kind == "auth":
        failed = rec.get("outcome") == "failure"
        ev = _base(3002, 1, status_id=2 if failed else 1, severity=2 if failed else 1, time_ms=t,
                   product=rec.get("product", "idp"))
        ev["user"] = {"name": rec.get("user", "")}
        ev["src_endpoint"] = {"ip": _valid_ip(rec.get("src_ip")), "location": {"country": rec.get("country")}}
        ev["auth_protocol"] = rec.get("protocol", "")
        return ev
    ev = _base(0, 99, time_ms=t, product=rec.get("product", "json"))
    ev["unmapped"] = rec
    return ev


def normalize(source: str, raw: Any) -> dict:
    if source == "syslog":
        return parse_syslog(str(raw))
    if source == "winevent":
        return parse_winevent(raw)
    if source == "json":
        return parse_json(raw)
    raise ValueError(f"unknown source '{source}' (expected syslog, winevent or json)")


def detection_finding(alert: dict) -> dict:
    """Render an alert as an OCSF Detection Finding (class 2004) for export to a data lake or ticketing."""
    ev = _base(2004, 1, severity=alert["severity"], time_ms=alert["ts"], product="sentinel")
    ev["finding_info"] = {
        "uid": alert["id"],
        "title": alert["title"],
        "types": [alert["rule_id"]],
        "attacks": alert.get("attack", []),
    }
    ev["evidence"] = {"event_ids": alert.get("event_ids", [])}
    return ev
