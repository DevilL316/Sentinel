"""Smoke test for a built Sentinel executable. Run by build.py and by CI; exits non-zero on any failure.

It starts the real binary twice against a throwaway home folder and checks, over HTTP, that:
  run 1: console loads, API is locked without the key, rules/correlations/playbooks loaded, a scenario raises
         alerts, cases are created, and editable rules/playbooks were copied next to the exe
  run 2: the same API key and the database survived the restart, and a rule the user added to the rules
         folder is picked up and fires (i.e. the exe really reads external, editable rules)

Usage: python packaging/smoke_test.py path/to/Sentinel[.exe]
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

CUSTOM_RULE = """title: Smoke test custom rule
id: smoke_custom
name: smoke_custom
description: Added by the smoke test to prove external rules are loaded.
level: high
tags: [attack.command-and-control, attack.t1071.004]
logsource: {category: dns}
detection:
  selection:
    query.hostname: smoke-test.invalid
  condition: selection
"""

results: list[tuple[bool, str]] = []


def check(ok: bool, name: str, detail: str = "") -> None:
    results.append((ok, name))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({detail})" if detail and not ok else ""), flush=True)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def http(method: str, url: str, key: str | None = None, body=None) -> tuple[int, bytes]:
    req = urllib.request.Request(url, method=method, data=None if body is None else json.dumps(body).encode())
    req.add_header("content-type", "application/json")
    if key is not None:
        req.add_header("x-api-key", key)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except (urllib.error.URLError, ConnectionError, TimeoutError):
        return 0, b""


def jget(url: str, key: str):
    status, data = http("GET", url, key)
    return json.loads(data) if status == 200 else None


class Server:
    def __init__(self, exe: Path, home: Path, log: Path, extra: tuple[str, ...] = ()):
        self.exe, self.home, self.log, self.port = exe, home, log, free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        env = {k: v for k, v in os.environ.items() if not k.startswith("SENTINEL_") and k != "ANTHROPIC_API_KEY"}
        env["SENTINEL_HOME"] = str(home)
        self.out = open(log, "wb")
        self.proc = subprocess.Popen([str(exe), "run", "--no-browser", "--port", str(self.port), *extra],
                                     env=env, stdout=self.out, stderr=subprocess.STDOUT)

    def wait_ready(self, timeout: int = 120) -> bool:
        end = time.time() + timeout  # single-file exes unpack themselves first, and antivirus can slow that
        while time.time() < end:
            if self.proc.poll() is not None:
                return False
            if http("GET", self.base + "/")[0] == 200:
                return True
            time.sleep(0.5)
        return False

    def stop(self) -> None:
        if self.proc.poll() is None:
            if os.name == "nt":  # a single-file exe is a launcher plus a child; end the whole tree
                subprocess.run(["taskkill", "/PID", str(self.proc.pid), "/T", "/F"], capture_output=True)
            else:
                self.proc.terminate()
            try:
                self.proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.out.close()

    def tail(self, n: int = 40) -> str:
        return "\n".join(self.log.read_text(errors="replace").splitlines()[-n:])


def read_key(home: Path) -> str:
    for line in (home / "sentinel.env").read_text(encoding="utf-8").splitlines():
        if line.startswith("SENTINEL_API_KEY="):
            return line.split("=", 1)[1].strip()
    return ""


def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print(__doc__)
        return 2
    exe = Path(sys.argv[1]).resolve()
    work = Path(tempfile.mkdtemp(prefix="sentinel-smoke-"))
    home = work / "home"
    home.mkdir()
    base_rules = 0
    events_run1 = 0
    key1 = ""

    print(f"Run 1: first start of {exe.name} (fresh folder)", flush=True)
    srv = Server(exe, home, work / "run1.log")
    try:
        if not srv.wait_ready():
            check(False, "server starts and serves the console", "did not become ready")
            print(srv.tail())
            return 1
        check(True, "server starts and serves the console")
        key1 = read_key(home)
        check(len(key1) >= 24, "random API key generated on first run")
        check(http("GET", srv.base + "/api/meta")[0] == 401, "API refuses requests without the key")
        check(http("GET", srv.base + "/api/meta", "wrong")[0] == 401, "API refuses a wrong key")
        meta = jget(srv.base + "/api/meta", key1) or {}
        base_rules = meta.get("rules", 0)
        check(meta.get("rules", 0) >= 16 and meta.get("correlations", 0) >= 4, "detection rules loaded",
              json.dumps(meta))
        check(meta.get("playbooks", 0) >= 2, "playbooks loaded")
        check(meta.get("ocsf") == "1.9.0" and str(meta.get("attack", "")).startswith("v19"),
              "standards versions reported", json.dumps(meta))
        status, body = http("POST", srv.base + "/api/simulate/phishing_to_ransomware", key1)
        sim = json.loads(body) if status == 200 else {}
        check(status == 200 and len(sim.get("alerts", [])) >= 3, "attack scenario raises alerts", body[:200].decode(errors="replace"))
        check(len(jget(srv.base + "/api/cases", key1) or []) >= 1, "case created from alerts")
        check(bool(jget(srv.base + "/api/coverage", key1)), "ATT&CK coverage endpoint works")
        events_run1 = (jget(srv.base + "/api/meta", key1) or {}).get("counts", {}).get("events", 0)
        check((home / "rules").is_dir() and any((home / "rules").glob("*.yml")), "editable rules copied next to the exe")
        check((home / "playbooks").is_dir() and any((home / "playbooks").glob("*.yml")), "editable playbooks copied next to the exe")
        check((home / "data" / "sentinel.db").is_file(), "database created in the data folder")
    finally:
        srv.stop()

    print("Run 2: restart in unattended --service mode with a user-added rule", flush=True)
    (home / "rules" / "zz_smoke.yml").write_text(CUSTOM_RULE, encoding="utf-8")
    srv = Server(exe, home, work / "run2.log", extra=("--service",))
    try:
        if not srv.wait_ready():
            check(False, "server restarts", "did not become ready")
            print(srv.tail())
            return 1
        check(True, "server restarts")
        check(read_key(home) == key1 and http("GET", srv.base + "/api/meta", key1)[0] == 200, "same API key after restart")
        meta = jget(srv.base + "/api/meta", key1) or {}
        check(meta.get("rules", 0) == base_rules + 1, "user-added rule is loaded", json.dumps(meta))
        check(meta.get("counts", {}).get("events", 0) >= events_run1 > 0, "database survived the restart")
        http("POST", srv.base + "/api/ingest", key1,
             {"source": "json", "records": [{"type": "dns", "src_ip": "10.1.1.1", "query": "smoke-test.invalid"}]})
        alerts = jget(srv.base + "/api/alerts", key1) or []
        check(any(a.get("rule_id") == "smoke_custom" for a in alerts), "user-added rule fires on matching data")
        check((home / "rules" / "zz_smoke.yml").exists() and
              any(p.name != "zz_smoke.yml" for p in (home / "rules").glob("*.yml")), "user edits not overwritten on restart")
        log_file = home / "data" / "sentinel.log"  # the startup task runs with --service; it must log to a file
        check(log_file.is_file() and log_file.stat().st_size > 0, "--service mode writes data/sentinel.log")
    finally:
        srv.stop()

    failed = [n for ok, n in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    if failed:
        print("FAILED:", "; ".join(failed))
        print("--- last server output ---")
        print(srv.tail())
        print(f"Test folder kept for inspection: {work}")
        return 1
    shutil.rmtree(work, ignore_errors=True)  # may be partly locked on Windows; harmless if it is
    return 0


if __name__ == "__main__":
    sys.exit(main())
