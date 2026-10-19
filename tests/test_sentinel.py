import pytest
from fastapi.testclient import TestClient

from sentinel import attack, config, db, ocsf, pipeline, sigma, simulate, soar, triage
from sentinel.app import app


# ------------------------------------------------------------------ OCSF normalization
def test_ssh_failure_normalizes_to_authentication():
    ev = ocsf.normalize("syslog", "Oct 12 15:01:02 web01 sshd[9]: Failed password for invalid user bob from 203.0.113.5 port 22 ssh2")
    assert (ev["class_uid"], ev["status_id"], ev["type_uid"]) == (3002, 2, 300201)
    assert ev["src_endpoint"]["ip"] == "203.0.113.5" and ev["user"]["name"] == "bob"
    assert ev["metadata"]["version"] == config.OCSF_VERSION == "1.9.0"


def test_windows_process_event_lowercases_names_and_keeps_parent():
    ev = ocsf.normalize("winevent", {"EventID": 4688, "Computer": "H", "NewProcessName": r"C:\Windows\System32\CMD.EXE",
                                     "ParentProcessName": r"C:\Office\WINWORD.EXE", "CommandLine": "cmd /c whoami"})
    assert ev["class_uid"] == 1007 and ev["process"]["name"] == "cmd.exe"
    assert ev["process"]["parent_process"]["name"] == "winword.exe"


def test_invalid_ip_is_dropped_not_stored():
    ev = ocsf.normalize("json", {"type": "network", "src_ip": "not-an-ip", "dst_ip": "10.0.0.1"})
    assert ev["src_endpoint"]["ip"] is None


def test_unknown_source_rejected():
    with pytest.raises(ValueError):
        ocsf.normalize("carrier-pigeon", {})


# ------------------------------------------------------------------ Sigma evaluator
EV = {"process": {"name": "powershell.exe", "cmd_line": "powershell -enc AAA -nop"}, "dst_endpoint": {"ip": "8.8.8.8", "port": 53}}


@pytest.mark.parametrize("det,expected", [
    ({"s": {"process.name": "POWERSHELL.EXE"}, "condition": "s"}, True),                                  # case-insensitive
    ({"s": {"process.cmd_line|contains|all": ["-enc", "-nop"]}, "condition": "s"}, True),
    ({"s": {"process.cmd_line|contains|all": ["-enc", "-hidden"]}, "condition": "s"}, False),
    ({"s": {"process.cmd_line|startswith": "powershell"}, "condition": "s"}, True),
    ({"s": {"process.cmd_line|re": r"-enc\s+\w+"}, "condition": "s"}, True),
    ({"s": {"dst_endpoint.ip|cidr": "8.8.8.0/24"}, "condition": "s"}, True),
    ({"s": {"dst_endpoint.port|gte": 50}, "condition": "s"}, True),
    ({"s": {"dst_endpoint.port|gt": 53}, "condition": "s"}, False),
    ({"s": {"process.pid|exists": False}, "condition": "s"}, True),
    ({"a": {"process.name": "x"}, "b": {"dst_endpoint.port": 53}, "condition": "a or b"}, True),
    ({"a": {"process.name": "x"}, "b": {"dst_endpoint.port": 53}, "condition": "a and b"}, False),
    ({"a": {"process.name": "powershell.exe"}, "b": {"dst_endpoint.port": 80}, "condition": "a and not b"}, True),
    ({"sel_1": {"process.name": "powershell.exe"}, "sel_2": {"process.name": "x"}, "condition": "1 of sel_*"}, True),
    ({"sel_1": {"process.name": "powershell.exe"}, "sel_2": {"process.name": "x"}, "condition": "all of sel_*"}, False),
    ({"a": {"process.name": "powershell.exe"}, "b": {"dst_endpoint.port": 53}, "condition": "all of them"}, True),
    ({"a": {"process.name": "nope"}, "b": {"dst_endpoint.port": 1}, "condition": "(a or b) or not a"}, True),
    ({"kw": ["-enc"], "condition": "kw"}, True),                                                          # keyword search
])
def test_sigma_conditions(det, expected):
    assert sigma.evaluate(det, EV) is expected


def test_bad_condition_raises():
    with pytest.raises(ValueError):
        sigma.evaluate({"a": {"process.name": "x"}, "condition": "a and"}, EV)
    with pytest.raises(ValueError):
        sigma.evaluate({"a": {"process.name": "x"}, "condition": "missing"}, EV)


def test_timespan_parsing():
    assert sigma.parse_timespan("5m") == 300_000
    with pytest.raises(ValueError):
        sigma.parse_timespan("five minutes")


# ------------------------------------------------------------------ detection + correlation
def feed(source, recs):
    out = []
    for r in recs:
        for a in pipeline.engine.process(ocsf.normalize(source, r)):
            out.append(a["rule_id"])
    return out


def test_bruteforce_needs_five_failures():
    lines = [simulate._ssh("root", "203.0.113.50", i=i) for i in range(5)]
    assert feed("syslog", lines[:4]) == []
    assert feed("syslog", lines[4:]) == ["corr_bruteforce"]


def test_failures_from_different_sources_do_not_correlate():
    lines = [simulate._ssh("root", f"203.0.113.{i}", i=i) for i in range(1, 7)]
    assert feed("syslog", lines) == []


def test_spray_counts_distinct_users_not_events():
    same = [simulate._ssh("alice", "203.0.113.9", i=i) for i in range(3)]
    assert "corr_spray" not in feed("syslog", same)
    many = [simulate._ssh(u, "203.0.113.77", i=i) for i, u in enumerate(["a", "b", "c", "d"])]
    assert "corr_spray" in feed("syslog", many)


def test_ordered_correlation_requires_order():
    ok = [simulate._ssh("root", "203.0.113.5", ok=True)]
    assert "corr_guess_then_success" not in feed("syslog", ok + [simulate._ssh("root", "203.0.113.5")])
    pipeline.init()
    seq = [simulate._ssh("root", "203.0.113.5")] + ok
    assert "corr_guess_then_success" in feed("syslog", seq)


def test_base_rules_referenced_by_correlation_do_not_alert_alone():
    assert feed("syslog", [simulate._ssh("root", "203.0.113.5")]) == []


def test_filter_suppresses_known_account():
    rec = {"EventID": 4688, "Computer": "H", "NewProcessName": r"C:\p\powershell.exe", "CommandLine": "powershell.exe -enc AAA"}
    assert "proc_encoded_powershell" in feed("winevent", [{**rec, "SubjectUserName": "mallory"}])
    assert feed("winevent", [{**rec, "SubjectUserName": "svc_deploy"}]) == []


def test_private_destination_is_not_exfil():
    base = {"type": "network", "src_ip": "10.1.1.1", "dst_port": 443, "bytes_out": 500_000_000}
    assert feed("json", [{**base, "dst_ip": "10.9.9.9"}]) == []
    assert feed("json", [{**base, "dst_ip": "198.51.100.9"}]) == ["net_large_egress"]


def test_benign_traffic_is_quiet():
    assert simulate.run("benign_noise")["alerts"] == []


# ------------------------------------------------------------------ ATT&CK v19
def test_v19_has_fifteen_tactics_and_no_defense_evasion():
    assert len(attack.TACTICS) == 15
    assert "defense-evasion" not in attack.TACTICS
    assert "stealth" in attack.TACTICS and "defense-impairment" in attack.TACTICS


def test_legacy_tag_is_flagged_not_dropped():
    out = attack.resolve_tags(["attack.defense-evasion", "attack.t1218"])
    assert any(a.get("legacy") for a in out)
    assert any(a.get("technique", {}).get("uid") == "T1218" for a in out)
    assert "proc_rundll32_temp" in attack.coverage(pipeline.engine.catalog())["legacy_tagged_rules"]


# ------------------------------------------------------------------ cases
def test_related_alerts_share_one_case():
    simulate.run("bruteforce_then_compromise")
    cases = db.list_("cases")
    assert len(cases) == 1 and len(cases[0]["alerts"]) >= 2


def test_unrelated_alerts_get_separate_cases():
    simulate.run("bruteforce_then_compromise")
    simulate.run("exfil_and_dns_tunnel")
    assert len(db.list_("cases")) >= 2


# ------------------------------------------------------------------ SOAR
def run_creds():
    simulate.run("bruteforce_then_compromise")
    return db.list_("runs", 50, "WHERE status='awaiting_approval'")


def test_containment_waits_for_approval_and_changes_nothing_yet():
    assert run_creds()
    assert soar.FIREWALL == set()


def test_only_listed_approvers_can_approve():
    run = run_creds()[0]
    with pytest.raises(PermissionError):
        pipeline.playbooks.decide(run["id"], "intern", True)
    assert soar.FIREWALL == set()


def test_approval_executes_and_is_audited():
    awaiting = [r for r in run_creds() if r["steps"][r["cursor"]]["action"] == "block_ip"]
    run = pipeline.playbooks.decide(awaiting[0]["id"], "soc_lead", True, "confirmed")
    assert "203.0.113.50" in soar.FIREWALL
    block = next(s for s in run["steps"] if s["id"] == "block")
    assert block["status"] == "done" and block["decision"]["by"] == "soc_lead"
    assert any(a["action"] == "approval_granted" for a in db.list_("audit", 50))


def test_denial_skips_action_but_finishes_run():
    awaiting = [r for r in run_creds() if r["steps"][r["cursor"]]["action"] == "block_ip"]
    run = pipeline.playbooks.decide(awaiting[0]["id"], "soc_lead", False)
    assert soar.FIREWALL == set()
    assert run["status"] == "completed"
    assert any(s["status"] == "denied" for s in run["steps"])


def test_cannot_decide_twice():
    run = run_creds()[0]
    while run["status"] == "awaiting_approval":  # a playbook can have several gated steps
        run = pipeline.playbooks.decide(run["id"], "soc_lead", False)
    assert run["status"] == "completed"
    with pytest.raises(ValueError):
        pipeline.playbooks.decide(run["id"], "soc_lead", True)


def test_never_blocks_internal_or_invalid_addresses():
    for ip in ("10.0.0.5", "192.168.1.1", "127.0.0.1", "", "garbage"):
        assert soar.a_block_ip({"ip": ip}, {})["blocked"] is False
    assert soar.FIREWALL == set()
    assert soar.a_block_ip({"ip": "203.0.113.5"}, {})["blocked"] is True


def test_live_mode_refuses_unconfigured_actions(monkeypatch):
    monkeypatch.setattr(config, "SOAR_DRY_RUN", False)
    with pytest.raises(RuntimeError):
        soar.a_block_ip({"ip": "203.0.113.5"}, {})


def test_template_rendering_and_conditions():
    ctx = {"alert": {"entities": {"src_ip": "1.2.3.4"}, "severity": 5}}
    assert soar.render("{{ alert.entities.src_ip }}", ctx) == "1.2.3.4"
    assert soar.render("ip={{ alert.entities.src_ip }}", ctx) == "ip=1.2.3.4"
    assert soar.render("{{ alert.nothing }}", ctx) is None
    assert soar.check({"any": [{"path": "alert.severity", "gte": 6}, {"path": "alert.severity", "equals": 5}]}, ctx)
    assert not soar.check({"not": {"path": "alert.severity", "gte": 5}}, ctx)


def test_playbook_validation_rejects_unknown_action(tmp_path):
    (tmp_path / "bad.yml").write_text("id: x\nname: x\ntrigger: {}\nsteps:\n  - {id: a, action: rm_rf_everything}\n")
    with pytest.raises(ValueError):
        soar.Playbooks(tmp_path)


# ------------------------------------------------------------------ triage
ALERT = {"title": "t", "level": "critical", "severity": 5, "kind": "correlation", "event_count": 6,
         "entities": {"src_ip": "203.0.113.50", "user": "root"},
         "attack": [{"technique": {"uid": "T1110", "name": "Brute Force"}, "tactics": [{"name": "credential-access"}]}]}


def test_heuristic_triage_shape_and_allowlist():
    r = triage.heuristic(ALERT, {"ip": "203.0.113.50", "reputation": "malicious"})
    assert r["verdict"] == "true_positive_likely" and 0 <= r["confidence"] <= 1
    assert set(r["recommended_actions"]) <= set(triage.ALLOWED_ACTIONS)


def test_llm_failure_falls_back_to_heuristic(monkeypatch):
    monkeypatch.setattr(config, "ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setattr(triage, "_llm", lambda *a: (_ for _ in ()).throw(RuntimeError("network down")))
    assert triage.analyze(ALERT)["source"] == "heuristic"


def test_llm_output_cannot_smuggle_unknown_actions(monkeypatch):
    class R:
        def raise_for_status(self): pass
        def json(self): return {"content": [{"text": '{"verdict":"needs_investigation","confidence":2,'
                                                      '"summary":"x","reasoning":["y"],"recommended_actions":["block_ip","format_disk"]}'}]}
    monkeypatch.setattr(config, "ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setattr(triage.httpx, "post", lambda *a, **k: R())
    r = triage.analyze(ALERT)
    assert r["recommended_actions"] == ["block_ip"] and r["confidence"] == 1.0


# ------------------------------------------------------------------ API
def test_api_end_to_end_and_validation():
    with TestClient(app) as c:
        assert c.post("/api/ingest", json={"source": "bogus", "records": []}).status_code == 422
        r = c.post("/api/ingest", json={"source": "syslog", "records": [simulate._ssh("root", "203.0.113.50", i=i) for i in range(5)]})
        assert r.status_code == 200 and len(r.json()["alerts"]) == 1
        aid = r.json()["alerts"][0]
        assert len(c.get(f"/api/alerts/{aid}").json()["events"]) == 5
        assert c.get("/api/alerts/nope").status_code == 404
        assert c.post("/api/simulate/nope").status_code == 404
        assert c.get("/").status_code == 200


def test_api_key_enforced(monkeypatch):
    monkeypatch.setattr(config, "API_KEY", "s3cret")
    with TestClient(app) as c:
        assert c.get("/api/meta").status_code == 401
        assert c.get("/api/meta", headers={"x-api-key": "wrong"}).status_code == 401
        assert c.get("/api/meta", headers={"x-api-key": "s3cret"}).status_code == 200


def test_malformed_record_is_rejected_without_aborting_batch():
    r = pipeline.ingest("winevent", [{"EventID": "abc"}, {"EventID": 4720, "TargetUserName": "u", "SubjectUserName": "a"}])
    assert r["stored"] == 1 and len(r["rejected"]) == 1


def test_case_keeps_highest_priority_triage():
    simulate.run("phishing_to_ransomware")
    case = db.list_("cases")[0]
    top = max(db.get("alerts", i)["severity"] for i in case["alerts"])
    assert top == 5 and case["triage"]["verdict"] == "true_positive_likely"
    cases_mod = __import__("sentinel.cases", fromlist=["x"])
    cases_mod.set_triage(case["id"], {"priority_score": 1, "verdict": "likely_benign"})
    assert db.get("cases", case["id"])["triage"]["verdict"] == "true_positive_likely"


# ------------------------------------------------------------------ launcher (Sentinel.exe entry point)
from sentinel import launcher  # noqa: E402


def test_parse_env_handles_comments_quotes_bom_and_crlf():
    text = "\ufeff# comment\r\nSENTINEL_API_KEY=abc123\r\nSENTINEL_PORT = 9000\r\nNAME=\"quoted value\"\r\nbadline\r\n\r\nPATH=C:\\x\\y\r\n"
    assert launcher.parse_env(text) == {"SENTINEL_API_KEY": "abc123", "SENTINEL_PORT": "9000",
                                        "NAME": "quoted value", "PATH": "C:\\x\\y"}


def test_first_run_generates_key_and_second_run_keeps_it(tmp_path):
    s1, created1 = launcher.ensure_config(tmp_path)
    s2, created2 = launcher.ensure_config(tmp_path)
    assert created1 and not created2
    assert len(s1["SENTINEL_API_KEY"]) >= 24 and s1 == s2
    assert s1["SENTINEL_HOST"] == "127.0.0.1"          # loopback by default, never exposed implicitly
    assert (tmp_path / "sentinel.env").exists()


def test_two_installs_get_different_keys(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir(); b.mkdir()
    assert launcher.ensure_config(a)[0]["SENTINEL_API_KEY"] != launcher.ensure_config(b)[0]["SENTINEL_API_KEY"]


def test_real_environment_overrides_file(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_PORT", "9999")
    monkeypatch.delenv("SENTINEL_DB", raising=False)
    bind = launcher.apply_settings(tmp_path, {"SENTINEL_PORT": "8000", "SENTINEL_HOST": "127.0.0.1"})
    assert bind["port"] == "9999"
    assert (tmp_path / "data").is_dir()
    assert launcher.os.environ["SENTINEL_DB"].endswith("sentinel.db")


def test_startup_task_runs_as_system_at_boot_with_quoted_path():
    args = launcher.schtasks_create_args(r"C:\Program Files\Sentinel\Sentinel.exe")
    assert args[args.index("/SC") + 1] == "ONSTART" and args[args.index("/RU") + 1] == "SYSTEM"
    assert args[args.index("/TR") + 1] == r'"C:\Program Files\Sentinel\Sentinel.exe" run --service'


def test_show_key_without_settings_file_fails_cleanly(tmp_path, capsys):
    assert launcher.cmd_show_key(tmp_path) == 1


def test_frozen_home_is_the_exe_folder(monkeypatch, tmp_path):
    monkeypatch.delenv("SENTINEL_HOME", raising=False)
    monkeypatch.setattr(launcher, "FROZEN", True)
    monkeypatch.setattr(launcher.sys, "executable", str(tmp_path / "Sentinel.exe"))
    assert launcher.home_dir() == tmp_path.resolve()
    assert launcher.own_exe() == str(tmp_path / "Sentinel.exe")
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "other"))        # explicit override still wins
    assert launcher.home_dir() == tmp_path / "other"


def test_frozen_seeds_rules_once_and_never_overwrites_user_edits(monkeypatch, tmp_path):
    monkeypatch.setattr(launcher, "FROZEN", True)
    monkeypatch.delenv("SENTINEL_RULES", raising=False)
    monkeypatch.delenv("SENTINEL_PLAYBOOKS", raising=False)
    try:
        launcher.seed_editable_content(tmp_path)
        assert list((tmp_path / "rules").glob("*.yml")) and list((tmp_path / "playbooks").glob("*.yml"))
        assert launcher.os.environ["SENTINEL_RULES"] == str(tmp_path / "rules")
        mine = tmp_path / "rules" / "auth.yml"
        mine.write_text("# my edit\n")
        launcher.seed_editable_content(tmp_path)
        assert mine.read_text() == "# my edit\n"
    finally:  # the function sets real env vars; do not leak them into other tests
        launcher.os.environ.pop("SENTINEL_RULES", None)
        launcher.os.environ.pop("SENTINEL_PLAYBOOKS", None)


def test_not_frozen_leaves_rule_paths_alone(monkeypatch, tmp_path):
    monkeypatch.setattr(launcher, "FROZEN", False)
    monkeypatch.delenv("SENTINEL_RULES", raising=False)
    launcher.seed_editable_content(tmp_path)
    assert "SENTINEL_RULES" not in launcher.os.environ and not (tmp_path / "rules").exists()
