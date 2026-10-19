"""MITRE ATT&CK catalog (bundled subset) and Sigma-tag resolution.

Targets ATT&CK v19.x. v19 retired the Defense Evasion tactic (TA0005) and replaced it with two
tactics, Stealth and Defense Impairment, so Enterprise now has 15 tactics. Sigma rules in the wild
still carry the legacy `attack.defense-evasion` tag; those resolve to a flagged "legacy" tactic
so detection engineers can re-map them rather than silently losing coverage.

This is a curated subset for the prototype. To cover the full matrix, load the enterprise-attack
STIX bundle from github.com/mitre-attack/attack-stix-data and populate TECHNIQUES from it.
"""

TACTICS = [
    "reconnaissance", "resource-development", "initial-access", "execution", "persistence",
    "privilege-escalation", "stealth", "defense-impairment", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control", "exfiltration", "impact",
]

LEGACY_TACTICS = {"defense-evasion": "defense-evasion (retired in v19: re-map to stealth or defense-impairment)"}

# id -> (name, tactics)
TECHNIQUES: dict[str, tuple[str, list[str]]] = {
    "T1078": ("Valid Accounts", ["initial-access", "persistence", "privilege-escalation"]),
    "T1110": ("Brute Force", ["credential-access"]),
    "T1110.001": ("Brute Force: Password Guessing", ["credential-access"]),
    "T1110.003": ("Brute Force: Password Spraying", ["credential-access"]),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", ["execution"]),
    "T1059.004": ("Command and Scripting Interpreter: Unix Shell", ["execution"]),
    "T1204": ("User Execution", ["execution"]),
    "T1190": ("Exploit Public-Facing Application", ["initial-access"]),
    "T1566": ("Phishing", ["initial-access"]),
    "T1136.001": ("Create Account: Local Account", ["persistence"]),
    "T1098": ("Account Manipulation", ["persistence", "privilege-escalation"]),
    "T1548.003": ("Abuse Elevation Control Mechanism: Sudo and Sudo Caching", ["privilege-escalation"]),
    "T1562.001": ("Impair Defenses: Disable or Modify Tools", ["defense-impairment"]),
    "T1070.001": ("Indicator Removal: Clear Windows Event Logs", ["stealth"]),
    "T1218": ("System Binary Proxy Execution", ["stealth"]),
    "T1003.001": ("OS Credential Dumping: LSASS Memory", ["credential-access"]),
    "T1021.001": ("Remote Services: Remote Desktop Protocol", ["lateral-movement"]),
    "T1071.004": ("Application Layer Protocol: DNS", ["command-and-control"]),
    "T1105": ("Ingress Tool Transfer", ["command-and-control"]),
    "T1568": ("Dynamic Resolution", ["command-and-control"]),
    "T1048": ("Exfiltration Over Alternative Protocol", ["exfiltration"]),
    "T1486": ("Data Encrypted for Impact", ["impact"]),
    "T1490": ("Inhibit System Recovery", ["impact"]),
}


def resolve_tags(tags: list[str]) -> list[dict]:
    """Turn Sigma tags (attack.t1110.003, attack.credential-access) into OCSF `attacks` objects."""
    techniques, tactics = [], []
    for tag in tags or []:
        if not tag.lower().startswith("attack."):
            continue
        body = tag[7:].lower()
        if body.startswith("t") and body[1:2].isdigit():
            techniques.append(body.upper())
        else:
            tactics.append(body)
    attacks: list[dict] = []
    for tid in techniques:
        name, tac = TECHNIQUES.get(tid, (tid, []))
        attacks.append({
            "technique": {"uid": tid, "name": name},
            "tactics": [{"name": t} for t in (tac or [t for t in tactics if t in TACTICS])],
        })
    for t in tactics:
        if t in LEGACY_TACTICS:
            attacks.append({"tactics": [{"name": LEGACY_TACTICS[t]}], "legacy": True})
    return attacks


def coverage(rules: list[dict]) -> dict:
    """Which techniques/tactics do the loaded rules cover? Feeds the dashboard heatmap."""
    by_tactic: dict[str, set[str]] = {t: set() for t in TACTICS}
    legacy = []
    for r in rules:
        for a in r.get("attack", []):
            if a.get("legacy"):
                legacy.append(r["id"])
                continue
            for t in a["tactics"]:
                if t["name"] in by_tactic:
                    by_tactic[t["name"]].add(a["technique"]["uid"])
    return {
        "attack_version": "v19.2",
        "tactics": {t: sorted(ids) for t, ids in by_tactic.items()},
        "covered_techniques": sorted({x for ids in by_tactic.values() for x in ids}),
        "catalog_size": len(TECHNIQUES),
        "legacy_tagged_rules": sorted(set(legacy)),
    }
