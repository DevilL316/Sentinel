"""Synthetic attack scenarios for demos and tests. All addresses are RFC 5737 documentation ranges."""

import time

BAD_IP = "203.0.113.50"


def _ssh(user: str, ip: str, ok: bool = False, i: int = 0) -> str:
    stamp = time.strftime("%b %d %H:%M:%S")
    if ok:
        return f"{stamp} web01 sshd[{2000 + i}]: Accepted password for {user} from {ip} port {40000 + i} ssh2"
    return f"{stamp} web01 sshd[{2000 + i}]: Failed password for invalid user {user} from {ip} port {40000 + i} ssh2"


def scenarios() -> dict[str, list[tuple[str, object]]]:
    return {
        "bruteforce_then_compromise": (
            [("syslog", _ssh("root", BAD_IP, i=i)) for i in range(6)] + [("syslog", _ssh("root", BAD_IP, ok=True, i=9))]
        ),
        "password_spray": [("syslog", _ssh(u, "203.0.113.77", i=n)) for n, u in
                           enumerate(["alice", "bob", "carol", "dave", "erin"])],
        "phishing_to_ransomware": [
            ("winevent", {"EventID": 4688, "Computer": "WS-FIN-07", "SubjectUserName": "carol",
                          "ParentProcessName": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                          "NewProcessName": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                          "CommandLine": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"}),
            ("winevent", {"EventID": 4688, "Computer": "WS-FIN-07", "SubjectUserName": "carol",
                          "NewProcessName": r"C:\Windows\System32\rundll32.exe",
                          "CommandLine": r"rundll32.exe C:\Users\carol\AppData\Local\Temp\x.dll,Start"}),
            ("winevent", {"EventID": 4688, "Computer": "WS-FIN-07", "SubjectUserName": "carol",
                          "NewProcessName": r"C:\Windows\System32\vssadmin.exe",
                          "CommandLine": "vssadmin.exe delete shadows /all /quiet"}),
            ("winevent", {"EventID": 1102, "Computer": "WS-FIN-07", "SubjectUserName": "carol"}),
        ],
        "persistence_admin_account": [
            ("winevent", {"EventID": 4720, "Computer": "DC01", "TargetUserName": "support_tmp", "SubjectUserName": "bob"}),
            ("winevent", {"EventID": 4732, "Computer": "DC01", "TargetUserName": "support_tmp",
                          "SubjectUserName": "bob", "GroupName": "Administrators"}),
        ],
        "exfil_and_dns_tunnel": [
            ("json", {"type": "network", "src_ip": "10.1.4.22", "dst_ip": "198.51.100.9", "dst_port": 443,
                      "bytes_out": 250_000_000}),
            ("json", {"type": "dns", "src_ip": "10.1.4.22", "query": "a" * 12 + "q9x" * 14 + ".t.example-c2.net"}),
        ],
        "benign_noise": [
            ("syslog", _ssh("alice", "10.0.0.5", ok=True, i=1)),
            ("json", {"type": "dns", "src_ip": "10.1.4.22", "query": "www.example.com"}),
            ("winevent", {"EventID": 4624, "Computer": "WS01", "TargetUserName": "bob", "IpAddress": "10.0.0.8", "LogonType": 2}),
        ],
    }


def run(name: str) -> dict:
    from . import pipeline
    sc = scenarios()
    if name not in sc:
        raise KeyError(f"unknown scenario '{name}' (available: {', '.join(sc)})")
    result = {"scenario": name, "stored": 0, "alerts": [], "rejected": []}
    for source, rec in sc[name]:
        r = pipeline.ingest(source, [rec])
        result["stored"] += r["stored"]
        result["alerts"] += r["alerts"]
        result["rejected"] += r["rejected"]
    return result
