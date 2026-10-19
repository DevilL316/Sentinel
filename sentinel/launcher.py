"""Entry point used by Sentinel.exe (and `python -m sentinel.launcher`).

Commands:  run (default) | install-task | remove-task | status | show-key | version
Settings live in sentinel.env next to the executable. Real environment variables override the file.
The first run creates the file with a freshly generated API key, so the server is never open by default.
"""

import argparse
import logging
import logging.handlers
import os
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path

from . import __version__

TASK_NAME = "Sentinel SIEM"
ENV_NAME = "sentinel.env"

DEFAULT_ENV = """# Sentinel settings. Lines starting with # are ignored. Real environment variables override this file.
SENTINEL_API_KEY={key}
SENTINEL_HOST=127.0.0.1
SENTINEL_PORT=8000

# Response actions are simulated unless you wire up connectors. Leave at 1.
SENTINEL_DRY_RUN=1

# Optional: enables Claude-based alert triage. Without it a built-in heuristic is used.
# ANTHROPIC_API_KEY=
# SENTINEL_TRIAGE_MODEL=claude-sonnet-5-5
"""


FROZEN = getattr(sys, "frozen", False)  # True inside a PyInstaller single-file exe


def home_dir() -> Path:
    """Where settings and data live: SENTINEL_HOME if set, else the folder of the single-file exe,
    else the source tree (dev runs)."""
    h = os.environ.get("SENTINEL_HOME")
    if h:
        return Path(h)
    return Path(sys.executable).resolve().parent if FROZEN else Path(__file__).resolve().parent.parent


def own_exe() -> str | None:
    return os.environ.get("SENTINEL_EXE") or (sys.executable if FROZEN else None)


def seed_editable_content(home: Path) -> None:
    """In the single-file exe the bundled rules/playbooks are unpacked to a temporary folder on every start,
    so edits there would be lost. Copy them next to the exe once, and use that copy from then on.
    An existing folder is never overwritten, so a user's edits survive restarts and upgrades."""
    if not FROZEN:
        return
    bundled = Path(__file__).resolve().parent.parent
    for name, var in (("rules", "SENTINEL_RULES"), ("playbooks", "SENTINEL_PLAYBOOKS")):
        target = home / name
        if not target.exists() and (bundled / name).is_dir():
            shutil.copytree(bundled / name, target)
        if target.is_dir():
            os.environ.setdefault(var, str(target))


def parse_env(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in text.lstrip("﻿").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        if k:
            out[k] = v
    return out


def _restrict_file(path: Path) -> None:
    """Best effort: on Windows, limit the settings file (it holds the API key) to admins and SYSTEM."""
    if os.name != "nt":
        try:
            path.chmod(0o600)
        except OSError:
            pass
        return
    try:
        subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F",
                        f"{os.environ.get('USERNAME', 'Users')}:F"], capture_output=True, timeout=15)
    except Exception:
        pass


def ensure_config(home: Path) -> tuple[dict[str, str], bool]:
    """Load sentinel.env, creating it with a random API key on first run. Returns (settings, created)."""
    path = home / ENV_NAME
    created = False
    if not path.exists():
        path.write_text(DEFAULT_ENV.format(key=secrets.token_urlsafe(24)), encoding="utf-8")
        _restrict_file(path)
        created = True
    return parse_env(path.read_text(encoding="utf-8")), created


def apply_settings(home: Path, settings: dict[str, str]) -> dict[str, str]:
    """Push file settings into os.environ (real env wins) and set data paths. Must run before importing the app."""
    for k, v in settings.items():
        os.environ.setdefault(k, v)
    data = home / "data"
    data.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("SENTINEL_DB", str(data / "sentinel.db"))
    seed_editable_content(home)
    return {
        "host": os.environ.get("SENTINEL_HOST", "127.0.0.1"),
        "port": os.environ.get("SENTINEL_PORT", "8000"),
    }


def schtasks_create_args(exe: str) -> list[str]:
    return ["schtasks", "/Create", "/TN", TASK_NAME, "/TR", f'"{exe}" run --service', "/SC", "ONSTART",
            "/RU", "SYSTEM", "/RL", "HIGHEST", "/F"]


def _port_free(host: str, port: int) -> bool:
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0 if os.name == "nt" else 1)
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def _banner(url: str, home: Path, created: bool, key_set: bool) -> None:
    print("=" * 62)
    print(f" Sentinel SIEM/SOAR {__version__}")
    print(f" Console : {url}")
    print(f" Settings: {home / ENV_NAME}")
    if key_set:
        print(" API key : stored in the settings file (run: Sentinel.exe show-key)")
    else:
        print(" API key : NOT SET - the API is open. Set SENTINEL_API_KEY in the settings file.")
    if created:
        print(" First run: a random API key was generated. Paste it into the console's key box.")
    print(" Stop    : press Ctrl+C")
    print("=" * 62, flush=True)


def cmd_run(args, home: Path) -> int:
    settings, created = ensure_config(home)
    bind = apply_settings(home, settings)
    host = args.host or bind["host"]
    try:
        port = int(args.port or bind["port"])
    except ValueError:
        print(f"Invalid port '{args.port or bind['port']}'.", file=sys.stderr)
        return 2
    if not _port_free(host, port):
        print(f"Port {port} on {host} is already in use. Is Sentinel already running? "
              f"Use --port to pick another.", file=sys.stderr)
        return 3
    if args.service:
        handler = logging.handlers.RotatingFileHandler(home / "data" / "sentinel.log", maxBytes=5_000_000,
                                                       backupCount=3, encoding="utf-8")
        logging.basicConfig(level=logging.INFO, handlers=[handler],
                            format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    key_set = bool(os.environ.get("SENTINEL_API_KEY"))
    shown = "localhost" if host in ("127.0.0.1", "0.0.0.0", "::") else host
    url = f"http://{shown}:{port}"
    if not args.service:
        _banner(url, home, created, key_set)
        if not args.no_browser:
            threading.Timer(1.5, lambda: webbrowser.open(url)).start()
    if host not in ("127.0.0.1", "localhost", "::1"):
        logging.getLogger("sentinel").warning(
            "Listening on %s over plain HTTP. Put a TLS reverse proxy in front before exposing it.", host)
    import uvicorn
    from .app import app  # imported only now: sentinel.config reads the environment at import time
    uvicorn.run(app, host=host, port=port, log_level="info",
                log_config=None if args.service else uvicorn.config.LOGGING_CONFIG)
    return 0


def cmd_install_task(home: Path) -> int:
    if os.name != "nt":
        print("install-task only works on Windows.", file=sys.stderr)
        return 2
    exe = own_exe()
    if not exe:
        print("Run this through Sentinel.exe, not python directly.", file=sys.stderr)
        return 2
    ensure_config(home)
    r = subprocess.run(schtasks_create_args(exe))
    if r.returncode != 0:
        print("Could not create the task. Run this from an elevated (Administrator) prompt.", file=sys.stderr)
        return r.returncode
    subprocess.run(["schtasks", "/Run", "/TN", TASK_NAME])
    print(f"Installed. Sentinel now starts at boot as SYSTEM and was started just now.\n"
          f"Logs: {home / 'data' / 'sentinel.log'}   Settings: {home / ENV_NAME}")
    return 0


def cmd_remove_task() -> int:
    if os.name != "nt":
        print("remove-task only works on Windows.", file=sys.stderr)
        return 2
    subprocess.run(["schtasks", "/End", "/TN", TASK_NAME], capture_output=True)
    r = subprocess.run(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"])
    return r.returncode


def cmd_status(home: Path) -> int:
    path = home / ENV_NAME
    settings = parse_env(path.read_text(encoding="utf-8")) if path.exists() else {}
    host = os.environ.get("SENTINEL_HOST", settings.get("SENTINEL_HOST", "127.0.0.1"))
    port = int(os.environ.get("SENTINEL_PORT", settings.get("SENTINEL_PORT", "8000")))
    print(f"Settings file : {path} ({'found' if path.exists() else 'not created yet - run once first'})")
    print(f"Configured    : {host}:{port}")
    probe = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    try:
        with socket.create_connection((probe, port), timeout=2):
            print("Server        : RUNNING")
    except OSError:
        print("Server        : not reachable")
    if os.name == "nt":
        r = subprocess.run(["schtasks", "/Query", "/TN", TASK_NAME], capture_output=True, text=True)
        print("Startup task  : " + ("installed" if r.returncode == 0 else "not installed"))
    return 0


def cmd_show_key(home: Path) -> int:
    path = home / ENV_NAME
    if not path.exists():
        print("No settings file yet. Start Sentinel once to create it.", file=sys.stderr)
        return 1
    key = parse_env(path.read_text(encoding="utf-8")).get("SENTINEL_API_KEY", "")
    print(key or "(no API key set)")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="Sentinel.exe", description="Sentinel SIEM/SOAR")
    p.add_argument("command", nargs="?", default="run",
                   choices=["run", "install-task", "remove-task", "status", "show-key", "version"])
    p.add_argument("--host", help="bind address (default 127.0.0.1)")
    p.add_argument("--port", help="port (default 8000)")
    p.add_argument("--no-browser", action="store_true", help="do not open the console in a browser")
    p.add_argument("--service", action="store_true", help="unattended mode: log to data/sentinel.log")
    a = p.parse_args(argv)
    home = home_dir()
    try:
        return {"run": lambda: cmd_run(a, home), "install-task": lambda: cmd_install_task(home),
                "remove-task": cmd_remove_task, "status": lambda: cmd_status(home),
                "show-key": lambda: cmd_show_key(home),
                "version": lambda: (print(__version__), 0)[1]}[a.command]()
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
