"""Central configuration and the standards versions this build targets."""

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Standards targeted by this build (verified Oct 2026).
OCSF_VERSION = "1.9.0"        # ocsf-schema release of Aug 3, 2026
ATTACK_VERSION = "v19.2"      # ATT&CK v19 (Apr 2026): Defense Evasion split into Stealth + Defense Impairment
SIGMA_SPEC = "2.0"            # Sigma specification 2.0 (correlation rules, filters)

DB_PATH = os.environ.get("SENTINEL_DB", str(ROOT / "sentinel.db"))
RULES_DIR = Path(os.environ.get("SENTINEL_RULES", ROOT / "rules"))
PLAYBOOKS_DIR = Path(os.environ.get("SENTINEL_PLAYBOOKS", ROOT / "playbooks"))
UI_DIR = ROOT / "ui"

# Optional API key. If set, all /api requests must send X-API-Key.
API_KEY = os.environ.get("SENTINEL_API_KEY", "")

# AI triage. With ANTHROPIC_API_KEY set the LLM is used; otherwise a deterministic
# offline heuristic produces the same output shape.
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
TRIAGE_MODEL = os.environ.get("SENTINEL_TRIAGE_MODEL", "claude-sonnet-5-5")

# SOAR actions are simulated unless this is set. No real device is touched in this prototype.
SOAR_DRY_RUN = os.environ.get("SENTINEL_DRY_RUN", "1") != "0"
