import os
import sys
from pathlib import Path

os.environ["SENTINEL_DB"] = ":memory:"
os.environ.pop("ANTHROPIC_API_KEY", None)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402

from sentinel import db, pipeline, soar  # noqa: E402


@pytest.fixture(autouse=True)
def fresh():
    db.reset()
    pipeline.init()
    soar.FIREWALL.clear(); soar.DISABLED_USERS.clear(); soar.ISOLATED_HOSTS.clear()
    yield
    db.reset()
