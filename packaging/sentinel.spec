# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for the single-file Sentinel executable. Used by packaging/build.py and by CI.
#   python -m PyInstaller --clean --noconfirm packaging/sentinel.spec
import os
import sys

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))  # noqa: F821  (SPECPATH is provided by PyInstaller)
IS_WIN = sys.platform == "win32"

# These libraries import parts of themselves by string at runtime (server loops/protocols, async backends,
# lazily loaded pydantic modules), which static analysis cannot see. Collect them whole.
hidden = []
for pkg in ("uvicorn", "anyio", "pydantic", "pydantic_core", "fastapi", "starlette", "httpx", "httpcore", "h11", "yaml"):
    hidden += collect_submodules(pkg)

datas = [
    (os.path.join(ROOT, "rules"), "rules"),          # default detections (copied next to the exe on first run)
    (os.path.join(ROOT, "playbooks"), "playbooks"),  # default playbooks (same)
    (os.path.join(ROOT, "ui"), "ui"),                # web console (served from the bundle)
]
datas += collect_data_files("certifi")               # CA bundle for outbound HTTPS (LLM triage)

a = Analysis(  # noqa: F821
    [os.path.join(SPECPATH, "sentinel_entry.py")],  # noqa: F821
    pathex=[ROOT],
    datas=datas,
    hiddenimports=hidden,
    excludes=["tkinter", "pytest", "IPython", "matplotlib", "numpy", "pandas"],
    noarchive=False,
)
pyz = PYZ(a.pure)  # noqa: F821

exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="Sentinel",
    console=True,            # it is a server with a console banner; a windowed build would have no stdout
    upx=False,               # UPX-packed executables trigger far more antivirus false positives
    runtime_tmpdir=None,
    version=os.path.join(ROOT, "build", "version_info.txt") if IS_WIN else None,
)
