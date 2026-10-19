"""Build the single-file Sentinel executable.

    python packaging/build.py                 # tests -> PyInstaller -> smoke test -> SHA-256
    python packaging/build.py --skip-tests    # faster rebuild
    python packaging/build.py --skip-smoke

Run it inside an environment with the packages from requirements-build.txt installed (packaging/build-windows.ps1
sets that up for you on Windows). PyInstaller builds for the OS it runs on: run it on Windows to get Sentinel.exe.
Output: dist/Sentinel.exe (Windows) or dist/Sentinel, plus a .sha256 file next to it.
"""

import argparse
import hashlib
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IS_WIN = sys.platform == "win32"
EXE_NAME = "Sentinel.exe" if IS_WIN else "Sentinel"


def run(cmd: list[str]) -> None:
    print("+ " + " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=ROOT, check=True)


def version_info_text(version: str) -> str:
    """Windows 'Details' tab metadata. Complete metadata also makes the exe look less anonymous to AV engines."""
    # Windows wants four integers: keep the leading digits of each part ("0.2.0rc1" -> 0.2.0.0), never fail the build
    nums = [(re.match(r"\d+", p) or ["0"])[0] for p in version.split(".")]
    parts = (nums + ["0"] * 4)[:4]
    tup = ", ".join(parts)
    dotted = ".".join(parts)
    return f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers=({tup}), prodvers=({tup}), mask=0x3f, flags=0x0, OS=0x40004,
                    fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'Sentinel'),
      StringStruct('FileDescription', 'Sentinel SIEM/SOAR server'),
      StringStruct('FileVersion', '{dotted}'),
      StringStruct('InternalName', 'Sentinel'),
      StringStruct('OriginalFilename', 'Sentinel.exe'),
      StringStruct('ProductName', 'Sentinel SIEM/SOAR'),
      StringStruct('ProductVersion', '{dotted}')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--skip-tests", action="store_true", help="do not run the unit tests first")
    ap.add_argument("--skip-smoke", action="store_true", help="do not start the built exe and test it")
    args = ap.parse_args()

    if sys.version_info < (3, 10):
        print("Python 3.10 or newer is required (3.12 recommended).", file=sys.stderr)
        return 2
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("PyInstaller is not installed. Run: pip install -r requirements-build.txt", file=sys.stderr)
        return 2

    sys.path.insert(0, str(ROOT))
    from sentinel import __version__

    if not args.skip_tests:
        run([sys.executable, "-m", "pytest", "-q"])

    (ROOT / "build").mkdir(exist_ok=True)
    (ROOT / "build" / "version_info.txt").write_text(version_info_text(__version__), encoding="utf-8")

    run([sys.executable, "-m", "PyInstaller", "--clean", "--noconfirm", "--distpath", "dist",
         "--workpath", str(Path("build") / "pyi"), str(Path("packaging") / "sentinel.spec")])

    exe = ROOT / "dist" / EXE_NAME
    if not exe.is_file():
        print(f"Build finished but {exe} was not produced.", file=sys.stderr)
        return 1

    if not args.skip_smoke:
        run([sys.executable, str(Path("packaging") / "smoke_test.py"), str(exe)])

    digest = hashlib.sha256(exe.read_bytes()).hexdigest()
    (exe.parent / (EXE_NAME + ".sha256")).write_text(f"{digest}  {EXE_NAME}\n", encoding="utf-8")
    print(f"\nBuilt {exe}  ({exe.stat().st_size / 1e6:.1f} MB)\nSHA-256 {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
