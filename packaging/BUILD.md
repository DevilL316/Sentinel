# Building the single-file `Sentinel.exe`

One file, no installer, no Python needed on the target machine. PyInstaller bundles the interpreter,
the libraries, the web console and the default rules/playbooks.

PyInstaller builds for the OS it runs on, so **the real `Sentinel.exe` must be built on Windows**
(your own machine, or GitHub Actions below). On Linux/macOS the same scripts build a native
`dist/Sentinel` binary, which is useful for testing the packaging but is not a Windows file.

## Option 1: build on a Windows machine

Needs Python 3.10+ (3.12 recommended) on PATH and internet access to PyPI. No Administrator rights.

```powershell
powershell -ExecutionPolicy Bypass -File packaging\build-windows.ps1
```

It creates `.build-venv`, installs the pinned `requirements-build.txt`, then runs `packaging\build.py`:
unit tests, PyInstaller, a **smoke test that starts the finished exe twice and checks it over HTTP**,
and a SHA-256 file. Output: `dist\Sentinel.exe` and `dist\Sentinel.exe.sha256`.
Flags: `-SkipTests`, `-SkipSmoke`.

## Option 2: build on GitHub (no Windows machine needed)

1. Push this folder to a GitHub repository.
2. Actions tab > **Build Windows exe** > **Run workflow**. When it finishes, download the
   `Sentinel-windows-x64` artifact from the run page.
3. To publish a release: set `__version__` in `sentinel/__init__.py`, commit, then
   `git tag v0.1.0 && git push origin v0.1.0`. The exe and its hash are attached to a GitHub Release.
   The build fails early if the tag and `__version__` disagree.

The workflow runs the tests on Linux and Windows, builds on Windows, smoke-tests the exe, and only then
publishes. The job that can write releases runs no project code and uses no third-party action.

Verify a download on Windows: `certutil -hashfile Sentinel.exe SHA256` and compare with `Sentinel.exe.sha256`.

## What the exe does on first run

Everything is created next to `Sentinel.exe`, so put it in its own folder (for example `C:\Sentinel`):

| Created | Purpose |
|---|---|
| `sentinel.env` | settings, including a randomly generated API key (`Sentinel.exe show-key` prints it) |
| `data\sentinel.db` | events, alerts, cases; `data\sentinel.log` in unattended mode |
| `rules\`, `playbooks\` | editable copies of the defaults; edit, then restart |

Commands: `Sentinel.exe` (run), `status`, `show-key`, `install-task` / `remove-task` (start at boot as a
background task; run from an elevated prompt), `version`. See `Sentinel.exe --help`.

**Upgrading:** replace `Sentinel.exe`. Settings, data and your `rules\` and `playbooks\` stay as they are.
Because those folders are never overwritten, new default rules shipped in a newer exe are *not* applied to an
existing `rules\` folder. To pick them up, rename `rules\` (and `playbooks\`) and restart; fresh defaults are
copied in, and you can merge your changes back.

## Things to know before relying on it

- **Unsigned.** Windows SmartScreen will warn, and one-file PyInstaller executables are sometimes flagged by
  antivirus products. If that matters, sign `Sentinel.exe` with your own code-signing certificate and, where
  needed, submit it to your AV vendor as a false positive.
- **Self-unpacking.** Each start unpacks the program to a temporary folder (under `C:\Windows\Temp` when run as
  the startup task). Startup takes a few seconds, and a hard stop (power loss, killing the process) can leave
  an old `_MEI...` folder behind. A one-folder build (PyInstaller's default layout, which unpacks nothing at
  start) avoids both; if you run the one-file exe as an always-on service, clear stale `_MEI*` folders
  from time to time.
- **Not run on Windows by its author.** The build script, spec, smoke test and workflow were exercised end to
  end on Linux (same code, native binary). Windows-specific parts (version resource, `taskkill`, scheduled
  task, the first real CI run) are checked by the workflow's own smoke test the first time it runs there.
- Response actions are still simulated; see the main README, "What this is not".

## Keeping it reproducible

- `requirements-build.txt` pins every package. To update: change the pins, run the build (it runs the tests and
  the smoke test), commit if it passes.
- GitHub Actions in the workflow are pinned to commit SHAs (the comment beside each shows the release). To
  update one, look up the new release's commit SHA and replace it.
