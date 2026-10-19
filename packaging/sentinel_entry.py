"""PyInstaller entry point. The launcher module uses relative imports, so it cannot be the entry script itself."""

import multiprocessing
import sys

from sentinel.launcher import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(main())
