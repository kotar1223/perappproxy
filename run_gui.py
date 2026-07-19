"""PerAppProxy GUI — standalone launcher."""

import sys
import os

# Add src to path for PyInstaller
if getattr(sys, 'frozen', False):
    base = sys._MEIPASS
    sys.path.insert(0, os.path.join(base, 'perappproxy'))
    os.chdir(base)

from perappproxy.gui import main

if __name__ == "__main__":
    main()
