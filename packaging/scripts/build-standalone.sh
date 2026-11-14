#!/bin/sh
# Build a self-contained diysca (bundled Python + deps, no system Python needed)
# into dist/diysca/. Used by the native packages (deb/rpm) and the AppImage.
set -eu
cd "$(dirname "$0")/../.."
PY=${PYTHON:-python3}
"$PY" -m venv build/venv
build/venv/bin/pip install --quiet --upgrade pip
build/venv/bin/pip install --quiet ".[zstd]" pyinstaller
build/venv/bin/python -m PyInstaller --noconfirm --clean --onedir --name diysca \
  --collect-submodules apprise --collect-data apprise \
  --collect-submodules uvicorn --collect-submodules asyncssh \
  --collect-data diysca --hidden-import diysca.web \
  --exclude-module tkinter --exclude-module PIL --exclude-module numpy --exclude-module scipy \
  --distpath dist --workpath build/pyinstaller --specpath build/pyinstaller \
  packaging/diysca-entry.py
./dist/diysca/diysca --version
