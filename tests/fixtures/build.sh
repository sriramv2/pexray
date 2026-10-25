#!/usr/bin/env bash
# Build real PEX files from PyPI to try pexray against by hand. Not used by pytest.
set -euo pipefail
cd "$(dirname "$0")"

pex "requests==2.31.0" "rich==13.7.0" -o req-old.pex
pex "requests==2.32.3" "rich==13.9.4" "httpx==0.27.2" -o req-new.pex
pex "requests==2.32.3" --no-pre-install-wheels -o req-whl.pex
pex "requests==2.32.3" --layout packed -o req-packed

# A platform gap: PyQt6-Qt6 ships an x86_64-only wheel next to universal2 siblings.
pex "PyQt6==6.11.0" --no-build --platform macosx_10_14_x86_64-cp-312-cp312 -o qt-mac.pex

# A platform regression between builds.
pex "numpy==2.1.2" --no-build \
  --platform manylinux2014_x86_64-cp-312-cp312 --platform macosx_11_0_arm64-cp-312-cp312 \
  -o np-multi.pex
pex "numpy==2.1.2" --no-build --platform manylinux2014_x86_64-cp-312-cp312 -o np-linux.pex

echo "Try:  pexray info qt-mac.pex   |   pexray diff req-old.pex req-new.pex   |   pexray diff np-multi.pex np-linux.pex"
