#!/bin/sh
# Build a single-file zipapp from a built wheel, with PyYAML bundled.
#
#   scripts/build-pyz.sh dist/kea_lease_audit-*.whl dist/kea-lease-audit.pyz
#
# PyYAML's compiled extension is removed so the bundle is pure Python and runs
# on any python3 >= 3.9; yaml falls back to its pure-Python loader on its own.
set -eu

wheel=$1
out=$2
python=${PYTHON:-python3}

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

"$python" -m pip install --quiet --disable-pip-version-check --no-compile --target "$stage" "$wheel"
find "$stage" -name '*.so' -delete
rm -rf "$stage/bin" "$stage"/*.dist-info "$stage"/_yaml
find "$stage" -name __pycache__ -prune -exec rm -rf {} +

# Not `zipapp -m`: its generated __main__ discards main()'s return value, which
# would turn every exit code (Nagios states included) into 0.
printf 'import sys\nfrom kea_lease_audit.cli import main\nsys.exit(main())\n' > "$stage/__main__.py"
"$python" -m zipapp "$stage" -o "$out" -p '/usr/bin/env python3' -c
