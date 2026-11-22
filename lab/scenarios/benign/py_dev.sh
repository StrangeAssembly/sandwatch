#!/bin/bash
# BENIGN: Python development loop. Create a venv, install packages (offline), run tests,
# make an edit, run tests again. Installers produce a lot of fast, varied file activity
# and many failed stats: a classic false-positive source for tempo rules.
source /lab/scenarios/_lib.sh
set -e
mark setup
cp -r /app /tmp/work && cd /tmp/work
python3 -m venv .venv

mark install
.venv/bin/pip install -q --no-index --find-links /opt/wheels pytest requests

mark test
.venv/bin/python -m pytest -q tests

mark edit
cat >> src/todo.py <<'EOF'


def count_done(todo):
    return len(todo) - len(todo.pending())
EOF
.venv/bin/python -m pytest -q tests
.venv/bin/python -m compileall -q src
exit 0
