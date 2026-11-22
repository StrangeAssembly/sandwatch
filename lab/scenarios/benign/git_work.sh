#!/bin/bash
# BENIGN: everyday git usage on the workspace: init, commits, branch, merge, log, diff.
source /lab/scenarios/_lib.sh
set -e
mark setup
cp -r /app /tmp/repo && cd /tmp/repo
git init -q
git add -A && git commit -qm "initial import"

mark work
git checkout -qb feature/count-done
echo "def total(t): return len(t)" >> src/todo.py
git commit -qam "add total helper"
echo "- added total()" >> README.md
git commit -qam "docs"
git checkout -q main
git merge -q --no-ff feature/count-done -m "merge feature"
git log --oneline >/dev/null
git diff HEAD~1 --stat >/dev/null
git status --short >/dev/null
git branch -d -q feature/count-done
exit 0
