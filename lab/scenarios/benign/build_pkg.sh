#!/bin/bash
# BENIGN: build/package step: byte-compile, checksum every file, tarball, unpack to verify.
source /lab/scenarios/_lib.sh
set -e
mark build
cp -r /app /tmp/build && cd /tmp/build
python3 -m compileall -q src tests
find . -type f -not -path './.git/*' -not -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > /tmp/SHA256SUMS
mv /tmp/SHA256SUMS SHA256SUMS

mark package
mkdir -p dist
tar czf dist/todo-service.tgz --exclude=dist .
mkdir -p /tmp/verify && tar xzf dist/todo-service.tgz -C /tmp/verify
(cd /tmp/verify && sha256sum -c --quiet SHA256SUMS)
rm -rf /tmp/verify
exit 0
