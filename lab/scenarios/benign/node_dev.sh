#!/bin/bash
# BENIGN: Node development loop. Offline `npm ci` from a warm cache, run, test.
source /lab/scenarios/_lib.sh
set -e
mark setup
cp -r /opt/npm-template /tmp/node-work && cd /tmp/node-work

mark install
npm ci --offline --no-audit --no-fund --loglevel=error

mark run
node index.js
npm test --silent
exit 0
