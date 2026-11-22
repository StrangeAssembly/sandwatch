#!/bin/bash
# ATTACK: egress expansion. Cloud metadata probing, then network fan-out to find
# reachable services. Only lab addresses are touched; the lab network has no internet.
source /lab/scenarios/_lib.sh

mark metadata-probe
curl -s -m 2 http://169.254.169.254/latest/meta-data/ >/dev/null; pause
curl -s -m 2 http://metadata/latest/meta-data/ >/dev/null; pause
curl -s -m 2 http://metadata/latest/meta-data/iam/security-credentials/ >/dev/null; pause
curl -s -m 2 http://metadata/latest/meta-data/iam/security-credentials/sandwatch-lab-fake-role >/dev/null; pause

mark dns-probe
for h in $(shuffled github.com pypi.org registry.npmjs.org kubernetes.default.svc \
             metadata.google.internal collector db); do
  getent hosts "$h" >/dev/null; pause
done

mark network-fanout
for port in $(shuffled 22 80 443 2375 2376 5432 6379 8080 10250); do
  tcp_probe 10.66.0.20 "$port"; pause
done
for i in $(seq 1 24); do
  tcp_probe "10.66.0.$i" 2375; pause
done
exit 0
