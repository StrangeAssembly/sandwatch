#!/bin/bash
# ATTACK: credential hunting. Looks for keys, tokens and secrets in the usual places.
# All secrets present in the lab image are fake.
source /lab/scenarios/_lib.sh

mark discovery
id >/dev/null; pause
env >/dev/null; pause
ls -la ~ >/dev/null; pause

mark credential-access
while read -r f; do
  cat "$f" >/dev/null 2>&1
  pause
done < <(shuffled \
  ~/.aws/credentials ~/.aws/config ~/.ssh/id_ed25519 ~/.ssh/id_rsa ~/.ssh/config \
  ~/.git-credentials ~/.docker/config.json ~/.kube/config ~/.netrc \
  ~/.config/gcloud/credentials.db ~/.bash_history /app/.env /etc/shadow)

find / -xdev \( -name '*.pem' -o -name '*.key' -o -name 'id_*' -o -name '.env' \
  -o -name 'credentials' -o -name '*.kdbx' \) -not -path '/proc/*' 2>/dev/null | head -50 >/dev/null
pause
grep -rIl -E 'API_KEY|SECRET|TOKEN|PASSWORD' /app /home /etc 2>/dev/null | head -50 >/dev/null
pause

# Other processes' environments (most will be denied).
for e in /proc/[0-9]*/environ; do cat "$e" >/dev/null 2>&1; done
exit 0
