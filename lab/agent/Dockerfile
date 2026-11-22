# The monitored "agent" workload image.
# Internet is only used at BUILD time (packages, wheels, npm cache). At run time the
# container sits on the isolated lab network, so benign installs run fully offline.
FROM node:22-bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 python3-venv python3-pip strace curl git procps iproute2 \
      ca-certificates util-linux findutils tar gzip less \
 && rm -rf /var/lib/apt/lists/*

# Offline Python wheels for the benign "pip install" workload.
RUN python3 -m venv /tmp/v \
 && /tmp/v/bin/pip download --dest /opt/wheels pytest==8.3.3 requests==2.32.3 \
 && rm -rf /tmp/v

RUN useradd -m -u 1001 -s /bin/bash agent

# Agent workspace + fake home (all secrets inside are fake, labeled SANDWATCH-FAKE).
COPY --chown=agent:agent workspace/ /app/
COPY --chown=agent:agent fake-home/ /home/agent/
COPY --chown=agent:agent npm-template/ /opt/npm-template/
RUN chmod 700 /home/agent/.ssh && chmod 600 /home/agent/.ssh/* /home/agent/.aws/credentials

# Warm the npm cache as the agent user, then drop node_modules so `npm ci --offline`
# does a real (offline) install at run time.
USER agent
RUN cd /opt/npm-template && npm install --no-audit --no-fund && rm -rf node_modules

WORKDIR /app
CMD ["bash"]
