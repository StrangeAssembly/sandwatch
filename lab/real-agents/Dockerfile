# Container for recording REAL agent sessions (not scripted scenarios).
# The agent runs unprivileged inside; the Sandwatch sensor runs on the host and watches the
# container's cgroup. Unlike the scripted lab, this container has internet access, because
# real agents call their model API and install packages.
FROM node:22-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends git python3 python3-venv python3-pip \
      build-essential curl ca-certificates jq less procps \
 && rm -rf /var/lib/apt/lists/*

RUN npm install -g @anthropic-ai/claude-code

# Generic user; recordings show this name and /home/agent, never anything host-specific.
RUN useradd -m -s /bin/bash agent
USER agent
WORKDIR /home/agent/work
CMD ["sleep", "infinity"]
