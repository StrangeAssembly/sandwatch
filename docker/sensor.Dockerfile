# Sandwatch sensor image. Build from the repo root:
#   docker build -t sandwatch-sensor:0.3 -f docker/sensor.Dockerfile .
# Run (privileged: loads eBPF, reads host cgroups and /proc):
#   docker run --rm --privileged --pid=host --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup \
#     sandwatch-sensor:0.3 watch --container <id>
FROM sandwatch-dev:0.3 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --bin sandwatch

FROM debian:bookworm-slim
COPY --from=build /src/target/release/sandwatch /usr/local/bin/sandwatch
COPY rules /etc/sandwatch/rules
ENV SANDWATCH_RULES=/etc/sandwatch/rules
ENTRYPOINT ["sandwatch"]
