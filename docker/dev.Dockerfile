# Sandwatch build/test toolchain: Rust + clang/libbpf headers for compiling the eBPF sensor.
FROM rust:1.88-bookworm
RUN apt-get update \
 && apt-get install -y --no-install-recommends clang llvm libbpf-dev linux-libc-dev \
 && rm -rf /var/lib/apt/lists/*
