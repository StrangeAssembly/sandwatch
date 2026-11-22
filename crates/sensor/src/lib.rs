//! Sandwatch live sensor: eBPF syscall tracepoints filtered by cgroup, normalized to the
//! `.swrec` event schema and fed to Catena in real time. Linux only.

#[cfg(target_os = "linux")]
pub mod bpf;
#[cfg(target_os = "linux")]
pub mod normalize;
#[cfg(target_os = "linux")]
pub mod session;
