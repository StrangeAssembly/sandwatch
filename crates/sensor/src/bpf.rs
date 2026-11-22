//! Loading the eBPF object, attaching tracepoints, and reading raw events.

use anyhow::{bail, Context, Result};
use aya::maps::{HashMap as BpfHashMap, MapData, PerCpuArray, RingBuf};
use aya::programs::TracePoint;
use aya::Ebpf;

pub const PATH_LEN: usize = 256;
pub const ARG_LEN: usize = 64;
pub const MAX_ARGS: usize = 6;
pub const RET_UNFINISHED: i64 = -100_000;

/// Mirror of `struct sw_event` in bpf/sensor.bpf.c.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawEvent {
    pub ts_ns: u64,
    pub cgroup_id: u64,
    pub start_ns: u64,
    pub ret: i64,
    pub a: [u64; 4],
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub sc: u32,
    pub argc: u32,
    pub comm: [u8; 16],
    pub path: [u8; PATH_LEN],
    pub path2: [u8; PATH_LEN],
    pub argv: [[u8; ARG_LEN]; MAX_ARGS],
}

const _: () = assert!(std::mem::size_of::<RawEvent>() == 1000);

pub fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

impl RawEvent {
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < std::mem::size_of::<RawEvent>() {
            return None;
        }
        // SAFETY: RawEvent is plain old data; length checked; read_unaligned handles alignment.
        Some(unsafe { std::ptr::read_unaligned(b.as_ptr() as *const RawEvent) })
    }
}

static BPF_OBJ: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/sensor.bpf.o"));

pub struct Sensor {
    ebpf: Ebpf,
    pub ring: RingBuf<MapData>,
    pub attached: usize,
    pub skipped: Vec<String>,
}

fn ensure_tracefs() {
    if std::path::Path::new("/sys/kernel/tracing/events").exists()
        || std::path::Path::new("/sys/kernel/debug/tracing/events").exists()
    {
        return;
    }
    let src = std::ffi::CString::new("nodev").unwrap();
    let dst = std::ffi::CString::new("/sys/kernel/tracing").unwrap();
    let fs = std::ffi::CString::new("tracefs").unwrap();
    // SAFETY: plain mount(2) call with valid C strings.
    unsafe {
        libc::mount(src.as_ptr(), dst.as_ptr(), fs.as_ptr(), 0, std::ptr::null());
    }
}

fn raise_memlock() {
    let lim = libc::rlimit { rlim_cur: libc::RLIM_INFINITY, rlim_max: libc::RLIM_INFINITY };
    // SAFETY: setrlimit with a valid struct; failure is non-fatal on modern kernels.
    unsafe {
        libc::setrlimit(libc::RLIMIT_MEMLOCK, &lim);
    }
}

impl Sensor {
    /// Load all programs and attach every tracepoint the running kernel provides.
    pub fn load() -> Result<Self> {
        raise_memlock();
        ensure_tracefs();
        let mut ebpf = Ebpf::load(BPF_OBJ).context(
            "loading eBPF object (needs root/CAP_BPF+CAP_PERFMON and kernel BTF at /sys/kernel/btf/vmlinux)",
        )?;
        let names: Vec<String> = ebpf.programs().map(|(n, _)| n.to_string()).collect();
        let mut attached = 0;
        let mut skipped = Vec::new();
        for name in names {
            let (category, tp) = if name == "sched_exit" {
                ("sched".to_string(), "sched_process_exit".to_string())
            } else if let Some(sc) = name.strip_prefix("enter_") {
                ("syscalls".into(), format!("sys_enter_{sc}"))
            } else if let Some(sc) = name.strip_prefix("exit_") {
                ("syscalls".into(), format!("sys_exit_{sc}"))
            } else {
                continue;
            };
            let exists = ["/sys/kernel/tracing/events", "/sys/kernel/debug/tracing/events"]
                .iter()
                .any(|base| std::path::Path::new(&format!("{base}/{category}/{tp}")).exists());
            if !exists {
                skipped.push(tp);
                continue; // e.g. sys_enter_open does not exist on arm64
            }
            let prog: &mut TracePoint = ebpf
                .program_mut(&name)
                .expect("listed program exists")
                .try_into()
                .with_context(|| format!("{name} is not a tracepoint program"))?;
            prog.load().with_context(|| format!("verifier rejected {name}"))?;
            prog.attach(&category, &tp).with_context(|| format!("attaching {category}/{tp}"))?;
            attached += 1;
        }
        if attached == 0 {
            bail!("no tracepoints attached; is tracefs available?");
        }
        let ring = RingBuf::try_from(ebpf.take_map("events").context("events map")?)?;
        Ok(Sensor { ebpf, ring, attached, skipped })
    }

    /// Watch every task in this cgroup (and its descendants).
    pub fn watch_cgroup(&mut self, cgroup_id: u64) -> Result<()> {
        let mut w: BpfHashMap<_, u64, u8> =
            BpfHashMap::try_from(self.ebpf.map_mut("watched").context("watched map")?)?;
        w.insert(cgroup_id, 1, 0)?;
        Ok(())
    }

    /// (ring-buffer drops, pending-map drops) summed over CPUs.
    pub fn drops(&self) -> (u64, u64) {
        let Some(map) = self.ebpf.map("stats") else { return (0, 0) };
        let Ok(arr) = PerCpuArray::<_, u64>::try_from(map) else { return (0, 0) };
        let sum = |i: u32| arr.get(&i, 0).map(|v| v.iter().sum()).unwrap_or(0);
        (sum(0), sum(1))
    }
}
