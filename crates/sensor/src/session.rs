//! A live monitoring session: sensor -> normalizer -> (.swrec writer + Catena) -> response.

use crate::bpf::{RawEvent, Sensor};
use crate::normalize::Normalizer;
use anyhow::{bail, Context, Result};
use catena::{Alert, Engine, Rule};
use serde_json::{json, Value};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";

pub enum Target {
    /// Watch an existing cgroup (e.g. a container's).
    Cgroup(PathBuf),
    /// Launch this command inside a fresh cgroup and watch it until it exits.
    Run(Vec<String>),
}

pub struct Options {
    pub session_id: String,
    pub out: PathBuf,
    pub labels: Option<Value>,
    /// Rule ids that trigger a freeze of the watched cgroup.
    pub freeze_on: Vec<String>,
    pub duration: Option<Duration>,
    pub stop: Arc<AtomicBool>,
}

pub struct Outcome {
    pub events: u64,
    pub alerts: Vec<Alert>,
    pub ring_drops: u64,
    pub pending_drops: u64,
    pub frozen_by: Option<String>,
    pub exit_code: Option<i32>,
    pub cgroup: PathBuf,
}

/// Find a container's cgroup directory by (a prefix of) its id.
pub fn find_container_cgroup(id: &str) -> Result<PathBuf> {
    if id.len() < 12 {
        bail!("container id prefix must be at least 12 characters");
    }
    let mut stack = vec![(PathBuf::from(CGROUP_ROOT), 0)];
    let mut hits = Vec::new();
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if !p.is_dir() {
                continue;
            }
            let name = e.file_name().to_string_lossy().to_string();
            if name.contains(id) {
                hits.push(p.clone());
            } else if depth < 4 {
                stack.push((p, depth + 1));
            }
        }
    }
    hits.sort_by_key(|p| p.components().count());
    hits.into_iter().next().with_context(|| format!("no cgroup found for container {id}"))
}

fn cgroup_id(path: &Path) -> Result<u64> {
    Ok(std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?.ino())
}

pub fn freeze(cgroup: &Path, on: bool) -> Result<()> {
    std::fs::write(cgroup.join("cgroup.freeze"), if on { "1" } else { "0" })
        .with_context(|| format!("writing {}/cgroup.freeze", cgroup.display()))
}

fn environment(target: &str) -> Value {
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    json!({
        "kernel": kernel.trim(),
        "arch": std::env::consts::ARCH,
        "runtime": "linux",
        "target": target,
    })
}

/// Run a session. `on_alert` is called for every alert as it happens.
pub fn run(
    opts: Options,
    target: Target,
    rules: Vec<Rule>,
    on_alert: &mut dyn FnMut(&Alert, Option<&str>),
) -> Result<Outcome> {
    let mut sensor = Sensor::load()?;

    let (cgroup, mut child, target_desc) = match &target {
        Target::Cgroup(p) => (p.clone(), None, p.display().to_string()),
        Target::Run(cmd) => {
            if cmd.is_empty() {
                bail!("nothing to run");
            }
            let cg = PathBuf::from(CGROUP_ROOT).join("sandwatch").join(&opts.session_id);
            std::fs::create_dir_all(&cg)
                .with_context(|| format!("creating {} (needs cgroup v2, writable)", cg.display()))?;
            (cg, Some(cmd.clone()), cmd.join(" "))
        }
    };
    let cg_id = cgroup_id(&cgroup)?;
    sensor.watch_cgroup(cg_id)?;

    let mut header = json!({
        "format": "sandwatch-recording",
        "format_version": "0.2",
        "session": {
            "id": opts.session_id,
            "recorded_at": chrono_like_now(),
        },
        "sensor": {
            "name": "sandwatch-ebpf",
            "version": env!("CARGO_PKG_VERSION"),
            "fidelity": "syscall tracepoints (file, process, network, namespace, creds) filtered \
                         by cgroup in kernel; no read/write payloads",
            "tracepoints_attached": sensor.attached,
        },
        "environment": environment(&target_desc),
        "schema": {"events": "ocsf-aligned-subset", "ocsf_version": "1.3.0"},
    });
    if let Some(l) = &opts.labels {
        header["labels"] = l.clone();
    }
    let mut writer = swrec::Writer::create(&opts.out, header)?;
    let mut norm = Normalizer::new(&opts.session_id);
    let mut engine = Engine::new(rules);
    let mut frozen_by: Option<String> = None;
    let mut responses: Vec<Value> = vec![];

    // Launch the workload inside the cgroup (moved there before exec).
    let mut proc_handle = None;
    if let Some(cmd) = child.take() {
        use std::os::unix::process::CommandExt;
        let procs = std::ffi::CString::new(cgroup.join("cgroup.procs").to_string_lossy().as_bytes())?;
        let mut c = std::process::Command::new(&cmd[0]);
        c.args(&cmd[1..]);
        // SAFETY: only async-signal-safe libc calls between fork and exec.
        unsafe {
            c.pre_exec(move || {
                let fd = libc::open(procs.as_ptr(), libc::O_WRONLY);
                if fd < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let r = libc::write(fd, b"0".as_ptr() as *const libc::c_void, 1);
                libc::close(fd);
                if r < 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
            });
        }
        proc_handle = Some(c.spawn().with_context(|| format!("starting {}", cmd[0]))?);
    }

    eprintln!(
        "sandwatch: watching {} (cgroup id {cg_id}), {} tracepoints attached{}",
        target_desc,
        sensor.attached,
        if sensor.skipped.is_empty() { String::new() } else { format!(", {} unavailable on this kernel", sensor.skipped.len()) }
    );

    let started = Instant::now();
    let mut exit_code = None;
    let mut drain_until: Option<Instant> = None;
    loop {
        let mut got = 0usize;
        while let Some(item) = sensor.ring.next() {
            got += 1;
            let Some(raw) = RawEvent::from_bytes(&item) else { continue };
            drop(item);
            let Some(mut ev) = norm.normalize(&raw) else { continue };
            ev["seq"] = json!(writer.event_count() + 1);
            ev["record_type"] = json!("event");
            let typed: swrec::Event = match serde_json::from_value(ev.clone()) {
                Ok(t) => t,
                Err(_) => continue,
            };
            for a in engine.process(&typed) {
                on_alert(&a, typed.actor.process.cmd_line.as_deref());
                if frozen_by.is_none() && opts.freeze_on.iter().any(|f| f == &a.rule_id) {
                    match freeze(&cgroup, true) {
                        Ok(()) => {
                            eprintln!("sandwatch: FROZE {} after {}", cgroup.display(), a.rule_id);
                            responses.push(json!({"action": "freeze", "rule_id": a.rule_id, "time": a.time}));
                            frozen_by = Some(a.rule_id.clone());
                            drain_until.get_or_insert(Instant::now() + Duration::from_millis(500));
                        }
                        Err(e) => eprintln!("sandwatch: freeze failed: {e:#}"),
                    }
                }
            }
            writer.event(ev)?;
        }

        if drain_until.is_none() {
            let stop = opts.stop.load(Ordering::Relaxed)
                || opts.duration.is_some_and(|d| started.elapsed() >= d);
            let child_done = match proc_handle.as_mut() {
                Some(ch) => match ch.try_wait()? {
                    Some(st) => {
                        exit_code = st.code();
                        true
                    }
                    None => false,
                },
                None => false,
            };
            if stop || child_done {
                drain_until = Some(Instant::now() + Duration::from_millis(300));
            }
        }
        if let Some(t) = drain_until {
            if Instant::now() >= t && got == 0 {
                break;
            }
        }
        if got == 0 {
            std::thread::sleep(Duration::from_millis(3));
        }
    }

    // Run mode: a frozen workload is killed when the session ends (it cannot be resumed
    // from here); the cgroup is removed.
    if let Some(mut ch) = proc_handle {
        if frozen_by.is_some() {
            let _ = std::fs::write(cgroup.join("cgroup.kill"), "1");
            let _ = freeze(&cgroup, false);
        }
        if let Ok(st) = ch.wait() {
            exit_code = exit_code.or(st.code());
        }
        for _ in 0..50 {
            if std::fs::remove_dir(&cgroup).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    let (ring_drops, pending_drops) = sensor.drops();
    let duration_ms = match norm.start_epoch_ms() {
        Some(s) => norm.last_epoch_ms - s,
        None => 0,
    };
    let events = writer.event_count();
    let phases: Vec<Value> =
        norm.phases.iter().map(|(n, t)| json!({"name": n, "time": t})).collect();
    writer.finish(json!({
        "duration_ms": duration_ms,
        "start_time": norm.start_epoch_ms(),
        "ground_truth": {"phases": phases},
        "sensor_stats": {"ring_buffer_drops": ring_drops, "pending_drops": pending_drops,
                         "runtime_init_events_dropped": norm.dropped_runtime},
        "responses": responses,
        "workload_exit_code": exit_code,
    }))?;

    Ok(Outcome {
        events,
        alerts: engine.alerts().to_vec(),
        ring_drops,
        pending_drops,
        frozen_by,
        exit_code,
        cgroup,
    })
}

fn chrono_like_now() -> String {
    // RFC 3339 UTC without pulling in a date crate.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // civil-from-days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}
