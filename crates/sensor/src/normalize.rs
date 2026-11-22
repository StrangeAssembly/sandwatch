//! Raw kernel records -> OCSF-aligned `.swrec` events (same schema as tools/swrec_convert.py).
//!
//! The kernel side only captures what the syscall was given. This module adds context:
//! stable process identities, parent links, command lines from exec, and absolute paths
//! (relative names are resolved against a tracked cwd / directory-fd table, falling back to
//! /proc when the process is still alive).

use crate::bpf::{cstr, RawEvent, RET_UNFINISHED};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

const MARK_PREFIX: &str = "/.sandwatch-mark/";
/// Must match SC_DENIED_BEFORE_ENTRY in bpf/sensor.bpf.c.
const SC_DENIED_BEFORE_ENTRY: u32 = 0x8000;
const AT_FDCWD: i32 = -100;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Open,
    Stat,
    Access,
    Delete,
    Rename,
    Create,
    Chdir,
    SetSecurity,
    Mount,
    Unmount,
    Exec,
    Connect,
    Namespace,
    Trace,
    Bpf,
    Fork,
    Signal,
    SetUid,
    Terminate,
}

struct Spec {
    name: &'static str,
    kind: Kind,
    dirfd: Option<usize>,
    flags: Option<usize>,
    dirfd2: Option<usize>,
}

const fn s(name: &'static str, kind: Kind, dirfd: Option<usize>, flags: Option<usize>, dirfd2: Option<usize>) -> Spec {
    Spec { name, kind, dirfd, flags, dirfd2 }
}

/// Must match the TP(...) table in bpf/sensor.bpf.c.
fn spec(sc: u32) -> Option<Spec> {
    use Kind::*;
    Some(match sc {
        1 => s("open", Open, None, Some(1), None),
        2 => s("openat", Open, Some(0), Some(2), None),
        3 => s("openat2", Open, Some(0), None, None),
        4 => s("creat", Open, None, None, None),
        5 => s("newfstatat", Stat, Some(0), None, None),
        6 => s("statx", Stat, Some(0), None, None),
        7 => s("stat", Stat, None, None, None),
        8 => s("lstat", Stat, None, None, None),
        9 => s("access", Access, None, None, None),
        10 => s("faccessat", Access, Some(0), None, None),
        11 => s("faccessat2", Access, Some(0), None, None),
        12 => s("readlink", Stat, None, None, None),
        13 => s("readlinkat", Stat, Some(0), None, None),
        14 => s("unlink", Delete, None, None, None),
        15 => s("unlinkat", Delete, Some(0), None, None),
        16 => s("rmdir", Delete, None, None, None),
        17 => s("rename", Rename, None, None, None),
        18 => s("renameat", Rename, Some(0), None, Some(2)),
        19 => s("renameat2", Rename, Some(0), None, Some(2)),
        20 => s("mkdir", Create, None, None, None),
        21 => s("mkdirat", Create, Some(0), None, None),
        22 => s("chdir", Chdir, None, None, None),
        23 => s("chmod", SetSecurity, None, None, None),
        24 => s("fchmodat", SetSecurity, Some(0), None, None),
        25 => s("chown", SetSecurity, None, None, None),
        26 => s("fchownat", SetSecurity, Some(0), None, None),
        27 => s("symlink", Create, None, None, None),
        28 => s("symlinkat", Create, Some(1), None, None),
        30 => s("execve", Exec, None, None, None),
        31 => s("execveat", Exec, Some(0), None, None),
        40 => s("connect", Connect, None, None, None),
        50 => s("unshare", Namespace, None, None, None),
        51 => s("setns", Namespace, None, None, None),
        52 => s("mount", Mount, None, None, None),
        53 => s("umount2", Unmount, None, None, None),
        54 => s("ptrace", Trace, None, None, None),
        55 => s("bpf", Bpf, None, None, None),
        60 => s("clone", Fork, None, None, None),
        61 => s("clone3", Fork, None, None, None),
        62 => s("fork", Fork, None, None, None),
        63 => s("vfork", Fork, None, None, None),
        64 => s("kill", Signal, None, None, None),
        65 => s("tkill", Signal, None, None, None),
        66 => s("tgkill", Signal, None, None, None),
        70 => s("setuid", SetUid, None, None, None),
        71 => s("setgid", SetUid, None, None, None),
        72 => s("setresuid", SetUid, None, None, None),
        73 => s("setresgid", SetUid, None, None, None),
        74 => s("setreuid", SetUid, None, None, None),
        75 => s("setregid", SetUid, None, None, None),
        90 => s("exit", Terminate, None, None, None),
        _ => return None,
    })
}

pub fn errno_name(e: i64) -> String {
    let n = match e {
        1 => "EPERM", 2 => "ENOENT", 3 => "ESRCH", 4 => "EINTR", 5 => "EIO", 6 => "ENXIO",
        7 => "E2BIG", 8 => "ENOEXEC", 9 => "EBADF", 10 => "ECHILD", 11 => "EAGAIN",
        12 => "ENOMEM", 13 => "EACCES", 14 => "EFAULT", 16 => "EBUSY", 17 => "EEXIST",
        18 => "EXDEV", 19 => "ENODEV", 20 => "ENOTDIR", 21 => "EISDIR", 22 => "EINVAL",
        23 => "ENFILE", 24 => "EMFILE", 25 => "ENOTTY", 26 => "ETXTBSY", 27 => "EFBIG",
        28 => "ENOSPC", 29 => "ESPIPE", 30 => "EROFS", 31 => "EMLINK", 32 => "EPIPE",
        36 => "ENAMETOOLONG", 38 => "ENOSYS", 39 => "ENOTEMPTY", 40 => "ELOOP",
        61 => "ENODATA", 95 => "EOPNOTSUPP", 97 => "EAFNOSUPPORT", 98 => "EADDRINUSE",
        99 => "EADDRNOTAVAIL", 101 => "ENETUNREACH", 103 => "ECONNABORTED",
        104 => "ECONNRESET", 110 => "ETIMEDOUT", 111 => "ECONNREFUSED", 113 => "EHOSTUNREACH",
        114 => "EALREADY", 115 => "EINPROGRESS",
        _ => return format!("E{e}"),
    };
    n.to_string()
}

fn signal_name(s: u64) -> String {
    let n = match s {
        0 => "0", 1 => "SIGHUP", 2 => "SIGINT", 3 => "SIGQUIT", 6 => "SIGABRT", 9 => "SIGKILL",
        10 => "SIGUSR1", 12 => "SIGUSR2", 13 => "SIGPIPE", 14 => "SIGALRM", 15 => "SIGTERM",
        17 => "SIGCHLD", 18 => "SIGCONT", 19 => "SIGSTOP",
        _ => return format!("SIG{s}"),
    };
    n.to_string()
}

const NS_FLAGS: &[(u64, &str)] = &[
    (0x0002_0000, "CLONE_NEWNS"),
    (0x0200_0000, "CLONE_NEWCGROUP"),
    (0x0400_0000, "CLONE_NEWUTS"),
    (0x0800_0000, "CLONE_NEWIPC"),
    (0x1000_0000, "CLONE_NEWUSER"),
    (0x2000_0000, "CLONE_NEWPID"),
    (0x4000_0000, "CLONE_NEWNET"),
    (0x0000_0080, "CLONE_NEWTIME"),
];

fn ns_flags(v: u64) -> String {
    let names: Vec<&str> = NS_FLAGS.iter().filter(|(b, _)| v & b != 0).map(|(_, n)| *n).collect();
    if names.is_empty() { format!("{v:#x}") } else { names.join("|") }
}

fn open_flags(f: u64) -> (String, &'static str) {
    let f = f as u32;
    let mut names = vec![match f & 3 { 0 => "O_RDONLY", 1 => "O_WRONLY", _ => "O_RDWR" }];
    for (bit, n) in [
        (0o100, "O_CREAT"), (0o200, "O_EXCL"), (0o400, "O_NOCTTY"), (0o1000, "O_TRUNC"),
        (0o2000, "O_APPEND"), (0o4000, "O_NONBLOCK"), (0o200000, "O_DIRECTORY"),
        (0o400000, "O_NOFOLLOW"), (0o2000000, "O_CLOEXEC"), (0o10000000, "O_PATH"),
    ] {
        if f & bit != 0 {
            names.push(n);
        }
    }
    let write = f & 3 != 0 || f & (0o100 | 0o1000 | 0o2000) != 0;
    (names.join("|"), if write { "write" } else { "read" })
}

/// Lexical normalization: collapses `.`, `..` and duplicate slashes.
pub fn norm_path(p: &str) -> String {
    let abs = p.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for c in p.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            x => parts.push(x),
        }
    }
    let joined = parts.join("/");
    if abs { format!("/{joined}") } else { joined }
}

fn readlink(p: &str) -> Option<String> {
    std::fs::read_link(p).ok().map(|x| x.to_string_lossy().into_owned())
}

fn parse_sockaddr(b: &[u8]) -> Option<(Value, &'static str)> {
    if b.len() < 4 {
        return None;
    }
    let family = u16::from_ne_bytes([b[0], b[1]]);
    let port = u16::from_be_bytes([b[2], b[3]]);
    match family {
        1 => {
            let raw = &b[2..];
            let path = if raw.first() == Some(&0) {
                format!("@{}", cstr(&raw[1..])) // abstract socket
            } else {
                cstr(raw)
            };
            Some((json!({ "path": path }), "unix"))
        }
        2 => {
            let ip = std::net::Ipv4Addr::new(b[4], b[5], b[6], b[7]);
            Some((json!({ "ip": ip.to_string(), "port": port }), "inet"))
        }
        10 if b.len() >= 24 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&b[8..24]);
            let ip = std::net::Ipv6Addr::from(a);
            let ip = ip.to_ipv4_mapped().map(|v4| v4.to_string()).unwrap_or(ip.to_string());
            Some((json!({ "ip": ip, "port": port }), "inet6"))
        }
        _ => None,
    }
}

#[derive(Clone, Default)]
struct Proc {
    uid: String,
    start_ns: u64,
    name: Option<String>,
    path: Option<String>,
    cmd_line: Option<String>,
    parent_uid: Option<String>,
    cwd: Option<String>,
    fds: HashMap<i32, String>,
}

pub struct Normalizer {
    session_id: String,
    mono_to_epoch_ns: i128,
    t0_ns: Option<u64>,
    procs: HashMap<u32, Proc>,
    users: HashMap<u32, String>,
    pub phases: Vec<(String, i64)>,
    pub last_epoch_ms: i64,
    /// Events dropped because they came from container-runtime init processes.
    pub dropped_runtime: u64,
}

fn clock_ns(clock: libc::clockid_t) -> i128 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: valid pointer to a timespec.
    unsafe { libc::clock_gettime(clock, &mut ts) };
    ts.tv_sec as i128 * 1_000_000_000 + ts.tv_nsec as i128
}

impl Normalizer {
    pub fn new(session_id: &str) -> Self {
        let offset = clock_ns(libc::CLOCK_REALTIME) - clock_ns(libc::CLOCK_MONOTONIC);
        Normalizer {
            session_id: session_id.to_string(),
            mono_to_epoch_ns: offset,
            t0_ns: None,
            procs: HashMap::new(),
            users: HashMap::new(),
            phases: vec![],
            last_epoch_ms: 0,
            dropped_runtime: 0,
        }
    }

    pub fn epoch_ms(&self, ts_ns: u64) -> i64 {
        ((ts_ns as i128 + self.mono_to_epoch_ns) / 1_000_000) as i64
    }

    pub fn start_epoch_ms(&self) -> Option<i64> {
        self.t0_ns.map(|t| self.epoch_ms(t))
    }

    fn uid_for(&self, tgid: u32, start_ns: u64) -> String {
        let h = Sha256::digest(format!("{}|{tgid}|{start_ns}", self.session_id).as_bytes());
        hex::encode(&h[..8])
    }

    fn user_name(&mut self, uid: u32, tgid: u32) -> String {
        if let Some(n) = self.users.get(&uid) {
            return n.clone();
        }
        let name = std::fs::read_to_string(format!("/proc/{tgid}/root/etc/passwd"))
            .ok()
            .and_then(|t| {
                t.lines().find_map(|l| {
                    let f: Vec<&str> = l.split(':').collect();
                    (f.len() > 2 && f[2] == uid.to_string()).then(|| f[0].to_string())
                })
            })
            .unwrap_or_else(|| format!("uid:{uid}"));
        self.users.insert(uid, name.clone());
        name
    }

    /// Get (creating if new) the process record for an event's thread group.
    fn proc_for(&mut self, r: &RawEvent) -> &mut Proc {
        let stale = self.procs.get(&r.tgid).is_some_and(|p| p.start_ns != r.start_ns);
        if stale || !self.procs.contains_key(&r.tgid) {
            let parent = self.procs.get(&r.ppid).cloned();
            let mut p = Proc {
                uid: self.uid_for(r.tgid, r.start_ns),
                start_ns: r.start_ns,
                ..Default::default()
            };
            if let Some(par) = parent {
                p.parent_uid = Some(par.uid.clone());
                p.name = par.name.clone();
                p.path = par.path.clone();
                p.cmd_line = par.cmd_line.clone();
                p.cwd = par.cwd.clone();
                p.fds = par.fds.clone();
            } else {
                p.name = Some(cstr(&r.comm));
                p.cwd = readlink(&format!("/proc/{}/cwd", r.tgid));
            }
            self.procs.insert(r.tgid, p);
        }
        self.procs.get_mut(&r.tgid).expect("just inserted")
    }

    fn resolve(&mut self, r: &RawEvent, raw: &str, dirfd: Option<u64>) -> Option<String> {
        if raw.is_empty() {
            return None;
        }
        if raw.starts_with('/') {
            return Some(norm_path(raw));
        }
        let tgid = r.tgid;
        let fd = dirfd.map(|d| d as i32).unwrap_or(AT_FDCWD);
        let p = self.proc_for(r);
        let base = if fd == AT_FDCWD {
            p.cwd.clone().or_else(|| readlink(&format!("/proc/{tgid}/cwd")))
        } else {
            p.fds.get(&fd).cloned().or_else(|| readlink(&format!("/proc/{tgid}/fd/{fd}")))
        };
        Some(match base {
            Some(b) if b.starts_with('/') => norm_path(&format!("{b}/{raw}")),
            _ => raw.to_string(),
        })
    }

    fn snapshot(p: &Proc, tgid: u32) -> Value {
        let mut m = Map::new();
        m.insert("uid".into(), json!(p.uid));
        m.insert("pid".into(), json!(tgid));
        for (k, v) in [("name", &p.name), ("path", &p.path), ("cmd_line", &p.cmd_line),
                       ("parent_uid", &p.parent_uid)] {
            if let Some(v) = v {
                m.insert(k.into(), json!(v));
            }
        }
        Value::Object(m)
    }

    /// Normalize one raw event. Returns None for events that are dropped (unknown syscall,
    /// fd-only variants without a path, ground-truth markers).
    pub fn normalize(&mut self, r: &RawEvent) -> Option<Value> {
        let denied_before_entry = r.sc & SC_DENIED_BEFORE_ENTRY != 0;
        let sp = spec(r.sc & !SC_DENIED_BEFORE_ENTRY)?;
        // Container-runtime plumbing (e.g. `runc init` joining namespaces for `docker exec`)
        // runs inside the watched cgroup before the real command starts. It is not the
        // workload, but its final exec IS the workload starting, so keep execs.
        if cstr(&r.comm).starts_with("runc") && sp.kind != Kind::Exec {
            self.dropped_runtime += 1;
            return None;
        }
        let t0 = *self.t0_ns.get_or_insert(r.ts_ns);
        let time = self.epoch_ms(r.ts_ns);
        self.last_epoch_ms = self.last_epoch_ms.max(time);
        let t_us = (r.ts_ns.saturating_sub(t0) / 1000) as i64;

        let (status, errno) = match sp.kind {
            Kind::Terminate => ("Success", None),
            _ if r.ret == RET_UNFINISHED => ("Failure", Some("UNFINISHED".to_string())),
            _ if r.ret < 0 => {
                let e = errno_name(-r.ret);
                (if e == "EINPROGRESS" { "Pending" } else { "Failure" }, Some(e))
            }
            _ => ("Success", None),
        };
        let mut unm = Map::new();
        unm.insert("t_us".into(), json!(t_us));
        unm.insert("syscall".into(), json!(sp.name));
        if denied_before_entry {
            // Rejected before the syscall started (seccomp); args recovered from registers.
            unm.insert("denied_before_entry".into(), json!(true));
        }
        let mut extra = Map::new();
        let path_raw = cstr(&r.path);
        let path2_raw = cstr(&r.path2);

        let (class, act_id, act_name): (u32, u32, &str) = match sp.kind {
            Kind::Open => (1001, 14, "Open"),
            Kind::Stat | Kind::Chdir => (1001, 8, "Get Attributes"),
            Kind::Access => (1001, 9, "Get Security"),
            Kind::Delete => (1001, 4, "Delete"),
            Kind::Rename => (1001, 5, "Rename"),
            Kind::Create => (1001, 1, "Create"),
            Kind::SetSecurity => (1001, 7, "Set Security"),
            Kind::Mount => (1001, 12, "Mount"),
            Kind::Unmount => (1001, 13, "Unmount"),
            Kind::Exec => (1007, 1, "Launch"),
            Kind::Fork => (1007, 99, "Fork"),
            Kind::Signal => (1007, 99, "Signal"),
            Kind::SetUid => (1007, 5, "Set User ID"),
            Kind::Trace => (1007, 99, "Trace"),
            Kind::Namespace => (1007, 99, "Namespace Change"),
            Kind::Bpf => (1007, 99, "BPF"),
            Kind::Terminate => (1007, 2, "Terminate"),
            Kind::Connect => (4001, 1, "Open"),
        };

        match sp.kind {
            Kind::Open | Kind::Stat | Kind::Access | Kind::Delete | Kind::Rename | Kind::Create
            | Kind::Chdir | Kind::SetSecurity | Kind::Mount | Kind::Unmount => {
                let dirfd = sp.dirfd.map(|i| r.a[i]);
                let path = self.resolve(r, &path_raw, dirfd)?;
                if path.starts_with(MARK_PREFIX) {
                    self.phases.push((path[MARK_PREFIX.len()..].to_string(), time));
                    return None;
                }
                let mut file = json!({ "path": path });
                if matches!(sp.kind, Kind::Rename | Kind::Mount) || (sp.kind == Kind::Create && !path2_raw.is_empty()) {
                    let p2 = if sp.kind == Kind::Rename {
                        self.resolve(r, &path2_raw, sp.dirfd2.map(|i| r.a[i]))
                    } else {
                        Some(path2_raw.clone())
                    };
                    if let Some(p2) = p2.filter(|s| !s.is_empty()) {
                        file["new_path"] = json!(p2);
                    }
                }
                if sp.kind == Kind::Open {
                    if let Some(fi) = sp.flags {
                        let (names, access) = open_flags(r.a[fi]);
                        unm.insert("flags".into(), json!(names));
                        unm.insert("access".into(), json!(access));
                    }
                    if status == "Success" && r.ret >= 0 {
                        let fd = r.ret as i32;
                        self.proc_for(r).fds.insert(fd, path.clone());
                    }
                }
                if sp.kind == Kind::Chdir && status == "Success" {
                    self.proc_for(r).cwd = Some(path.clone());
                }
                extra.insert("file".into(), file);
            }
            Kind::Exec => {
                let dirfd = sp.dirfd.map(|i| r.a[i]);
                let path = self.resolve(r, &path_raw, dirfd).unwrap_or_default();
                let argv: Vec<String> = (0..r.argc as usize).map(|i| cstr(&r.argv[i])).collect();
                let tgid = r.tgid;
                if status == "Success" {
                    let p = self.proc_for(r);
                    p.path = Some(path.clone());
                    p.name = Some(path.rsplit('/').next().unwrap_or(&path).to_string());
                    p.cmd_line = Some(if argv.is_empty() { path.clone() } else { argv.join(" ") });
                    let snap = Self::snapshot(p, tgid);
                    extra.insert("process".into(), snap);
                } else {
                    extra.insert("file".into(), json!({ "path": path }));
                }
            }
            Kind::Connect => {
                let (ep, fam) = parse_sockaddr(&r.path2)?;
                if fam == "unix" {
                    extra.insert("dst_endpoint".into(), ep);
                    extra.insert("connection_info".into(), json!({"protocol_name": "unix"}));
                } else {
                    extra.insert("dst_endpoint".into(), ep);
                }
            }
            Kind::Namespace => {
                let v = if r.sc == 51 { r.a[1] } else { r.a[0] };
                unm.insert("flags".into(), json!(ns_flags(v)));
            }
            Kind::Trace => {
                unm.insert("request".into(), json!(r.a[0]));
                extra.insert("process".into(), json!({ "pid": r.a[1] as i32 }));
            }
            Kind::Signal => {
                let (target, sig) = if r.sc == 66 { (r.a[1], r.a[2]) } else { (r.a[0], r.a[1]) };
                extra.insert("process".into(), json!({ "pid": target as i32 }));
                unm.insert("signal".into(), json!(signal_name(sig)));
            }
            Kind::Fork => {
                if r.ret > 0 {
                    unm.insert("child_pid_ns".into(), json!(r.ret));
                }
            }
            Kind::Bpf => {
                unm.insert("cmd".into(), json!(r.a[0]));
            }
            Kind::SetUid => {
                unm.insert("target_id".into(), json!(r.a[0] as i32));
            }
            Kind::Terminate => {
                let code = r.ret as i32;
                unm.insert("exit_code".into(), json!((code >> 8) & 0xff));
                if code & 0x7f != 0 {
                    unm.insert("killed_by".into(), json!(signal_name((code & 0x7f) as u64)));
                }
            }
        }

        let tgid = r.tgid;
        let user = self.user_name(r.uid, tgid);
        let p = self.proc_for(r);
        let actor = Self::snapshot(p, tgid);
        if sp.kind == Kind::Terminate {
            extra.insert("process".into(), actor.clone());
            self.procs.remove(&tgid);
        }
        let mut ev = json!({
            "time": time,
            "class_uid": class,
            "class_name": match class { 1001 => "File System Activity", 1007 => "Process Activity", _ => "Network Activity" },
            "activity_id": act_id,
            "activity_name": act_name,
            "status": status,
            "actor": { "process": actor, "user": { "name": user } },
            "unmapped": Value::Object(unm),
        });
        if let Some(e) = errno {
            ev["status_detail"] = json!(e);
        }
        for (k, v) in extra {
            ev[k] = v;
        }
        Some(ev)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_paths() {
        assert_eq!(norm_path("/a/./b//c/../d"), "/a/b/d");
        assert_eq!(norm_path("/.."), "/");
        assert_eq!(norm_path("x/../y"), "y");
    }

    #[test]
    fn parses_inet_sockaddr() {
        let mut b = [0u8; 28];
        b[0..2].copy_from_slice(&2u16.to_ne_bytes());
        b[2..4].copy_from_slice(&2375u16.to_be_bytes());
        b[4..8].copy_from_slice(&[10, 66, 0, 20]);
        let (ep, fam) = parse_sockaddr(&b).unwrap();
        assert_eq!(fam, "inet");
        assert_eq!(ep["ip"], "10.66.0.20");
        assert_eq!(ep["port"], 2375);
    }

    #[test]
    fn open_flags_access() {
        assert_eq!(open_flags(0o2000000).1, "read");
        assert_eq!(open_flags(0o1101).1, "write");
        assert!(open_flags(0o100 | 1).0.contains("O_CREAT"));
    }

    #[test]
    fn ns_flag_names() {
        assert_eq!(ns_flags(0x1000_0000), "CLONE_NEWUSER");
    }
}
