#!/usr/bin/env python3
"""Convert lab strace output into a labeled, hash-chained .swrec recording.

    swrec_convert.py --raw X.strace --env X.env.json --manifest manifest.json \
                     --scenario escape-probe --seed 1 --out X.swrec

Expected strace flags: -f -ttt -T -yy  (pid prefix, epoch timestamps, durations, fd decoding).
Standard library only.
"""
import argparse
import gzip
import hashlib
import io
import os
import posixpath
import json
import re
import sys
from datetime import datetime, timezone

MARK_PREFIX = "/.sandwatch-mark/"
ZERO_HASH = "0" * 64

LINE_RE = re.compile(r"^(\d+)\s+(\d+\.\d+)\s+(.*)$")
CALL_RE = re.compile(r"^(\w+)\((.*)\)\s+=\s+(.+?)(?:\s+<(\d+\.\d+)>)?$")
RET_RE = re.compile(r"^(-?\d+|\?|0x[0-9a-fA-F]+)(?:<[^>]*>)?(?:\s+(E[A-Z0-9]+|UNFINISHED)\b)?")
QSTR_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
UNFINISHED = "<unfinished ...>"
RESUMED_RE = re.compile(r"^<\.\.\. (\w+) resumed>\s?(.*)$")
EXIT_RE = re.compile(r"^\+\+\+ (?:exited with (\d+)|killed by (\w+)).*\+\+\+$")

# syscall -> (class_uid, activity_id, activity_name)
FILE = 1001
PROC = 1007
NET = 4001
FILE_MAP = {
    **{s: (FILE, 14, "Open") for s in ("open", "openat", "openat2", "creat")},
    **{s: (FILE, 8, "Get Attributes") for s in (
        "stat", "lstat", "fstat", "newfstatat", "fstatat64", "statx", "readlink",
        "readlinkat", "statfs", "chdir", "getxattr", "lgetxattr", "listxattr",
        "llistxattr", "chroot", "uselib", "inotify_add_watch", "fanotify_mark",
        "name_to_handle_at", "getdents64")},
    **{s: (FILE, 9, "Get Security") for s in ("access", "faccessat", "faccessat2")},
    **{s: (FILE, 1, "Create") for s in (
        "mkdir", "mkdirat", "symlink", "symlinkat", "link", "linkat", "mknod", "mknodat")},
    **{s: (FILE, 4, "Delete") for s in ("unlink", "unlinkat", "rmdir")},
    **{s: (FILE, 5, "Rename") for s in ("rename", "renameat", "renameat2")},
    **{s: (FILE, 6, "Set Attributes") for s in (
        "utime", "utimes", "utimensat", "futimesat", "truncate", "setxattr",
        "lsetxattr", "removexattr", "lremovexattr")},
    **{s: (FILE, 7, "Set Security") for s in (
        "chmod", "fchmodat", "fchmodat2", "chown", "lchown", "fchownat")},
    "mount": (FILE, 12, "Mount"),
    "umount2": (FILE, 13, "Unmount"),
}
PROC_MAP = {
    "execve": (PROC, 1, "Launch"),
    "execveat": (PROC, 1, "Launch"),
    **{s: (PROC, 99, "Fork") for s in ("clone", "clone3", "fork", "vfork")},
    **{s: (PROC, 5, "Set User ID") for s in (
        "setuid", "setgid", "setreuid", "setregid", "setresuid", "setresgid",
        "setfsuid", "setfsgid", "setgroups")},
    **{s: (PROC, 99, "Signal") for s in ("kill", "tkill", "tgkill")},
    "ptrace": (PROC, 99, "Trace"),
    "capget": (PROC, 99, "Capability Query"),
    "capset": (PROC, 99, "Capability Set"),
    "unshare": (PROC, 99, "Namespace Change"),
    "setns": (PROC, 99, "Namespace Change"),
    "bpf": (PROC, 99, "BPF"),
    "prctl": (PROC, 99, "Process Control"),
}
NET_MAP = {
    "connect": (NET, 1, "Open"),
    "sendto": (NET, 6, "Traffic"),
    "bind": (NET, 7, "Listen"),
    "listen": (NET, 7, "Listen"),
    "accept": (NET, 99, "Accept"),
    "accept4": (NET, 99, "Accept"),
}
CLASS_NAMES = {FILE: "File System Activity", PROC: "Process Activity", NET: "Network Activity"}
# Noise we deliberately drop: credential/identity reads, waits, exits (we use +++ lines).
SKIP = {"wait4", "waitid", "exit", "exit_group", "getuid", "geteuid", "getgid", "getegid",
        "getresuid", "getresgid", "getgroups", "socket", "socketpair", "getsockopt",
        "setsockopt", "getsockname", "getpeername", "shutdown", "recvfrom", "recvmsg",
        "recvmmsg", "sendmsg", "sendmmsg", "arch_prctl", "rt_sigreturn", "set_tid_address"}
WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")


def unescape(s):
    try:
        return s.encode("latin-1", "backslashreplace").decode("unicode_escape") \
                .encode("latin-1", "replace").decode("utf-8", "replace")
    except Exception:
        return s


DIRFD_RE = re.compile(r"^\s*(?:\d+|AT_FDCWD)<([^>]*)>")
RET_PATH_RE = re.compile(r"^\d+<(/[^>]*)>")


def resolve_path(args, path, ret):
    """Absolute, normalized path for a filename argument.

    Absolute arguments are kept as written (so /proc/self/... stays /proc/self/...). A
    relative name is joined onto the directory fd / cwd that strace decorates the first
    argument with (-yy), falling back to the resolved path decorating a returned fd.
    Without this, `openat(5</home/agent/.aws>, "credentials")` would be recorded as just
    "credentials".
    """
    if path.startswith("/"):
        return posixpath.normpath(path)
    d = DIRFD_RE.match(args)
    if d and d.group(1).startswith("/"):
        return posixpath.normpath(posixpath.join(d.group(1), path))
    m = RET_PATH_RE.match(ret.strip())
    if m:
        return m.group(1)
    return path


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def chain(obj, prev):
    obj = {k: v for k, v in obj.items() if k != "hash"}
    obj["prev_hash"] = prev
    obj["hash"] = hashlib.sha256((prev + canonical(obj)).encode("utf-8")).hexdigest()
    return obj


def parse_ret(ret):
    m = RET_RE.match(ret.strip())
    if not m:
        return None, None
    val, errno = m.group(1), m.group(2)
    return val, errno


def endpoint(args):
    m = re.search(r'sun_path="((?:[^"\\]|\\.)*)"', args)
    if m:
        return {"path": unescape(m.group(1))}, "unix"
    m = re.search(r'sin_port=htons\((\d+)\).*?sin_addr=inet_addr\("([^"]+)"\)', args)
    if m:
        return {"ip": m.group(2), "port": int(m.group(1))}, None
    m = re.search(r'sin6_port=htons\((\d+)\).*?inet_pton\(AF_INET6,\s*"([^"]+)"', args)
    if m:
        return {"ip": m.group(2), "port": int(m.group(1))}, None
    return None, None


def proto_from_fd(args):
    m = re.match(r"\d+<(TCP|UDP|TCPv6|UDPv6|UNIX|UNIX-STREAM|UNIX-DGRAM)", args)
    if not m:
        return None
    p = m.group(1).lower()
    return "unix" if p.startswith("unix") else p.replace("v6", "")


class Converter:
    def __init__(self, session_id):
        self.session_id = session_id
        self.procs = {}          # pid -> process dict
        self.pending = {}        # pid -> (ts, text) for unfinished calls
        self.events = []
        self.phases = []
        self.t0 = None
        self.t_last = None
        self.skipped_lines = 0

    # --- process identity -------------------------------------------------
    def _uid(self, pid, start_us):
        h = hashlib.sha256(f"{self.session_id}|{pid}|{start_us}".encode()).hexdigest()
        return h[:16]

    def proc(self, pid, ts, parent=None):
        p = self.procs.get(pid)
        if p is None:
            start_us = int(ts * 1e6)
            p = {"uid": self._uid(pid, start_us), "pid": pid, "name": None, "path": None,
                 "cmd_line": None}
            if parent is not None:
                p["parent_uid"] = parent["uid"]
                p["name"], p["path"], p["cmd_line"] = parent["name"], parent["path"], parent["cmd_line"]
            self.procs[pid] = p
        return p

    def snapshot(self, p):
        return {k: v for k, v in p.items() if v is not None}

    # --- event building ---------------------------------------------------
    def emit(self, ts, pid, cls, act_id, act_name, status, errno, extra, unmapped):
        p = self.proc(pid, ts)
        ev = {
            "record_type": "event",
            "time": int(ts * 1000),
            "class_uid": cls,
            "class_name": CLASS_NAMES[cls],
            "activity_id": act_id,
            "activity_name": act_name,
            "status": status,
            "actor": {"process": self.snapshot(p), "user": {"name": "agent"}},
            "unmapped": {"t_us": int((ts - self.t0) * 1e6), **unmapped},
        }
        if errno:
            ev["status_detail"] = errno
        ev.update(extra)
        self.events.append(ev)

    def feed(self, line):
        m = LINE_RE.match(line.rstrip("\n"))
        if not m:
            self.skipped_lines += 1
            return
        pid, ts, body = int(m.group(1)), float(m.group(2)), m.group(3)
        if self.t0 is None:
            self.t0 = ts
        self.t_last = ts

        if body.endswith(UNFINISHED):
            self.pending[pid] = (ts, body[: -len(UNFINISHED)].rstrip())
            return
        r = RESUMED_RE.match(body)
        if r:
            start = self.pending.pop(pid, None)
            if start is None:
                self.skipped_lines += 1
                return
            ts, head = start
            body = head + r.group(2)

        if body.startswith("+++"):
            # A call still pending when its process died never returned (e.g. a connect
            # killed by `timeout`). Keep it as a failed attempt instead of dropping it.
            stuck = self.pending.pop(pid, None)
            if stuck is not None:
                s_ts, head = stuck
                self.feed(f"{pid} {s_ts:.6f} {head}) = -1 UNFINISHED (never returned)")
            e = EXIT_RE.match(body)
            p = self.proc(pid, ts)
            code = e.group(1) if e else None
            self.emit(ts, pid, PROC, 2, "Terminate", "Success", None,
                      {"process": self.snapshot(p)},
                      {k: v for k, v in (("exit_code", int(code) if code else None),
                                         ("killed_by", e.group(2) if e else None)) if v is not None})
            return
        if body.startswith("---"):
            return  # signal delivery notices

        c = CALL_RE.match(body)
        if not c:
            self.skipped_lines += 1
            return
        name, args, ret, dur = c.group(1), c.group(2), c.group(3), c.group(4)
        if name in SKIP:
            return
        val, errno = parse_ret(ret)
        if val is None:
            self.skipped_lines += 1
            return
        if errno == "EINPROGRESS":
            status = "Pending"
        elif errno or val == "-1":
            status = "Failure"
        else:
            status = "Success"
        unm = {"syscall": name}
        if dur:
            unm["duration_us"] = int(float(dur) * 1e6)
        strings = [unescape(s) for s in QSTR_RE.findall(args)]

        # ground-truth markers: record and drop
        if strings and strings[0].startswith(MARK_PREFIX):
            self.phases.append({"name": strings[0][len(MARK_PREFIX):], "time": int(ts * 1000)})
            return

        if name in PROC_MAP:
            cls, aid, aname = PROC_MAP[name]
            p = self.proc(pid, ts)
            extra = {}
            if name in ("execve", "execveat"):
                if status == "Success" and strings:
                    path = strings[0]
                    argv_m = re.search(r"\[(.*?)\](?:,|$)", args)
                    argv = [unescape(s) for s in QSTR_RE.findall(argv_m.group(1))] if argv_m else []
                    p["path"] = path
                    p["name"] = path.rsplit("/", 1)[-1]
                    p["cmd_line"] = " ".join(argv) if argv else path
                else:
                    extra["file"] = {"path": strings[0]} if strings else {}
                    aname = "Launch"
                extra["process"] = self.snapshot(p)
            elif aname == "Fork":
                # clone/clone3 creating namespaces: report as a namespace change (same as
                # the live sensor), keeping the child process below.
                ns = re.findall(r"\bCLONE_NEW[A-Z]+\b", args)
                if ns:
                    aid, aname = 99, "Namespace Change"
                    unm["flags"] = "|".join(dict.fromkeys(ns))
                if status == "Success" and val.isdigit():
                    child = self.proc(int(val), ts, parent=p)
                    # With -f the child's first lines can be logged before the parent's
                    # clone() returns; fill in parent info if the child already existed.
                    child.setdefault("parent_uid", p["uid"])
                    for k in ("name", "path", "cmd_line"):
                        if child.get(k) is None:
                            child[k] = p.get(k)
                    extra["process"] = self.snapshot(child)
            elif aname == "Signal":
                tgt = re.match(r"\s*(-?\d+)", args)
                if tgt:
                    extra["process"] = {"pid": int(tgt.group(1))}
                sig = re.search(r"\b(SIG[A-Z0-9]+)\b", args)
                if sig:
                    unm["signal"] = sig.group(1)
            elif aname == "Trace":
                req = re.match(r"\s*(PTRACE_\w+)", args)
                if req:
                    unm["request"] = req.group(1)
            elif aname == "Namespace Change":
                unm["flags"] = args.strip()
            self.emit(ts, pid, cls, aid, aname, status, errno, extra, unm)
            return

        if name in NET_MAP:
            cls, aid, aname = NET_MAP[name]
            ep, proto = endpoint(args)
            if name == "sendto" and ep is None:
                return  # sendto on connected socket: no new destination info
            proto = proto or proto_from_fd(args)
            extra = {}
            if ep:
                extra["dst_endpoint" if name in ("connect", "sendto") else "src_endpoint"] = ep
            if proto:
                extra["connection_info"] = {"protocol_name": proto}
            self.emit(ts, pid, cls, aid, aname, status, errno, extra, unm)
            return

        cls, aid, aname = FILE_MAP.get(name, (FILE, 99, "Other"))
        if not strings and aid != 13:
            return  # fd-only variant (e.g. fstat on a descriptor): no path, skip
        extra = {"file": {"path": resolve_path(args, strings[0], ret)}} if strings else {}
        if aid in (5, 1) and len(strings) > 1:
            extra["file"]["new_path"] = strings[1]
            if not strings[1].startswith("/"):
                base = os.path.dirname(extra["file"]["path"]) if extra["file"]["path"] else ""
                extra["file"]["new_path"] = posixpath.normpath(posixpath.join(base or "/", strings[1]))
        if aid == 14:
            flags = re.search(r"\b(O_[A-Z_|]+(?:\|O_[A-Z_]+)*)", args)
            if flags:
                unm["flags"] = flags.group(1)
                unm["access"] = "write" if any(f in flags.group(1) for f in WRITE_FLAGS) else "read"
        if name == "mount" and len(strings) > 1:
            extra["file"]["new_path"] = strings[1]
        self.emit(ts, pid, cls, aid, aname, status, errno, extra, unm)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--raw", required=True)
    ap.add_argument("--env", required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    manifest = json.load(open(a.manifest, encoding="utf-8"))
    scen = next((s for s in manifest["scenarios"] if s["id"] == a.scenario), None)
    if scen is None:
        sys.exit(f"scenario {a.scenario!r} not in manifest")
    env = json.load(open(a.env, encoding="utf-8"))
    session_id = f"{a.scenario}-s{a.seed}"

    conv = Converter(session_id)
    with open(a.raw, encoding="utf-8", errors="replace") as f:
        for line in f:
            conv.feed(line)
    conv.events.sort(key=lambda e: (e["time"], e["unmapped"]["t_us"]))

    start_ms = int(conv.t0 * 1000) if conv.t0 else 0
    dur_ms = int((conv.t_last - conv.t0) * 1000) if conv.t0 else 0
    labels = {
        "class": scen["class"],
        "scenario": scen["id"],
        "variant": a.seed,
        "pace": scen.get("pace", "natural"),
        "description": scen["description"],
        "attack_techniques": scen.get("attack_techniques", []),
        "expected_detections": scen.get("expected_detections", []),
        "synthetic": True,
    }
    if scen.get("forbidden_detections"):
        labels["forbidden_detections"] = scen["forbidden_detections"]
    if scen.get("hard_negative"):
        labels["hard_negative"] = True
    if scen.get("notes"):
        labels["notes"] = scen["notes"]
    header = {
        "record_type": "header",
        "format": "sandwatch-recording",
        "format_version": "0.1",
        "session": {
            "id": session_id,
            "recorded_at": env.get("recorded_at") or datetime.now(timezone.utc).isoformat(),
            "start_time": start_ms,
            "duration_ms": dur_ms,
            "event_count": len(conv.events),
        },
        "sensor": {
            "name": "strace",
            "version": env.get("strace_version"),
            "fidelity": "syscall-level via ptrace; file/process/network/creds syscalls; "
                        "no read/write payloads",
        },
        "environment": {
            "kernel": env.get("kernel"),
            "arch": env.get("arch"),
            "runtime": "docker",
            "container_user": env.get("container_user"),
            "network": "isolated lab network, no internet",
            "scenario_exit_code": env.get("scenario_exit_code"),
        },
        "labels": labels,
        "ground_truth": {"phases": conv.phases},
        "schema": {"events": "ocsf-aligned-subset", "ocsf_version": "1.3.0"},
    }

    prev = ZERO_HASH
    if a.out.endswith(".gz"):
        # mtime=0 keeps the compressed bytes reproducible for identical content
        out_ctx = io.TextIOWrapper(gzip.GzipFile(a.out, "wb", mtime=0), encoding="utf-8", newline="\n")
    else:
        out_ctx = open(a.out, "w", encoding="utf-8", newline="\n")
    with out_ctx as out:
        h = chain(header, prev)
        out.write(canonical(h) + "\n")
        prev = h["hash"]
        for i, ev in enumerate(conv.events, 1):
            ev["seq"] = i
            h = chain(ev, prev)
            out.write(canonical(h) + "\n")
            prev = h["hash"]
        footer = chain({"record_type": "footer", "event_count": len(conv.events),
                        "final_event_hash": prev}, prev)
        out.write(canonical(footer) + "\n")

    print(f"{session_id}: {len(conv.events)} events, {len(conv.phases)} phases, "
          f"{dur_ms} ms, {conv.skipped_lines} unparsed lines")


if __name__ == "__main__":
    main()
