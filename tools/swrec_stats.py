#!/usr/bin/env python3
"""Summarize .swrec recordings: volume, tempo, failure ratio, sensitive-target breadth.

    swrec_stats.py recordings/*.swrec

This is a sanity check on the recordings, NOT a detector. It shows whether attack and benign
sessions differ on the raw features detection rules will build on. Standard library only.
"""
import gzip
import json
import re
import sys
from collections import deque

SENSITIVE = re.compile(
    r"docker\.sock|containerd\.sock|crio\.sock|podman\.sock|/serviceaccount/|"
    r"/proc/1/(root|environ|cgroup|sched|mountinfo)|/proc/\d+/environ|core_pattern|"
    r"release_agent|/\.aws/|/\.ssh/|/\.kube/|/\.docker/config|\.git-credentials|\.netrc|"
    r"/etc/(shadow|gshadow|sudoers)|/dev/(mem|kmsg)|/proc/kcore|(^|/)\.env$|/\.dockerenv|"
    r"/run/secrets|/var/lib/kubelet|admin\.conf|k3s\.yaml|/sys/kernel/(debug|security)"
)
WINDOW_US = 2_000_000


def load(path):
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as f:
        lines = [json.loads(l) for l in f if l.strip()]
    header = lines[0]
    footer = next((l for l in lines if l.get("record_type") == "footer"), {})
    # Live recordings put duration/counts in the footer; merge them into the session
    # metadata the way the Rust reader does (header values win when present).
    session = header.setdefault("session", {})
    for k in ("duration_ms", "event_count", "start_time"):
        if not session.get(k) and footer.get(k) is not None:
            session[k] = footer[k]
    return header, [l for l in lines if l.get("record_type") == "event"]


def stats(header, events):
    procs = {e["actor"]["process"]["uid"] for e in events}
    launches = sum(1 for e in events if e["class_uid"] == 1007 and e["activity_id"] == 1)
    fileish = [e for e in events if e["class_uid"] in (1001, 4001)]
    fails = sum(1 for e in fileish if e["status"] == "Failure")
    sens = [(e["unmapped"]["t_us"], e["file"]["path"], e["status"]) for e in events
            if e.get("file", {}).get("path") and SENSITIVE.search(e["file"]["path"])]
    sens_targets = {p for _, p, _ in sens}
    sens_fail = {p for _, p, s in sens if s == "Failure"}
    # peak number of DISTINCT sensitive targets touched within any 2-second window
    peak, win, counts = 0, deque(), {}
    for t, p, _ in sens:
        win.append((t, p)); counts[p] = counts.get(p, 0) + 1
        while win and t - win[0][0] > WINDOW_US:
            _, old = win.popleft(); counts[old] -= 1
            if counts[old] == 0:
                del counts[old]
        peak = max(peak, len(counts))
    dsts = {(e["dst_endpoint"].get("ip"), e["dst_endpoint"].get("port"))
            for e in events if e["class_uid"] == 4001 and "ip" in e.get("dst_endpoint", {})
            and e["dst_endpoint"].get("port") != 53}
    meta = any(e.get("dst_endpoint", {}).get("ip") in ("169.254.169.254", "10.66.0.20")
               and e["dst_endpoint"].get("port") == 80 for e in events)
    return {
        "events": len(events),
        "procs": len(procs),
        "launch": launches,
        "secs": header["session"].get("duration_ms", 0) / 1000,
        "fail%": 100 * fails / len(fileish) if fileish else 0,
        "sens": len(sens_targets),
        "sensFail": len(sens_fail),
        "peak2s": peak,
        "netDst": len(dsts),
        "meta": "yes" if meta else "-",
    }


def main(paths):
    rows = []
    for p in sorted(paths):
        h, ev = load(p)
        lab = h["labels"]
        kind = lab["class"] + ("*" if lab.get("hard_negative") else "")
        rows.append((h["session"]["id"], kind, lab.get("pace", ""), stats(h, ev)))
    cols = ["events", "procs", "launch", "secs", "fail%", "sens", "sensFail", "peak2s", "netDst", "meta"]
    print(f"{'session':<24} {'class':<8} {'pace':<8} " + " ".join(f"{c:>8}" for c in cols))
    print("-" * (42 + 9 * len(cols)))
    for sid, kind, pace, s in sorted(rows, key=lambda r: (r[1].rstrip('*') != "attack", r[0])):
        vals = []
        for c in cols:
            v = s[c]
            vals.append(f"{v:>8.1f}" if isinstance(v, float) else f"{v:>8}")
        print(f"{sid:<24} {kind:<8} {pace:<8} " + " ".join(vals))
    print("\n* = hard negative (benign, deliberately attack-like)")
    print("sens = distinct sensitive targets touched; peak2s = most distinct sensitive targets in any 2 s;")
    print("netDst = distinct non-DNS destinations; meta = touched a metadata endpoint")


if __name__ == "__main__":
    main(sys.argv[1:])
