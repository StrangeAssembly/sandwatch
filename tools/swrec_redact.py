#!/usr/bin/env python3
"""Redact identifying details from a .swrec recording and re-seal its hash chain.

    swrec_redact.py IN.swrec.gz OUT.swrec.gz [--term TEXT ...]

Real agent sessions record paths and command lines that can identify the person who made
them. This rewrites every string value in the recording:

  - UUIDs (account, organization, session and file ids)     -> uuid-0001, uuid-0002, ...
  - names under .claude/{skills,plugins}/synced/<id>/       -> item-01, item-02, ...
  - home directories of real accounts on this machine       -> /home/user
  - this machine's user name and host name, and every --term -> <redacted>
  - email addresses                                         -> <email>
  - credential-looking assignments (api_key=..., token: ...) -> <name>=<redacted>

Replacements are consistent within a file (the same UUID always becomes the same
placeholder), so the recording stays analyzable. The hash chain is recomputed and the
header gains a `redaction` block saying what was done; the original's final hash is kept in
it so the redacted copy can be tied back to an original that stays private.
Standard library only.
"""
import argparse
import gzip
import hashlib
import json
import os
import re
import socket
import sys

ZERO_HASH = "0" * 64
# Hex lookarounds, not \b: ids are often glued to "_" (e.g. "<org>_<account>"), and "_" is a
# word character, so \b would miss them.
UUID = re.compile(r"(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-f])", re.I)
# Runs of 8+ hex digits: redacted inside an agent's state directory (.claude/...), where
# they are account, session and job ids or hashes of them.
HEXRUN = re.compile(r"(?<![0-9a-f])[0-9a-f]{8,}(?![0-9a-f])", re.I)
STATE_DIR = ".claude/"
SYNCED = re.compile(r"(\.claude/(?:skills|plugins)/synced/[^/\"]+/)([^/\"]+)")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
SECRET = re.compile(r"(?i)\b([A-Za-z0-9_]*(?:api[_-]?key|token|secret|password|passwd|bearer))(\s*[=:]\s*)[^\s\"]{6,}")
ANTHROPIC_KEY = re.compile(r"sk-ant-[A-Za-z0-9_-]+")
GENERIC_USERS = {"agent", "node", "root", "user"}


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def local_homes():
    homes = []
    try:
        with open("/etc/passwd", encoding="utf-8") as f:
            for line in f:
                p = line.split(":")
                if len(p) > 5 and re.fullmatch(r"/home/[^/]+", p[5]) and p[0] not in GENERIC_USERS:
                    homes.append(p[5])
    except OSError:
        pass
    return homes


class Redactor:
    def __init__(self, terms, known_ids=()):
        self.uuids, self.items, self.count = {}, {}, 0
        self.homes = [re.compile(re.escape(h) + r"(?=/|\b)") for h in local_homes()]
        self.terms = [re.compile(r"\b" + re.escape(t) + r"\b") for t in terms if t and t not in GENERIC_USERS]
        # Short forms of ids seen anywhere in the file (tools print the first group of a
        # UUID, e.g. job directories named after a session id).
        shorts = sorted({u.split("-")[0].lower() for u in known_ids})
        self.short = re.compile(r"(?<![0-9a-f])(" + "|".join(shorts) + r")(?![0-9a-f])", re.I) if shorts else None

    def _hex(self, m):
        k = m.group(0).lower()
        return self.uuids.setdefault(k, f"id-{len(self.uuids) + 1:04d}")

    def _sub(self, pattern, repl, s):
        s2, n = pattern.subn(repl, s)
        self.count += n
        return s2

    def _uuid(self, m):
        k = m.group(0).lower()
        return self.uuids.setdefault(k, f"uuid-{len(self.uuids) + 1:04d}")

    def _item(self, m):
        k = m.group(2)
        if re.fullmatch(r"item-\d+|uuid-\d+.*|\.staging", k):
            return m.group(0)
        return m.group(1) + self.items.setdefault(k, f"item-{len(self.items) + 1:02d}")

    def text(self, s):
        s = self._sub(ANTHROPIC_KEY, "<redacted>", s)
        s = self._sub(SECRET, r"\1\2<redacted>", s)
        s = self._sub(EMAIL, "<email>", s)
        for h in self.homes:
            s = self._sub(h, "/home/user", s)
        for t in self.terms:
            s = self._sub(t, "<redacted>", s)
        s = self._sub(UUID, self._uuid, s)
        if self.short:
            s = self._sub(self.short, self._hex, s)
        s = self._sub(SYNCED, self._item, s)
        i = s.find(STATE_DIR)
        if i >= 0:
            j = i + len(STATE_DIR)
            s = s[:j] + self._sub(HEXRUN, self._hex, s[j:])
        return s

    def value(self, v):
        if isinstance(v, str):
            return self.text(v)
        if isinstance(v, list):
            return [self.value(x) for x in v]
        if isinstance(v, dict):
            return {k: (x if k in ("hash", "prev_hash") else self.value(x)) for k, x in v.items()}
        return v


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("src")
    ap.add_argument("dst")
    ap.add_argument("--term", action="append", default=[], help="extra text to redact (repeatable)")
    a = ap.parse_args()
    if os.path.abspath(a.src) == os.path.abspath(a.dst):
        sys.exit("refusing to overwrite the original; write to a new file")

    terms = a.term + [os.environ.get("USER", ""), socket.gethostname()]
    opener = lambda p, m: gzip.open(p, m, encoding="utf-8") if p.endswith(".gz") else open(p, m, encoding="utf-8")
    with opener(a.src, "rt") as f:
        raw = [l for l in f if l.strip()]
    known = set(UUID.findall("\n".join(raw)))  # first pass: every full id in the file
    red = Redactor(terms, known)
    lines = [json.loads(l) for l in raw]
    if not lines or lines[0].get("record_type") != "header":
        sys.exit("not a recording (first line is not a header)")
    original_final = lines[-1].get("hash")

    out, prev = [], ZERO_HASH
    for i, obj in enumerate(lines):
        obj = red.value(obj)
        obj.pop("hash", None)
        if i == 0:
            obj["redaction"] = {
                "tool": "tools/swrec_redact.py",
                "version": 1,
                "rules": ["uuid", "synced-item-names", "local-homes", "user-host-terms", "email", "secrets"],
                "source_final_hash": original_final,
            }
        if obj.get("record_type") == "footer":
            obj["final_event_hash"] = prev
        obj["prev_hash"] = prev
        h = hashlib.sha256((prev + canonical(obj)).encode("utf-8")).hexdigest()
        obj["hash"] = h
        prev = h
        out.append(canonical(obj))
    with opener(a.dst, "wt") as f:
        f.write("\n".join(out) + "\n")
    print(f"{a.dst}: {len(lines)} lines, {red.count} replacements, "
          f"{len(red.uuids)} distinct ids, {len(red.items)} synced item names")


if __name__ == "__main__":
    main()
