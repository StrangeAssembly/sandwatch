#!/usr/bin/env python3
"""Verify the hash chain and structure of .swrec recordings.

    swrec_verify.py recordings/*.swrec

Exit code 0 if every file verifies, 1 otherwise. Standard library only.
"""
import gzip
import hashlib
import json
import sys

ZERO_HASH = "0" * 64


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def verify(path):
    opener = gzip.open if path.endswith(".gz") else open
    prev = ZERO_HASH
    n_events = 0
    header = footer = None
    with opener(path, "rt", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            if not line.strip():
                continue  # blank lines are ignored (as by the Rust reader)
            obj = json.loads(line)
            stored = obj.pop("hash", None)
            if obj.get("prev_hash") != prev:
                return f"line {lineno}: prev_hash does not match previous line"
            calc = hashlib.sha256((prev + canonical(obj)).encode("utf-8")).hexdigest()
            if calc != stored:
                return f"line {lineno}: hash mismatch (content altered)"
            rt = obj.get("record_type")
            if lineno == 1:
                if rt != "header":
                    return "first line is not a header"
                header = obj
            elif rt == "event":
                if footer is not None:
                    return f"line {lineno}: event after footer"
                n_events += 1
                if obj.get("seq") != n_events:
                    return f"line {lineno}: seq {obj.get('seq')} != expected {n_events}"
            elif rt == "footer":
                if footer is not None:
                    return f"line {lineno}: duplicate footer"
                footer = obj
            else:
                return f"line {lineno}: unknown record_type {rt!r}"
            prev = stored
    if footer is None:
        return "missing footer (file truncated?)"
    if footer["event_count"] != n_events:
        return f"footer event_count {footer['event_count']} != {n_events} events"
    hc = header["session"].get("event_count")  # optional: live recordings put it in the footer
    if hc and hc != n_events:  # 0 / absent = "not known up front" (same as the Rust reader)
        return "header event_count does not match"
    return None


def main(paths):
    bad = 0
    for p in paths:
        try:
            err = verify(p)
        except (OSError, EOFError, ValueError, KeyError, TypeError, AttributeError) as e:
            # truncated gzip, invalid JSON/UTF-8, malformed header: a failure, not a crash
            err = f"unreadable: {type(e).__name__}: {e}"
        print(f"{'OK  ' if err is None else 'FAIL'}  {p}" + (f"  -- {err}" if err else ""))
        bad += err is not None
    print(f"\n{len(paths) - bad}/{len(paths)} recordings verified")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
