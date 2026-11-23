#!/usr/bin/env python3
"""Syscall storm for sensor load testing: the pattern of a big `pip install`.

    syscall_storm.py [workers] [iterations]

Each worker repeatedly stats files that exist and files that don't (ENOENT, like an import
system or package manager probing paths), and opens/closes a file. Prints the number of
syscalls issued so the sensor's event count and drop counters can be compared with it.
"""
import os
import sys
import tempfile
import time
from multiprocessing import Process


def worker(root, n):
    present = os.path.join(root, "present.txt")
    for i in range(n):
        os.stat(present)
        try:
            os.stat(os.path.join(root, f"missing-{i % 997}.py"))
        except FileNotFoundError:
            pass
        with open(present, "rb"):
            pass


def main():
    workers = int(sys.argv[1]) if len(sys.argv) > 1 else 4
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 50_000
    with tempfile.TemporaryDirectory() as root:
        open(os.path.join(root, "present.txt"), "w").close()
        t = time.time()
        ps = [Process(target=worker, args=(root, n)) for _ in range(workers)]
        for p in ps:
            p.start()
        for p in ps:
            p.join()
        dt = time.time() - t
    total = workers * n * 3
    print(f"storm: {workers} workers x {n} iterations = {total} syscalls in {dt:.2f}s "
          f"({total / dt:,.0f}/s)", flush=True)


if __name__ == "__main__":
    main()
