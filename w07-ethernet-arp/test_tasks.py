#!/usr/bin/env python3
"""Week 7 · does your work pass?"""
import argparse, importlib, os, shutil, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")
sys.path.insert(0, HERE)
PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"
results = []


def record(task, name, status, detail=""):
    results.append((task, name, status, detail))
    print({PASS: "  ok  ", FAIL: " FAIL ", SKIP: " skip "}[status]
          + f" [{task}] {name}" + (f"  - {detail}" if detail else ""))


def test_task1():
    try:
        m = importlib.import_module("task1_switch")
    except Exception as e:
        return record(1, "task1_switch.py imports", FAIL, repr(e))
    try:
        rc = m.verify()
    except Exception as e:
        return record(1, "verify runs", FAIL, repr(e))
    record(1, "all seven checks", PASS if rc == 0 else FAIL)


def test_task2():
    for fname, label in [("arp-before.txt", "A1 table before clearing"),
                         ("arp-after.txt", "A1 table after refilling")]:
        path = os.path.join(OUT, fname)
        record(2, label, PASS if os.path.exists(path) and os.path.getsize(path)
               else FAIL, f"out/{fname}")

    before = os.path.join(OUT, "arp-before.txt")
    after = os.path.join(OUT, "arp-after.txt")
    if os.path.exists(before) and os.path.exists(after):
        b = open(before, errors="replace").read()
        a = open(after, errors="replace").read()
        record(2, "the two tables differ", PASS if b != a else FAIL,
               "identical files - did the clear work?")

    cap = os.path.join(OUT, "arp.pcapng")
    if not os.path.exists(cap):
        record(2, "out/arp.pcapng exists", FAIL, "capture request and reply (Part B)")
    elif not shutil.which("tshark"):
        record(2, "request and reply in capture", SKIP, "tshark not installed")
    else:
        r = subprocess.run(["tshark", "-r", cap, "-Y", "arp", "-T", "fields",
                            "-e", "arp.opcode"], capture_output=True, text=True)
        ops = {l.strip() for l in r.stdout.splitlines() if l.strip()}
        record(2, "B1 request (1) and reply (2) both present",
               PASS if {"1", "2"} <= ops else FAIL, f"opcodes seen {sorted(ops)}")


def test_task3():
    try:
        bench = importlib.import_module("bench")
        mod = importlib.import_module("task3_flooding")
    except Exception as e:
        return record(3, "modules import", FAIL, repr(e))
    macs, where, frames = bench.build()
    base = bench.run(mod.NaiveSwitch, "baseline", where, frames)
    try:
        mine = bench.run(mod.YourSwitch, "yours", where, frames)
    except NotImplementedError:
        return record(3, "YourSwitch implemented", FAIL, "still a stub")
    except RuntimeError as e:
        return record(3, "R3 table within capacity", FAIL, str(e))
    except Exception as e:
        return record(3, "YourSwitch runs", FAIL, repr(e))
    record(3, "R4 no extra missed deliveries",
           PASS if mine["missed"] <= base["missed"] else FAIL,
           f"{mine['missed']} vs {base['missed']}")
    cut = 1 - mine["wasted"] / base["wasted"]
    record(3, "R5 fewer wasted deliveries", PASS if cut > 0.02 else FAIL,
           f"{cut:.0%} cut")
    record(3, "R6 attack description in observation.md", SKIP, "graded by a human")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--task", type=int, choices=[1, 2, 3])
    a = p.parse_args()
    os.makedirs(OUT, exist_ok=True)
    for n, fn in [(1, test_task1), (2, test_task2), (3, test_task3)]:
        if a.task in (None, n):
            print(f"\n=== Task {n}")
            fn()
    print()
    failed = sum(1 for *_, s, _ in results if s == FAIL)
    skipped = sum(1 for *_, s, _ in results if s == SKIP)
    print(f"  {len(results) - failed - skipped} passed, {failed} failed, {skipped} skipped")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
