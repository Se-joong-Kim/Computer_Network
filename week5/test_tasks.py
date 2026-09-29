#!/usr/bin/env python3
"""Week 5 · does your work pass?"""
import argparse, importlib, json, os, shutil, subprocess, sys

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
        m = importlib.import_module("task1_forward")
    except Exception as e:
        return record(1, "task1_forward.py imports", FAIL, repr(e))
    src = open(os.path.join(HERE, "task1_forward.py"), encoding="utf-8").read()
    record(1, "R6 no ipaddress module",
           FAIL if "import ipaddress" in src else PASS)
    try:
        rc = m.verify()
    except NotImplementedError:
        return record(1, "implemented", FAIL, "still a stub")
    except Exception as e:
        return record(1, "verify runs", FAIL, repr(e))
    record(1, "all ten cases", PASS if rc == 0 else FAIL)


def test_task2():
    path = os.path.join(OUT, "addresses.json")
    if not os.path.exists(path):
        record(2, "out/addresses.json exists", FAIL, "run --collect")
    else:
        data = json.load(open(path))
        labels = {r.get("label") for r in data}
        record(2, "B1 two or more labelled networks",
               PASS if len(labels) >= 2 else FAIL, ", ".join(sorted(map(str, labels))))
        record(2, "A4 public address recorded",
               PASS if all(r.get("public") for r in data) else FAIL)

    cap = os.path.join(OUT, "dhcp.pcapng")
    if not os.path.exists(cap):
        record(2, "out/dhcp.pcapng exists", FAIL, "capture DORA (Part C)")
    elif not shutil.which("tshark"):
        record(2, "DORA in capture", SKIP, "tshark not installed")
    else:
        r = subprocess.run(["tshark", "-r", cap, "-Y", "dhcp || bootp",
                            "-T", "fields", "-e", "dhcp.option.dhcp"],
                           capture_output=True, text=True)
        kinds = {l.strip() for l in r.stdout.splitlines() if l.strip()}
        # 1 Discover, 2 Offer, 3 Request, 5 Ack
        record(2, "C1 Discover/Offer/Request/Ack present",
               PASS if {"1", "2", "3", "5"} <= kinds else FAIL, f"saw {sorted(kinds)}")

    rep = os.path.join(OUT, "report.md")
    record(2, "out/report.md exists", PASS if os.path.exists(rep) else FAIL)


def test_task3():
    try:
        bench = importlib.import_module("bench")
        lpm = importlib.import_module("task3_lpm")
    except Exception as e:
        return record(3, "modules import", FAIL, repr(e))
    routes, queries = bench.build()
    base = bench.run(lpm.LinearTable, "baseline", routes, queries)
    try:
        mine = bench.run(lpm.YourTable, "yours", routes, queries, base["answers"])
    except NotImplementedError:
        return record(3, "YourTable implemented", FAIL, "still a stub")
    except Exception as e:
        return record(3, "YourTable runs", FAIL, repr(e))
    record(3, "every answer matches the linear table",
           PASS if mine["wrong"] == 0 else FAIL, f"{mine['wrong']} wrong")
    speedup = base["lookup"] / mine["lookup"]
    record(3, "faster than the baseline", PASS if speedup > 2 else FAIL,
           f"{speedup:.1f}x")


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
