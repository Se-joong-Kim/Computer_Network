#!/usr/bin/env python3
"""Week 4 · does your work pass?

    python3 test_tasks.py
    python3 test_tasks.py --task 3
"""
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
        m = importlib.import_module("task1_rdt")
    except Exception as e:
        return record(1, "task1_rdt.py imports", FAIL, repr(e))
    for seed in (246, 999):
        try:
            rc = m.verify(seed)
        except NotImplementedError:
            return record(1, "Sender/Receiver implemented", FAIL, "still a stub")
        except Exception as e:
            record(1, f"transfer seed={seed}", FAIL, repr(e))
            continue
        record(1, f"transfer seed={seed} arrives identical", PASS if rc == 0 else FAIL)


def test_task2():
    cap = os.path.join(OUT, "tcp.pcapng")
    if not os.path.exists(cap):
        record(2, "out/tcp.pcapng exists", FAIL, "capture it in Wireshark (Part A)")
    elif not shutil.which("tshark"):
        record(2, "capture parses", SKIP, "tshark not installed")
    else:
        r = subprocess.run(["tshark", "-r", cap, "-Y", "tcp.flags.syn==1", "-T",
                            "fields", "-e", "tcp.seq_raw"],
                           capture_output=True, text=True)
        syns = [l for l in r.stdout.splitlines() if l.strip()]
        record(2, "capture contains a handshake",
               PASS if len(syns) >= 2 else FAIL, f"{len(syns)} SYN packets")

    path = os.path.join(OUT, "throughput.json")
    if not os.path.exists(path):
        return record(2, "out/throughput.json exists", FAIL, "run task2_measure.py")
    try:
        data = json.load(open(path))
    except Exception as e:
        return record(2, "throughput.json parses", FAIL, repr(e))
    labels = {r.get("label") for r in data}
    record(2, "B1 two or more labelled networks",
           PASS if len(labels) >= 2 else FAIL, ", ".join(sorted(map(str, labels))))
    record(2, "B2 five runs each",
           PASS if all(len(r.get("runs", [])) >= 5 for r in data) else FAIL)


def test_task3():
    try:
        bench = importlib.import_module("bench")
        cc = importlib.import_module("task3_congestion")
    except Exception as e:
        return record(3, "modules import", FAIL, repr(e))
    base = bench.simulate(cc.FixedWindow)
    bench.show("baseline", base)
    try:
        mine = bench.simulate(cc.YourControl)
    except NotImplementedError:
        return record(3, "YourControl implemented", FAIL, "still a stub")
    except Exception as e:
        return record(3, "YourControl runs", FAIL, repr(e))
    bench.show("yours", mine)
    record(3, "R3 loss at most 5%", PASS if mine["loss"] <= 0.05 else FAIL,
           f"{mine['loss']:.1%}")
    record(3, "R4 average queue at most 5.0", PASS if mine["queue"] <= 5.0 else FAIL,
           f"{mine['queue']:.1f}")
    share = mine["goodput"] / base["goodput"]
    record(3, "goodput share of baseline", PASS, f"{share:.0%}")
    record(3, "R5 argument in observation.md", SKIP, "graded by a human")


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
