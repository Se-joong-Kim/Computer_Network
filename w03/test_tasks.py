#!/usr/bin/env python3
"""Week 3 · does your work pass?

Run this before you submit. It checks what a program can check: that your
code runs, that it agrees with a reference where one exists, and that the
files you were asked to produce are there and parse.

It does NOT check whether you understood anything. That is observation.md.

    python3 test_tasks.py
    python3 test_tasks.py --task 3      # just one
"""
import argparse, importlib, json, os, shutil, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")
sys.path.insert(0, HERE)

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"
results = []


def record(task, name, status, detail=""):
    results.append((task, name, status, detail))
    mark = {PASS: "  ok  ", FAIL: " FAIL ", SKIP: " skip "}[status]
    print(f"{mark} [{task}] {name}" + (f"  - {detail}" if detail else ""))


def has_network():
    return subprocess.run(["dig", "+short", "+time=2", "+tries=1", "dns.google", "A"],
                          capture_output=True, text=True).stdout.strip() != ""


# ------------------------------------------------------------------- task 1
def test_task1():
    if not shutil.which("dig"):
        return record(1, "resolver vs dig", SKIP, "dig not installed")
    if not has_network():
        return record(1, "resolver vs dig", SKIP, "no network - path (B) applies")
    try:
        m = importlib.import_module("task1_resolve")
    except Exception as e:
        return record(1, "task1_resolve.py imports", FAIL, repr(e))

    for name, kind in m.VERIFY_NAMES:
        try:
            addr, path = m.Resolver().resolve(name)
        except NotImplementedError:
            return record(1, "Resolver.resolve implemented", FAIL, "still a stub")
        except Exception as e:
            record(1, f"resolve {name}", FAIL, repr(e))
            continue
        expected = m.dig_answer(name)
        if addr in expected:
            record(1, f"resolve {name}", PASS, f"{addr} in {len(path)} hops")
        elif kind == "cdn":
            record(1, f"resolve {name}", PASS,
                   f"{addr} != dig {','.join(expected)} - CDN, explain it in observation.md")
        else:
            record(1, f"resolve {name}", FAIL, f"you={addr} dig={','.join(expected)}")
    record(1, "R2 started at a root server", SKIP, "read your path[0] yourself")
    record(1, "R3 handled a delegation without glue", SKIP, "graded by a human")


# ------------------------------------------------------------------- task 2
def test_task2():
    cap = os.path.join(OUT, "dns.pcapng")
    if not os.path.exists(cap):
        record(2, "out/dns.pcapng exists", FAIL, "capture it in Wireshark (Part A)")
    elif not shutil.which("tshark"):
        record(2, "capture parses", SKIP, "tshark not installed - open it in Wireshark")
    else:
        r = subprocess.run(["tshark", "-r", cap, "-Y", "dns", "-T", "fields",
                            "-e", "dns.flags.response"],
                           capture_output=True, text=True)
        rows = [l for l in r.stdout.splitlines() if l.strip()]
        q = sum(1 for l in rows if l.strip() == "0")
        a = sum(1 for l in rows if l.strip() == "1")
        if q and a:
            record(2, "capture has queries and responses", PASS, f"{q} queries, {a} responses")
        else:
            record(2, "capture has queries and responses", FAIL,
                   f"{q} queries, {a} responses - filter was 'port 53'?")

    chains = os.path.join(OUT, "chains.json")
    if os.path.exists(chains):
        try:
            data = json.load(open(chains, encoding="utf-8"))
            record(2, "out/chains.json parses", PASS, f"{len(data)} sites")
        except Exception as e:
            record(2, "out/chains.json parses", FAIL, repr(e))
    else:
        record(2, "out/chains.json exists", FAIL, "produce it with --collect (B1)")

    rep = os.path.join(OUT, "report.md")
    if not os.path.exists(rep):
        return record(2, "out/report.md exists", FAIL, "write the report")
    text = open(rep, encoding="utf-8").read().lower()
    for need, label in [("|", "a table"), ("third", "third-party verdict"),
                        ("resolver", "the steering number")]:
        record(2, f"report mentions {label}", PASS if need in text else FAIL)


# ------------------------------------------------------------------- task 3
def test_task3():
    try:
        bench = importlib.import_module("bench")
        cache = importlib.import_module("task3_cache")
    except Exception as e:
        return record(3, "modules import", FAIL, repr(e))

    base = bench.run(cache.BaselineCache, "baseline")
    try:
        mine = bench.run(cache.YourCache, "yours")
    except NotImplementedError:
        return record(3, "YourCache implemented", FAIL, "still a stub")
    except Exception as e:
        return record(3, "YourCache runs", FAIL, repr(e))

    record(3, "R3 zero stale answers", PASS if mine["stale"] == 0 else FAIL,
           f"{mine['stale']} stale")
    record(3, "R4 no more upstream than baseline",
           PASS if mine["upstream"] <= base["upstream"] else FAIL,
           f"{mine['upstream']} vs {base['upstream']}")
    record(3, "R5 floor argument in observation.md", SKIP, "graded by a human")


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
