#!/usr/bin/env python3
"""Week 7 · Task 3 — which half of YourSwitch does the work?

YourSwitch makes two decisions: which entry leaves (lowest estimated frequency)
and whether a newcomer gets in at all (only if it beats that entry). This runs
bench.py's trace with each decision swapped for the obvious alternative, so the
numbers in observation.md can be reproduced.

    python task3_compare.py
"""
import bench
from task3_flooding import NaiveSwitch, YourSwitch


def least_recent(self):
    return next(iter(self.table))


def always(self, src, victim):
    return True


class LRU(YourSwitch):
    _victim, _admit = least_recent, always


class LRUDeclining(YourSwitch):
    _victim = least_recent


class LFUAlways(YourSwitch):
    _admit = always


class NoHalving(YourSwitch):
    HALVE_EVERY = 10 ** 12


class NarrowSketch(YourSwitch):
    SKETCH_WIDTH = 64


VARIANTS = [
    ("baseline: evict the oldest arrival", NaiveSwitch),
    ("LRU, always admit", LRU),
    ("LFU, always admit", LFUAlways),
    ("LRU, decline the unpopular", LRUDeclining),
    ("LFU, decline the unpopular (submitted)", YourSwitch),
    ("  same, counters never halved", NoHalving),
    ("  same, sketch 4 x 64", NarrowSketch),
]


def main():
    _, where, frames = bench.build()
    print(f"\n  {len(frames):,} frames, table {bench.CAPACITY}\n")
    rows = [(label, bench.run(cls, cls.__name__, where, frames)) for label, cls in VARIANTS]
    base = rows[0][1]["wasted"]
    print(f"\n  {'policy':<42}{'wasted':>10}{'missed':>8}{'cut':>6}")
    for label, r in rows:
        cut = "" if r is rows[0][1] else f"{1 - r['wasted'] / base:.0%}"
        print(f"  {label:<42}{r['wasted']:>10,}{r['missed']:>8}{cut:>6}")
    print()


if __name__ == "__main__":
    main()
