#!/usr/bin/env python3
"""Week 7 · Task 3 R6 — what an attacker does with a small table.

The table holds 64 of 400 stations and floods whatever it does not hold. So
anyone who can fill it with junk can make the switch flood *everything*, and a
switch that floods everything is a hub: every port, the attacker's included,
gets a copy of traffic that was never meant for it.

This replays bench.py's trace and, during its middle third, has one port send
frames from source MACs that never existed before - several per legitimate
frame. It then counts, for the legitimate traffic only, how much of it the
switch could no longer deliver precisely, i.e. how much the attacker's port
received a copy of.

    python task3_attack.py

`repeat` is how many times the attacker reuses each fake MAC before moving on.
repeat=1 is the textbook attack. Larger repeats are an attacker who has read
YourSwitch's docstring and is trying to look popular enough to be admitted.
"""
import random
import bench
from task3_flooding import NaiveSwitch, YourSwitch

ATTACKER_PORT = 47
PER_FRAME = 3          # attack frames injected per legitimate frame, mid-trace


def replay(cls, frames, repeat):
    rng = random.Random(7)
    sw = cls(bench.PORTS, bench.CAPACITY)
    lo, hi = len(frames) // 3, 2 * len(frames) // 3
    fake, uses = None, repeat
    seen = flooded = leaked = 0
    for i, (src, dst, t, in_port) in enumerate(frames):
        if lo <= i < hi:
            for _ in range(PER_FRAME):
                if uses >= repeat:
                    fake = "02:" + ":".join(f"{rng.randrange(256):02x}" for _ in range(5))
                    uses = 0
                uses += 1
                sw.handle((fake, bench.BROADCAST, t), ATTACKER_PORT)
        out = sw.handle((src, dst, t), in_port)
        if not (lo <= i < hi) or dst == bench.BROADCAST:
            continue
        if WHERE[dst] == in_port:              # same segment: the harness skips these too
            continue
        seen += 1
        if len(out) > 1:                       # not forwarded precisely: flooded
            flooded += 1
            leaked += ATTACKER_PORT in out
    return seen, flooded, leaked


def main():
    global WHERE
    _, WHERE, frames = bench.build()
    print(f"\n  {bench.PORTS} ports, table {bench.CAPACITY}; during the middle third of "
          f"the trace one port sends {PER_FRAME} frames from fake source MACs per real frame\n")
    print(f"  {'attacker reuses each fake MAC':<30}{'switch':<14}"
          f"{'legit unicast flooded':>24}{'copies to attacker':>20}")
    for repeat in (1, 2, 5):
        for name, cls in (("baseline", NaiveSwitch), ("yours", YourSwitch)):
            seen, flooded, leaked = replay(cls, frames, repeat)
            print(f"  {repeat:>3} time(s){'':<20}{name:<14}"
                  f"{flooded:>8,} of {seen:,} ({flooded / seen:>4.0%})"
                  f"{leaked:>14,}")
        print()
    print("  Without the attack, the same window floods:")
    for name, cls in (("baseline", NaiveSwitch), ("yours", YourSwitch)):
        sw = cls(bench.PORTS, bench.CAPACITY)
        lo, hi = len(frames) // 3, 2 * len(frames) // 3
        seen = flooded = 0
        for i, (src, dst, t, in_port) in enumerate(frames):
            out = sw.handle((src, dst, t), in_port)
            if lo <= i < hi and dst != bench.BROADCAST and WHERE[dst] != in_port:
                seen += 1
                flooded += len(out) > 1
        print(f"    {name:<10} {flooded:,} of {seen:,} ({flooded / seen:.0%})")
    print()


WHERE = {}

if __name__ == "__main__":
    main()
