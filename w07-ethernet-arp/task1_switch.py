#!/usr/bin/env python3
"""Week 7 · Task 1 — Build a learning switch.

Textbook §6.4.3 (link-layer switches, self-learning) and §6.4.1 (MAC addresses).

A switch is handed a frame and has to decide which ports to send it out of.
Nobody configures it. It works out the map by **watching where frames come
from**, which is the whole idea of self-learning, and it is about thirty lines.

The thirty lines are not the hard part. The hard part is what it does when it
does not know, and what happens to the things it learned when a machine moves.

    python3 task1_switch.py --verify
"""
import argparse


class Switch:
    """A self-learning Ethernet switch.

    `ports` is how many it has, numbered from 0.

    handle(frame, in_port) -> list of ports to forward out of, in ascending order

    A frame is (src_mac, dst_mac, time). Time is in seconds and it only moves
    forward; you need it for aging.
    """

    BROADCAST = "ff:ff:ff:ff:ff:ff"
    AGE_SECONDS = 300

    def __init__(self, ports):
        self.ports = ports
        self.learned = {}          # mac -> (port, time it was last heard from)
        self.now = 0.0             # the switch's clock: the latest frame's time

    def _age_out(self):
        """Forget anything not heard from in AGE_SECONDS.

        This is R4, and it is the same mechanism as R3 seen from the other side:
        R3 says believe new evidence, R4 says stop believing old evidence. A
        table that only did R3 would keep a station that left on its last port
        forever, and frames to it would vanish down a dead port instead of being
        flooded to wherever it is now.
        """
        stale = [m for m, (_, seen) in self.learned.items()
                 if self.now - seen > self.AGE_SECONDS]
        for m in stale:
            del self.learned[m]

    def handle(self, frame, in_port):
        """Learn from the source, then decide where the frame goes.

        The rules, in the order they matter:

          1. learn: the source MAC is reachable through `in_port`, as of now
          2. never send a frame back out of the port it arrived on
          3. broadcast destination -> every other port
          4. known destination -> that one port only
          5. unknown destination -> every other port ("flooding")

        Rule 5 is why a switch works at all before it has learned anything, and
        it is also what Task 3 is about.
        """
        src, dst, t = frame
        self.now = max(self.now, t)
        self._age_out()

        # 1. Learn. Overwriting is the whole of R3: if a station shows up on a
        #    new port, the newest frame is the best evidence of where it is.
        self.learned[src] = (in_port, self.now)

        others = [p for p in range(self.ports) if p != in_port]   # rule 2
        if dst == self.BROADCAST:                                   # rule 3
            return others
        if dst in self.learned:                                     # rule 4
            out = self.learned[dst][0]
            # The destination is on the segment the frame came from - it has
            # already heard it. Sending it back would only duplicate it there.
            return [] if out == in_port else [out]
        return others                                               # rule 5

    def table(self):
        """{mac: port} as currently learned. Aged-out entries must be gone."""
        self._age_out()
        return {m: port for m, (port, _) in self.learned.items()}


# ------------------------------------------------------------------- harness
A, B, C = "00:00:00:00:00:0a", "00:00:00:00:00:0b", "00:00:00:00:00:0c"
BC = Switch.BROADCAST


def verify():
    fails = 0

    def check(label, got, want):
        nonlocal fails
        ok = got == want
        print(f"  {'ok  ' if ok else 'FAIL'}  {label:<46} {got}"
              + ("" if ok else f"   want {want}"))
        fails += not ok

    try:
        s = Switch(4)
    except NotImplementedError:
        print("  Switch is still a stub"); return 1

    # A talks to B. Nobody knows B yet, so it floods - but not back to port 0.
    check("unknown destination floods",
          s.handle((A, B, 0.0), 0), [1, 2, 3])
    # Now B answers from port 2. The switch has seen A, so it forwards precisely.
    check("known destination is not flooded",
          s.handle((B, A, 1.0), 2), [0])
    check("learned both",
          s.table(), {A: 0, B: 2})
    # Broadcast always goes everywhere except back.
    check("broadcast floods",
          s.handle((A, BC, 2.0), 0), [1, 2, 3])
    # A frame for yourself must not come back out of the port it came in on.
    check("never back out the arrival port",
          s.handle((C, A, 3.0), 0), [])
    # B moves to port 3. The switch must believe the new evidence.
    check("station moved, table follows",
          (s.handle((B, A, 4.0), 3), s.table()[B]), ([0], 3))
    # Nothing heard from A for longer than AGE_SECONDS - it must be forgotten.
    s.handle((C, BC, 400.0), 1)
    check("aged-out entry is gone", A in s.table(), False)

    print(f"\n  {'all ok' if not fails else str(fails) + ' failed'}")
    return 1 if fails else 0


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--verify", action="store_true")
    a = p.parse_args()
    raise SystemExit(verify() if a.verify else p.print_help())
