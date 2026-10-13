#!/usr/bin/env python3
"""Week 7 · Task 3 — A switch that runs out of room.

Textbook §6.4.3.

A switch does not have room for every station on the network. Its forwarding
table sits in a fixed amount of fast memory, and when that fills, something has
to go. Whatever goes gets **flooded** the next time anyone sends to it - out of
every port, to every station that did not ask for it.

`NaiveSwitch` handles a full table the simplest way: throw out whichever entry
has been there longest. That is a perfectly reasonable first idea and it is
close to the worst thing you can do with this traffic.

    python3 bench.py
    python3 bench.py --yours

Correctness first: every frame whose destination is reachable must still reach
it. A switch that floods less because it delivers less is not a switch.
"""
import hashlib
from collections import OrderedDict


class NaiveSwitch:
    """Correct. Evicts the oldest entry, which is not the least useful one."""

    BROADCAST = "ff:ff:ff:ff:ff:ff"

    def __init__(self, ports, capacity):
        self.ports = ports
        self.capacity = capacity
        self.table = OrderedDict()                 # mac -> port, insertion order

    def handle(self, frame, in_port):
        src, dst, now = frame
        if src not in self.table and len(self.table) >= self.capacity:
            self.table.popitem(last=False)         # throw out the oldest arrival
        self.table[src] = in_port

        if dst == self.BROADCAST or dst not in self.table:
            return [p for p in range(self.ports) if p != in_port]
        out = self.table[dst]
        return [] if out == in_port else [out]


class YourSwitch:
    """Your switch. Same interface, same deliveries, far less flooding.

        __init__(ports, capacity)
        handle((src, dst, time), in_port) -> ports to forward out of

    `self.table` must exist and must never hold more than `capacity` entries.
    The harness checks this after every frame.

    What the baseline gets wrong: it decides what to keep by **when the entry
    arrived**, and that has nothing to do with whether it is about to be needed.
    On this trace a handful of stations carry most of the traffic, and the
    baseline keeps throwing them out to make room for stations that spoke once.

    Two questions worth separating:

      * which entry should leave when the table is full?
      * should learning a new source ever be *declined*?

    The second one is less obvious and is worth thinking about before you
    dismiss it.

    Note what you are NOT allowed to do: you cannot look at `where`, you cannot
    see the future, and you cannot hold more than `capacity` entries. Everything
    you know comes from the frames you have already handled.

    What this one does
    ------------------
    Evidence: how often each station has been heard from *or asked for*,
    estimated in a count-min sketch - a fixed grid of 4 x 256 counters. It
    holds no ports and its size does not grow with the number of stations, so
    the forwarding table proper is still the only place a MAC maps to a port,
    and it never exceeds `capacity`. Every 2,000 updates all counters are
    halved, so a station that stops talking loses its standing (the same idea
    as Task 1's aging, applied to popularity).

    Eviction: the entry with the lowest estimated frequency leaves; ties go to
    the one least recently used.

    Admission: when the table is full, a new source is learned only if its
    estimate beats the entry it would replace. A station heard from once is
    *declined* - it gets flooded if anyone does send to it, which is exactly
    what would have happened anyway after it pushed out somebody useful.
    """

    BROADCAST = "ff:ff:ff:ff:ff:ff"
    SKETCH_DEPTH, SKETCH_WIDTH, HALVE_EVERY = 4, 256, 2000

    def __init__(self, ports, capacity):
        self.ports = ports
        self.capacity = capacity
        self.table = OrderedDict()                 # mac -> port, least recent first
        self.counts = [[0] * self.SKETCH_WIDTH for _ in range(self.SKETCH_DEPTH)]
        self.updates = 0
        self.declined = 0                          # for observation.md

    # ------------------------------------------------------- the frequency sketch
    def _cells(self, mac):
        h = int.from_bytes(hashlib.blake2b(mac.encode(), digest_size=16).digest(), "little")
        return [(h >> (32 * i)) % self.SKETCH_WIDTH for i in range(self.SKETCH_DEPTH)]

    def _count(self, mac):
        for row, i in zip(self.counts, self._cells(mac)):
            row[i] += 1
        self.updates += 1
        if self.updates % self.HALVE_EVERY == 0:
            for row in self.counts:
                for i in range(self.SKETCH_WIDTH):
                    row[i] >>= 1

    def _estimate(self, mac):
        return min(row[i] for row, i in zip(self.counts, self._cells(mac)))

    # -------------------------------------------------------------------- frames
    def handle(self, frame, in_port):
        src, dst, now = frame
        self._count(src)
        if dst != self.BROADCAST:
            self._count(dst)            # being asked for is evidence of usefulness

        if src in self.table:
            self.table[src] = in_port
            self.table.move_to_end(src)
        elif len(self.table) < self.capacity:
            self.table[src] = in_port
        else:
            victim = self._victim()
            if self._admit(src, victim):
                del self.table[victim]
                self.table[src] = in_port
            else:
                self.declined += 1

        if dst == self.BROADCAST or dst not in self.table:
            return [p for p in range(self.ports) if p != in_port]
        self.table.move_to_end(dst)
        out = self.table[dst]
        return [] if out == in_port else [out]

    # The two decisions, kept apart so task3_compare.py can swap either one.
    def _victim(self):
        return min(self.table, key=self._estimate)    # ties: least recent

    def _admit(self, src, victim):
        return self._estimate(src) > self._estimate(victim)
