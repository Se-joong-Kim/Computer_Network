#!/usr/bin/env python3
"""Week 5 · Task 3 — Make longest-prefix match fast.

Textbook §4.3.3.

`LinearTable` is correct and it is what you probably wrote in Task 1: keep the
prefixes in a list, check every one, remember the longest that matched. On six
entries that is fine. A real router holds close to a million, and it has to
answer while the packet is still in the buffer.

Beat it:

    python3 bench.py
    python3 bench.py --yours

Correctness first: `bench.py` checks every one of your answers against the
linear table. A fast router that forwards to the wrong next hop is not a
router, it is an outage.
"""


class LinearTable:
    """Correct, and slow in the obvious way."""

    def __init__(self):
        self.entries = []                     # (prefix_len, network, next_hop)

    def add(self, network, prefix_len, next_hop):
        self.entries.append((prefix_len, network, next_hop))

    def lookup(self, address):
        best = None
        for plen, net, hop in self.entries:
            mask = (0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF
            if address & mask == net and (best is None or plen > best[0]):
                best = (plen, hop)
        return best[1] if best else None


class YourTable:
    """Your table. Same three methods, same answers, fewer comparisons.

    Addresses and networks are plain 32-bit ints here - no strings, no parsing,
    so that the benchmark measures your lookup and nothing else.

    Two directions worth knowing about before you pick one:

      * group by prefix length. There are only 33 possible lengths, and you can
        ask them in an order that lets you stop early.
      * walk the address one bit at a time. Each bit takes you to at most one
        child, so the work is bounded by the address width, not by the table size.

    The second is what hardware does. The first is easier and often enough.
    Say which you chose and what it cost you in memory.
    """

    __slots__ = ("by_len", "probe")

    def __init__(self):
        # One dict per prefix length: {prefix_len: {network: next_hop}}.
        self.by_len = {}
        # The same dicts again as [(mask, dict)], ordered longest prefix first.
        # lookup() walks this and nothing else, so the hot loop never touches
        # self.by_len, never sorts, and never computes a mask.
        self.probe = []

    def add(self, network, prefix_len, next_hop):
        table = self.by_len.get(prefix_len)
        if table is None:
            table = self.by_len[prefix_len] = {}
            mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF if prefix_len else 0
            self.probe.append((mask, table))
            # Sorting here rather than in a freeze step, because bench.py calls
            # add() and then lookup() with no hook in between. It runs once per
            # *distinct prefix length* - 7 times for 5,000 routes - not once per
            # route. A longer prefix has a numerically larger mask, so ordering
            # by mask descending is ordering by prefix length descending.
            self.probe.sort(key=lambda entry: entry[0], reverse=True)
        table[network] = next_hop

    def lookup(self, address):
        # Longest prefix first, stop at the first hit. Stopping early is what
        # makes this longest-prefix-match and not just "some match": the first
        # length that answers is by construction the longest one that can.
        for mask, table in self.probe:
            next_hop = table.get(address & mask)
            if next_hop is not None:
                return next_hop
        return None
