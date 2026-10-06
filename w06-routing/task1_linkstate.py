#!/usr/bin/env python3
"""Week 6 · Task 1 — Link state: build the forwarding table yourself.

Textbook §5.2 (link state and distance vector) and §5.3 (OSPF).

Every OSPF router ends up holding the same map of the network, and then each one
computes, alone, where to send a packet for every destination. The computation is
Dijkstra; the output is a forwarding table with **one next hop per destination**,
not a path.

That last part is what makes routing work without anybody carrying a route around
in the packet. Build it.

    python3 task1_linkstate.py --verify
"""
import argparse, heapq

# Undirected weighted graph: node -> {neighbour: cost}
TOPOLOGY = {
    "u": {"v": 2, "w": 5, "x": 1},
    "v": {"u": 2, "w": 3, "x": 2},
    "w": {"u": 5, "v": 3, "x": 3, "y": 1, "z": 5},
    "x": {"u": 1, "v": 2, "w": 3, "y": 1},
    "y": {"w": 1, "x": 1, "z": 2},
    "z": {"w": 5, "y": 2},
}


def _spf(graph, source):
    """One Dijkstra run that keeps what a router needs: cost and first hop.

    The first hop is carried *through* the search instead of being read off a
    finished path. A node reached directly from the source gets itself as its
    first hop; everything reached through it inherits that hop. So no path is
    ever stored - which is the point: a router installs one next hop per
    destination, never a route.

    Tie rule, for two equal-cost paths: the first one settled wins. Nodes are
    settled in (cost, name) order and an entry is only replaced by a strictly
    cheaper one, so of two equal-cost predecessors the one with the lower cost,
    then the alphabetically earlier name, decides the hop. It is deterministic,
    and it is the same rule Task 3's reference `dijkstra_table()` uses.
    """
    best = {source: (0, None)}               # node -> (cost, first hop)
    heap = [(0, source, None)]
    done = set()
    while heap:
        cost, node, hop = heapq.heappop(heap)
        if node in done:
            continue
        done.add(node)
        best[node] = (cost, hop)
        for nbr, w in sorted(graph[node].items()):
            if nbr in done:
                continue
            nhop = nbr if node == source else hop
            if cost + w < best.get(nbr, (float("inf"), None))[0]:
                best[nbr] = (cost + w, nhop)
                heapq.heappush(heap, (cost + w, nbr, nhop))
    return {n: v for n, v in best.items() if n in done}


def dijkstra(graph, source):
    """Shortest path cost from `source` to every node.

    Return {node: cost}. Unreachable nodes must not appear, and neither does
    the source - nobody routes to themselves.
    """
    return {n: c for n, (c, _) in _spf(graph, source).items() if n != source}


def forwarding_table(graph, source):
    """What the router at `source` actually installs.

    Return {destination: first_hop}, where first_hop is a **direct neighbour**
    of `source` - the one interface a packet for that destination leaves by.

    The source itself is not in the table. Neither are unreachable nodes.

    In TOPOLOGY, u's table sends w out of the x interface, not the w one: the
    direct u-w link costs 5 and u-x-y-w costs 3. Adjacency is not routing.
    """
    return {n: h for n, (_, h) in _spf(graph, source).items() if n != source}


def link_down(graph, a, b):
    """A copy of `graph` with the link a-b removed, in both directions."""
    g = {n: dict(e) for n, e in graph.items()}
    g[a].pop(b, None)
    g[b].pop(a, None)
    return g


# ------------------------------------------------------------------- harness
# Costs from the textbook's worked example, §5.2.1
EXPECTED_COST_U = {"v": 2, "w": 3, "x": 1, "y": 2, "z": 4}
EXPECTED_TABLE_U = {"v": "v", "w": "x", "x": "x", "y": "x", "z": "x"}


def verify():
    fails = 0
    try:
        cost = dijkstra(TOPOLOGY, "u")
    except NotImplementedError:
        print("  dijkstra is still a stub"); return 1
    ok = cost == EXPECTED_COST_U
    print(f"  {'ok  ' if ok else 'FAIL'}  costs from u: {cost}")
    if not ok:
        print(f"        expected {EXPECTED_COST_U}")
    fails += not ok

    try:
        table = forwarding_table(TOPOLOGY, "u")
    except NotImplementedError:
        print("  forwarding_table is still a stub"); return 1
    ok = table == EXPECTED_TABLE_U
    print(f"  {'ok  ' if ok else 'FAIL'}  table at u:  {table}")
    if not ok:
        print(f"        expected {EXPECTED_TABLE_U}")
    fails += not ok

    # every node should be able to reach every other
    for n in TOPOLOGY:
        t = forwarding_table(TOPOLOGY, n)
        missing = set(TOPOLOGY) - {n} - set(t)
        bad = [d for d, h in t.items() if h not in TOPOLOGY[n]]
        ok = not missing and not bad
        print(f"  {'ok  ' if ok else 'FAIL'}  table at {n} covers all, hops are neighbours"
              + (f"  missing={missing} bad={bad}" if not ok else ""))
        fails += not ok

    # cutting a link must change somebody's mind
    cut = link_down(TOPOLOGY, "u", "x")
    after = forwarding_table(cut, "u")
    ok = after != table
    print(f"  {'ok  ' if ok else 'FAIL'}  u reroutes when u-x goes down: {after}")
    fails += not ok

    print(f"\n  {'all ok' if not fails else str(fails) + ' failed'}")
    return 1 if fails else 0


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--verify", action="store_true")
    a = p.parse_args()
    raise SystemExit(verify() if a.verify else p.print_help())
