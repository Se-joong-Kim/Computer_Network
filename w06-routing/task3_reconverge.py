#!/usr/bin/env python3
"""Week 6 · Task 3 — Reconverge without recomputing the world.

Textbook §5.2.1, §5.3.

A link flaps. Every router in the area has to decide what changed. `FullRecompute`
does the honest thing: throw the table away and run Dijkstra again, from scratch,
for every event. It is correct and it is what the first implementations did.

It is also why a single flapping link in a large area used to melt the CPU of
every router that could see it.

Beat it:

    python3 bench.py
    python3 bench.py --yours

Correctness first. `bench.py` compares your table against a full recompute after
**every single event**. A router that is fast and wrong black-holes traffic.
"""
import heapq

# The harness counts how many times you run a full SPF. This is the score:
# wall-clock time in Python says more about dictionary overhead than about
# routing, but "how many times did the CPU have to recompute the world" is
# exactly what melted real routers.
SPF_RUNS = 0


def dijkstra_table(graph, source):
    """Reference shortest-path-first. Returns {destination: first_hop}.

    Use THIS function whenever you need a full recompute. Rolling your own to
    dodge the counter is not an optimisation, it is cheating the meter.
    """
    global SPF_RUNS
    SPF_RUNS += 1
    best = {source: (0, None)}
    pq, done = [(0, source, None)], set()
    while pq:
        cost, node, first_hop = heapq.heappop(pq)
        if node in done:
            continue
        done.add(node)
        best[node] = (cost, first_hop)
        for nbr, w in sorted(graph[node].items()):
            if nbr in done:
                continue
            hop = nbr if node == source else first_hop
            if cost + w < best.get(nbr, (float("inf"), None))[0]:
                best[nbr] = (cost + w, hop)
                heapq.heappush(pq, (cost + w, nbr, hop))
    return {d: h for d, (_, h) in best.items() if d != source and h}


class FullRecompute:
    """On every event, forget everything and run SPF again."""

    def __init__(self, graph, source):
        self.graph = {n: dict(e) for n, e in graph.items()}
        self.source = source
        self.table = dijkstra_table(self.graph, source)

    def link_change(self, a, b, cost):
        """cost=None means the link went down."""
        if cost is None:
            self.graph[a].pop(b, None)
            self.graph[b].pop(a, None)
        else:
            self.graph[a][b] = cost
            self.graph[b][a] = cost
        self.table = dijkstra_table(self.graph, self.source)


class YourRouter:
    """Your router. Same two methods, same table, less work per event.

    What is actually true after one link changes:

      * most destinations are not affected at all
      * a link that is not on any of your shortest paths, going *up*, can only
        matter if it creates something shorter
      * a link going *down* only matters if you were using it

    Deciding which of those applies, cheaply, without getting it wrong, is the
    task. Getting it wrong is worse than being slow - the harness will catch it
    on the event where it happens.

    State kept between events, all O(V):

      dist   cost of my shortest path to every reachable node
      pred   the neighbour each node's chosen shortest path arrives from -
             together these edges are my shortest-path tree
      hop    the first hop, i.e. the forwarding table itself

    How each event is handled:

      down or dearer, on an edge NOT in my tree   nothing changes, no work.
          Every distance is achieved inside the tree, so none can move, and
          every node's chosen predecessor is untouched.
      down or dearer, on an edge IN my tree       full SPF via dijkstra_table().
      up or cheaper                               can only shorten paths, so
          the improvement is propagated outward from the edge, touching only
          the nodes that actually got closer (about 20 of 400 here), and only
          those and their neighbours have their next hop re-decided.

    Ties are decided exactly as dijkstra_table() decides them: of several
    equal-cost predecessors, the one settled first wins, and nodes settle in
    (distance, name) order. That makes the table a pure function of `dist`,
    which is what lets an incremental update reproduce it without an SPF.

    One thing to be open about: dijkstra_table() returns next hops but hides
    distances. So each metered full recompute is followed, on the same graph
    and at the same moment, by a distance pass. That pass never runs on its
    own - the meter counts every time this router recomputes the world.
    """

    INF = float("inf")

    def __init__(self, graph, source):
        self.graph = {n: dict(e) for n, e in graph.items()}
        self.source = source
        self._full()

    # ------------------------------------------------------------ full SPF
    def _full(self):
        self.table = dijkstra_table(self.graph, self.source)    # metered
        dist, heap, done = {self.source: 0}, [(0, self.source)], set()
        while heap:                                             # distances, same instant
            d, n = heapq.heappop(heap)
            if n in done:
                continue
            done.add(n)
            for m, w in self.graph[n].items():
                if d + w < dist.get(m, self.INF):
                    dist[m] = d + w
                    heapq.heappush(heap, (d + w, m))
        self.dist, self.pred, self.hop = dist, {}, {}
        for v in sorted(dist, key=lambda n: (dist[n], n)):
            if v != self.source:
                self._settle(v)
        # The derived table must equal the reference's. If the tie rule above
        # were even slightly off, this is where it would show.
        if self._derived() != self.table:
            raise AssertionError("derived table disagrees with dijkstra_table()")

    def _settle(self, v):
        """Pick v's predecessor and next hop from the current distances."""
        dv, best = self.dist[v], None
        for p, w in self.graph[v].items():
            dp = self.dist.get(p, self.INF)
            if dp + w == dv and (best is None or (dp, p) < (self.dist[best], best)):
                best = p
        self.pred[v] = best
        self.hop[v] = v if best == self.source else self.hop[best]

    def _derived(self):
        return {v: h for v, h in self.hop.items() if v in self.dist}

    def _in_tree(self, a, b):
        return self.pred.get(a) == b or self.pred.get(b) == a

    # --------------------------------------------------------------- events
    def link_change(self, a, b, cost):
        """cost=None means the link went down."""
        old = self.graph[a].get(b)

        if cost is None:                                # ---- down
            if old is None:
                return                                  # already down
            in_tree = self._in_tree(a, b)
            del self.graph[a][b], self.graph[b][a]
            if in_tree:
                self._full()
            return

        if old == cost:
            return                                      # nothing changed
        self.graph[a][b] = self.graph[b][a] = cost

        if old is not None and cost > old:              # ---- dearer
            if self._in_tree(a, b):
                self._full()
            return

        self._shorten(a, b, cost)                       # ---- up, or cheaper

    def _shorten(self, a, b, cost):
        """An edge appeared or got cheaper. Distances can only fall."""
        dist, graph, INF = self.dist, self.graph, self.INF
        changed, heap = set(), []
        for x, y in ((a, b), (b, a)):
            nd = dist.get(x, INF) + cost
            if nd < dist.get(y, INF):
                dist[y] = nd
                heapq.heappush(heap, (nd, y))
        while heap:                                     # spread the improvement
            d, n = heapq.heappop(heap)
            if d != dist.get(n):
                continue
            changed.add(n)
            for m, w in graph[n].items():
                if d + w < dist.get(m, INF):
                    dist[m] = d + w
                    heapq.heappush(heap, (d + w, m))

        # Whose next hop could have moved: nodes that got closer, the two ends
        # of the edge (a new equal-cost path is a new tie), and their
        # neighbours. Re-decide them in settle order, and pass the change on to
        # anyone who inherits their hop.
        dirty = set(changed) | {a, b}
        for n in list(changed) + [a, b]:
            dirty.update(graph[n])
        dirty.discard(self.source)
        heap = [(dist[n], n) for n in dirty if n in dist]
        heapq.heapify(heap)
        seen = set()
        while heap:
            _, v = heapq.heappop(heap)
            if v in seen:
                continue
            seen.add(v)
            before = (self.pred.get(v), self.hop.get(v))
            self._settle(v)
            if v in changed or (self.pred[v], self.hop[v]) != before:
                for q, w in graph[v].items():
                    if q != self.source and q in dist and q not in seen \
                            and dist[v] + w == dist[q]:
                        heapq.heappush(heap, (dist[q], q))
        self.table = self._derived()
