# Week 6 · Observations

Full evidence: `reconverge.txt`, `ospf-timeline.json`, `traceroute.txt`, `cost-change.txt`.

## Task 1 · link state by hand

Tie rule: of equal-cost predecessors the one settled first wins (lower cost, then name) — the same rule
as Task 3's `dijkstra_table()`. A real OSPF router keeps both instead (ECMP), and FRR did in Task 2.
`u`'s next hop for `w` is `x`, not `w`: the direct link costs 5 but `u-x-y-w` costs 3.
After `u-x` fails, `x`, `y`, `z` move from `x` to `v` (costs 1→4, 2→5, 4→7) and `v` stays `v`.
`w` moves from `x` to `w`: direct (5) now ties `u-v-w` (5), and the rule picks the one settled first.
No path is stored, only one next hop per destination — which is why no packet has to carry a route.

## Task 2 · break a real network

A2 my ISP hands off at hop 6→7: `1.213.107.222` (LG U+) → `211.44.125.206` (SK Broadband), then KU's 10.x.
A3 `web.stanford.edu` jumps +98 ms from `tyo1.he.net` (66 ms) to `sea1.he.net` (164 ms): the Pacific
cable; `www.stanford.edu` never crosses (AWS anycast, 7 ms). A4 `1.1.1.1`: 13 hops, 6 ms — in Seoul.
A5 `*` before hops that answer = a router sending no ICMP; `*` up to hop 30 = KU filtering the probes.
B2 each router learned the net it has no link to (r1→net_c, ECMP). B4 link-down 0.32 s: hello/dead (10/40,
defaults; not in frr.conf) unused; silent cut 35–38 s ≈ dead 40. B5 repair 7–15 s. C3 cost change 0.4 s.

## Task 3 · reconverge without recomputing the world

I keep `dist`, `pred` and `hop` per node — three O(V) maps. Down or dearer off my tree: no work.
On my tree: full SPF via `dijkstra_table()`, plus a distance pass then, as it hides distances.
Up or cheaper: propagate the improvement from the edge, ~20 of 400 nodes, no SPF. 212 runs vs 1001 = 79%.
The hint's third case done by SPF reached only 64%; past 75% needed the propagation. 0 wrong in 1000.
R5: wall time is worse (1.54 s vs 1.07 s): Python pays per dict operation, plus the harness's own checks.
A router pays per SPF, on every router that sees a flapping link at once — so it is still the right trade.
