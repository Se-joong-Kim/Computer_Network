# Week 3 · Observations

Working notes with the full evidence, tables and derivations are in `observation-full.md`.

## Task 1 · the iterative resolver

The root did not hand me the address because it does not have it: a root server is
authoritative for the root zone only, which contains nothing but "who runs each TLD" — it
answered `ANCOUNT=0` with 13 `NS` records for `com`. That is what lets one machine be
asked about every name on the internet without knowing any of them.

When `.com` delegated `adobe.com` to six `akam.net` nameservers **with no glue**, I
suspended the walk and resolved `a1-217.akam.net` from the root first: 3 extra queries,
taking `www.adobe.com` to **13 queries against 3** for the fully-glued `www.korea.ac.kr`.
That nested walk is where the recursion in "recursive resolver" actually lives.

Servers asked per name: 3 (korea.ac.kr), 3 (dns.google), 6 (en.wikipedia.org), 6
(stanford.edu), 10 (microsoft.com), 13 (adobe.com) — against the **one** question my
laptop normally asks its ISP resolver, which absorbs all of this *and caches it*, which
is Task 3's subject.

## Task 2 · CDNs and steering

A delegation and an answer are the **same packet format** with a different section filled
in: frame 2 (838 B) has `ANCOUNT=0` and 13 `NS` in the *authority* section; frame 10
(60 B) has `ANCOUNT=1` with an `A` in the *answer* section and `AA=1`. Largest response
was 854 B — a root delegation, big because it must carry glue for the servers it names
(without EDNS0 the same reply is 491 B with `TC=1`).

My rule: third party means *the content is delivered by another organisation*, not "someone
else hosts the DNS" (Netflix's DNS is on Route 53; its video is its own). Domains compared
as eTLD+1 under the Public Suffix List, then a CDN-operator list, then NS-RRset and PTR
as tie-breakers. The naive last-two-labels rule fails **both ways**: `www.wikipedia.org`
false positive (`wikipedia.org` and `wikimedia.org` publish the identical NS RRset and the
address PTRs to `text-lb.eqsin.wikimedia.org`) and `www.github.com` false negative (no
CNAME at all, yet Quad9 returns `20.27.177.113` where the other four return
`20.200.245.247`).

**Steering: 8 of 9 third-party sites answered differently to a different resolver** — but
this only *partly* supports claim (b). All the public resolvers are anycast and land in
Asia from Seoul, so much of the variance is EDNS Client Subnet policy (Google sends it,
Quad9 and Cloudflare do not) rather than my location; and `www.stanford.edu` and
`www.wikipedia.org` return one address everywhere because their replica is chosen by BGP
anycast, where DNS has nothing to steer.

## Task 3 · the cache and its floor

One root cause, wrong in both directions: `BaselineCache` reads `address, ttl =
self.upstream(name)` and **throws `ttl` away** for a fixed 60 s. Correctness — all 266
stale answers come from the two names with TTL under 60 (microsoft 189, cnn 77; worst
served 39.81 s past expiry). Performance — the seven names with TTL over 60 are discarded
while still valid, costing **145 needless round trips**; `a.root-servers.net` has an
86400 s TTL and is refetched 20 times an hour.

Worst-handled record: **`www.microsoft.com`**, worst on both axes at once — shortest TTL
(20 s, a 3× mismatch) *and* top Zipf weight (322 of 1000 queries), so it alone is **189 of
the 266 stale answers (71%)**. The tell is `www.netflix.com`: TTL exactly 60, and the
baseline is perfectly correct on it.

**The floor is 275, and my cache sits on it** (275 upstream, 0 stale, against the
baseline's 325/266). A cache has no clock — `lookup(name, now)` is its only entry point —
so every fetch happens at a query instant and covers exactly `[t, t+TTL)`. The fetch times
must therefore be an interval cover of that name's query times, and greedy is optimal by a
stays-ahead argument; summing per-name gives 118+76+37+23+11+6+1+1+1+1 = 275. Prefetching
only shortens a window for the same round trip, `Upstream.__call__` serves one name per
call, and no data structure changes *which* queries are covered. So the optimum is the
naive algorithm, which is what having a TTL is for.

## Notes on provenance and limits

- **`out/dns.pcapng` was not captured with Wireshark.** Wireshark/tshark/Npcap could not
  be installed, so `task2_steering.py --capture` wrote it from the resolver's own sockets.
  The DNS payloads, transaction IDs, source ports and timestamps are genuine traffic from
  this machine; the Ethernet/IPv4/UDP framing is reconstructed and the IPv4 TTL is set to
  64 and is **not** an observed value. Stated in the file's own metadata and every packet
  comment.
- **`dig` is not installed** (Windows), so `dig_answer()` falls back to
  `socket.getaddrinfo`, which asks the same recursive resolver `dig +short` would
  (`61.41.153.2`). `--verify` reports 5/5.
- **B3 used the path (B) fallback**: one network, five resolvers at differing distances
  rather than two physical vantage points. The steering number is a lower bound.

