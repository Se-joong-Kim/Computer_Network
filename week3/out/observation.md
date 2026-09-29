# Week 3 · Observations

Full evidence and tables: `observation-full.md`.

## Task 1 · the iterative resolver

The root only knows who runs each TLD, so it answered `www.adobe.com` with `ANCOUNT=0` and 13
`NS` records for `com` — a pointer, not an answer; that is how it serves every name knowing none.
`.com` delegated `adobe.com` to `akam.net` servers with no glue, so I resolved `a1-217.akam.net`
from the root first: 3 extra queries, 13 in all, against 3 for the fully glued `www.korea.ac.kr`.
My laptop asks its ISP resolver one question and gets a cached answer; the cold walk asks 3–13.
`dig` is absent on Windows, so `dig_answer()` falls back to `getaddrinfo` (same resolver): 5/5.

## Task 2 · CDNs and steering

A delegation and an answer are the same packet, different sections filled: frame 2 has `ANCOUNT=0`
and 13 `NS` in *authority*, frame 10 an `A` in *answer* with `AA=1` (DNS bytes real, framing
reconstructed — no Wireshark here). Rule: same organisation by eTLD+1 and NS RRset, not the last
two labels; the naive rule fails both ways — `www.wikipedia.org` (→ `wikimedia.org`, same NS
RRset) and `www.github.com` (no CNAME, yet two addresses). Steering: 8 of 9 third-party sites
answered differently per resolver — only partly (b), since anycast and ECS explain most of it.

## Task 3 · the cache and its floor

The baseline discards the TTL for a fixed 60 s: names with TTL < 60 are served stale (all 266
stale answers) and names with TTL > 60 are refetched while valid (145 wasted round trips).
Worst record: `www.microsoft.com` — shortest TTL (20 s) and most queried (322/1000) — 189 of 266.
The floor is 275 and my cache hits it (275 upstream, 0 stale): a fetch happens only at a query and
covers exactly `[t, t+TTL)`, so fetches must cover every query time, and greedy is the minimum
cover — 118+76+37+23+11+6+1+1+1+1 = 275. No data structure changes which queries are covered.
