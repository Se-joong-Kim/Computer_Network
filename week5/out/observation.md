# Week 5 · Observations

## Task 1 · subnets and longest-prefix match

`/32` returns `(addr, addr, None)` and `/31` returns `(net, net+1, None)`: the textbook's
"first and last usable" assumes a prefix with a middle, a `/32` is a single host, and RFC
3021 made both addresses of a `/31` point-to-point link usable with no broadcast — so the
third value is `None`, because "there isn't one" is the true answer and an invented address
would be a lie.

`10.20.30.70` actually matches **five** entries, not the four the brief says — `0.0.0.0/0`,
`10.0.0.0/8`, `10.20.0.0/16`, `10.20.30.0/24`, `10.20.30.64/26` — four if the default route
is not counted. One rule picks the winner, the longest prefix (`/26` → `lab-rack-2`), and
the default route loses because its length is 0, not because it is special-cased.

A second entry with the same prefix and a different next hop is **rejected with an error**,
not silently resolved: it means the table is malformed, and a real router settles it
earlier, in the routing protocol by administrative distance or metric.

## Task 2 · where exactly am I

**One NAT.** A1 `192.168.219.111/24` is RFC 1918 and A4 is public, so at least one; and
traceroute hop 2, the first router past my gateway, is already public (`58.78.x.y`) and
shares a `/27` with A4, so my router's WAN side is public and the translation happens once,
at hop 1. The brief's "a `100.64.x` address means two NATs" fires twice here and is wrong both
times: hops 4–8 are `100.64/10` but come *after* my packets are already public (ISP backbone,
not a NAT in front of me), and my Tailscale interface holds `100.111.74.12` but is a `/32`
with no gateway, origin `Manual`, that the default route does not use (a VPN reusing the
block). An address range is a registry convention, not a topology.

**Between two networks: not yet measured.** The second network is phone tethering, and the
phone is not with me this week; `--collect "phone tethering"` then `--report` generates the
comparison. What I expect, stated so it can be checked: both the public and the private
address change, because each belongs to a different DHCP server and a different outermost NAT.

The Discover's source is **`0.0.0.0`**, because the client has no address and every other
value would claim one it does not own; that forces the destination to `255.255.255.255`,
since unicast needs the server's address and a route, and both arrive in the Ack.

## Task 3 · make the lookup fast

**One dict per prefix length**, probed longest-first with an early exit: **1782× in
`bench.txt`** (1782–2015× over four runs — 7 ms is near the timer's floor), every one of
the 20,000 answers identical, and **0.3 MB**. I also measured a direct-indexed `2^24` table
(4129×, but **403 MB**) and a bit-walk trie (347×) — the table is twice as fast for 1300
times the memory, and assumes no prefix is longer than `/24`.

Lookup time is now proportional to **the number of distinct prefix lengths in the table**,
not the number of routes: 7 here (`/24 /22 /20 /16 /12 /8 /0`) in the worst case and **2.61
probes on average**, each one mask and one dict lookup. It is bounded by 33 however many
routes the table holds; the baseline was proportional to all 5,000.

The trie is what hardware builds even though it was 5.7× slower here in the same run, because its cost is
**fixed and pipelineable**: every lookup takes the same bounded number of memory steps, so
a router can guarantee line rate. In CPython each of those steps is an interpreted list
index, so 32 of them lose to 2.6 hash probes; but a hash has a probabilistic worst case,
and a router has to meet its worst case, not its average.

## Provenance and limits

- **Part C uses the official DHCP trace, not my own capture (path B).** No Wireshark, tshark
  or Npcap here, and `pktmon` refuses without administrator rights (exit 5). `--analyze-dhcp`
  parses it directly. Wireshark lab trace files from J.F. Kurose and K.W. Ross, *Computer
  Networking: A Top-Down Approach*, 9th ed., <https://gaia.cs.umass.edu/kurose_ross/>,
  Copyright 1996-2025 J.F. Kurose, K.W. Ross. All Rights Reserved.
- **B1–B3 are not yet done** — one network only; `test_tasks.py` fails B1 until the second
  `--collect`.
- The speedups above are against the baseline **in the same run** (12.0 s here), not the
  6.7 s quoted in `task3.md`; this machine runs the baseline ~1.8× slower.
