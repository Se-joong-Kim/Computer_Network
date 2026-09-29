# Week 5 · Observations

Full evidence: `report.md` (Task 2) and `bench.txt` (Task 3).

## Task 1 · subnets and longest-prefix match

`/32` returns `(addr, addr, None)` and `/31` `(net, net+1, None)`: neither has a middle, and RFC 3021
makes both `/31` addresses usable with no broadcast, so "none" is the honest third value.
`10.20.30.70` matches five entries, not four — `/0`, `/8`, `/16`, `/24`, `/26` — and the longest,
`/26` → `lab-rack-2`, wins; the default route loses only because its length is 0.
A duplicate prefix with a different next hop raises an error: the table is malformed, and a router
settles that earlier, by administrative distance or metric.

## Task 2 · where exactly am I

One NAT: A1 `192.168.219.111/24` is private, A4 `58.78.179.154` public, and traceroute hop 2
(`58.78.179.129`) is already public and shares a /27 with A4, so translation happens once, at hop 1.
"100.64.x means CGNAT" fails twice here: hops 4–8 are ISP backbone after my packets are already
public, and Tailscale's `100.111.74.12` is a /32 with no gateway that the default route never uses.
The Discover (official trace, path B) comes from `0.0.0.0` because the client has no address, which
forces a broadcast destination. Second network pending: phone tethering on Friday (B1–B3).

## Task 3 · make the lookup fast

One dict per prefix length, probed longest first: 1782× in `bench.txt`, 0 wrong, 0.3 MB (a 2^24
direct table was twice as fast but 403 MB; a bit-walk trie was 5.7× slower).
Lookup is proportional to the number of distinct prefix lengths — 7 here, 2.61 probes on average —
not to the 5,000 routes, and can never exceed 33.
Hardware builds the trie anyway: every lookup costs the same bounded, pipelineable number of memory
steps, and a router must meet its worst case, where a hash only promises a good average.
