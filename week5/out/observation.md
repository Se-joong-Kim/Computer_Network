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

Home: **one** NAT — A1 `192.168.219.111` private, A4 `58.78.179.154` public, and hop 2 already public
and in A4's /27, so my router is the only translation. Tethering: **two** NATs — the phone, then SK
Telecom's NAT64: AAAA for `ipv4only.arpa` returns `64:ff9b::c000:aa`, and the public IPv4 changed
between requests a second apart (`211.234.201.129`, `.66`). Private and public addresses both
changed — each is lent by that link's DHCP server or outermost NAT; only tethering had IPv6, NAT-free.
The Discover (official trace) is from `0.0.0.0`; any other source would claim an unowned address.

## Task 3 · make the lookup fast

One dict per prefix length, probed longest first: 1782× in `bench.txt`, 0 wrong, 0.3 MB (a 2^24
direct table was twice as fast but 403 MB; a bit-walk trie was 5.7× slower).
Lookup is proportional to the number of distinct prefix lengths — 7 here, 2.61 probes on average —
not to the 5,000 routes, and can never exceed 33.
Hardware builds the trie anyway: every lookup costs the same bounded, pipelineable number of memory
steps, and a router must meet its worst case, where a hash only promises a good average.
