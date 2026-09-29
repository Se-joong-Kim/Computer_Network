# Week 4 · Observations

Full evidence and tables: `observation-full.md`.

## Task 1 · reliable delivery over a bad channel

Selective repeat, 16-packet window. Reordering forced it: with only reordering it sends 250 packets
(the minimum) while Go-Back-N sends 643 and discards 393 that arrived intact. The channel carried
309 packets for 250 of data, 1.24× — exactly 250/(1−0.1)², since data and ACK must each survive
10% loss; stop-and-wait pays the same, a window only buys time. Duplication broke first: an
appending receiver returns 2288 bytes for 2000, an ACK-counting sender 8. (`verify()` builds its
payload from one repeated byte, so it cannot see reordering bugs; `--selftest` uses random data.)

## Task 2 · measure your own link, twice

ISNs 4,236,649,187 and 1,068,969,752 (official trace, path B — no capture driver here): random, so
a delayed segment from an old connection on the same four-tuple, or a guess, misses the window.
The server offered 194,816 B (scale ×128), yet the client never had over 75,296 B in flight: cwnd
was still in slow start (3→6→12→24→47 segments, ×2 per RTT) when the data ran out.
Home 137 Mbps / 8.5 ms vs KU campus via a Tailscale exit node 71 Mbps / 22.5 ms (spread 37% / 23%);
slow start grows cwnd once per RTT, so RTT costs throughput — ~21% of this drop, the rest capacity.

## Task 3 · beat the fixed window

The baseline wins goodput only by holding the queue at 8.8/10 and losing 37% of its packets — delay
and waste exported to every other flow; two such senders would collapse the link. My window averages
24.9 = BDP 20 + 4.9, matching the 4.6 average queue: everything above BDP is queue, not speed.
Gentler backoff buys goodput and costs queue: β 0.5 → 87%, 0.7 → 97% (queue 4.55), 0.75 → queue
5.13, failing R4. So β must keep the post-loss window above BDP (β ≥ 20/32) and the queue ≤ 5
(β ≲ 0.72). Result: 97% of baseline goodput, loss 37.4% → 0.5%, retransmissions 2340 → 18.
