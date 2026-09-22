# Week 4 · Observations

Working notes with the full evidence, tables and derivations are in `observation-full.md`.

## Task 1 · reliable delivery over a bad channel

**Selective repeat**, 16-packet window, per-packet timers. The case that forced it is
**reordering**, and I measured it rather than assumed: on a channel with *only* reordering,
selective repeat sends **250** packets — the theoretical minimum — while a Go-Back-N sender
and receiver send **643** and discard **393 packets that arrived intact**, because a
cumulative-ACK receiver accepts nothing but the next expected sequence number. This channel
reorders 10%, which is exactly Go-Back-N's worst input.

The channel carried **309 packets for 250 packets of data — 1.24×** — and that ratio is
the channel, not the protocol (stop-and-wait pays the same; a window buys latency, 456
steps against 1676, not packets). It is `250/(1−0.10)² = 308.6`, because the data packet
**and** its ACK each have to survive a 10% loss. Checked at another rate: 30% loss predicts
250/0.49 = 510 and measures 499.

**Duplication broke first**, including the duplicates that loss itself creates. A receiver
that appends instead of keying by sequence number fails under loss alone and returns 2288
bytes for a 2000-byte file — too long, not wrong, so a spot-check misses it. A sender that
counts ACKs instead of tracking distinct sequence numbers slides past data that never
arrived and finishes having delivered 8 bytes. Both halves of R3 are real and they are
different bugs.

## Task 2 · measure your own link, twice

The two initial sequence numbers are **4,236,649,187** (client) and **1,068,969,752**
(server) — not zero, not each other, 3.17 billion apart, with the SYN-ACK acknowledging
client ISN + 1. They are not zero because the sequence number is the only thing placing a
byte in a connection, and connections reuse the same four-tuple: starting at 0 would let a
segment delayed from a previous incarnation look valid in the new one (RFC 793), and a
predictable ISN would let an off-path attacker inject one (RFC 6528).

SYN options were MSS 1460, window scale **6** (client) and **7** (server), SACK permitted,
timestamps. So the server advertised up to **194,816 bytes** scaled (×128) — and the client
never had more than **75,296 bytes** outstanding, **38.6%** of the offer. The receive window
was never the limit; **the congestion window was, still in slow start.** Peak bytes in
flight per RTT: 3 → 6 → 12 → 24 → 47 segments, **exactly ×2.0 each round trip**, with no
loss to end it — and the 153 KB transfer ran out of data at 8.6 RTTs. `min(cwnd, rwnd)` had
`cwnd` as the smaller term for the entire connection.

**B3 · two vantage points**, one minute apart so conditions are shared. The second is my
own laptop on the KU campus network, used as a Tailscale exit node — my traffic leaves
from `163.152.233.19` instead of my home ISP address, which I verified before measuring.

| label | median | min–max | spread | median handshake |
|---|---:|---|---:|---:|
| `home-wifi afternoon` (14:03) | **137.02 Mbps** | 97.43–147.61 | 37% | **8.5 ms** |
| `KU campus via Tailscale exit node` (14:02) | **71.21 Mbps** | 61.03–77.17 | 23% | **22.5 ms** |
| `home-wifi afternoon` (13:11, control) | 110.96 Mbps | 79.87–128.49 | 44% | 8.2 ms |

**B4 · the spread.** 37–44% across five runs a minute apart on an unchanged link: each run
is a fresh connection paying slow start again, over Wi-Fi that is a shared half-duplex
radio, to an anycast POP whose load varies (one handshake hit 30.8 ms against a median of
8.5). The third row is a deliberate control — the *same* network 52 minutes earlier —
and it moved 23% while its handshake did not move at all (8.2 → 8.5 ms). So throughput
varying is not by itself evidence of an RTT effect, which is what makes the second vantage
necessary rather than decorative.

**B5 · the mechanism, §3.7.** The handshake got 2.6× worse and throughput fell 48%. During
slow start throughput is bounded by `cwnd/RTT` while `cwnd` doubles once per RTT, so the
*time* to reach any given window is proportional to RTT — the handshake is a direct
measurement of that RTT, taken before any data moves. A worse handshake therefore does not
merely delay the start; it stretches every subsequent doubling.

But I can only claim part of the 48%, because the exit node changed capacity too (WireGuard
encapsulation, the campus uplink, and a doubled traversal). Decomposing the 270 ms of extra
transfer time: reaching the bandwidth-delay product takes ≈`log₂(BDP/IW)` round trips —
3.3 RTTs at home (100 segments of BDP) against 3.8 through the tunnel (137 segments) — so
the ramp costs 28 ms against 85 ms. **That 57 ms is ~21% of the slowdown and is the pure
RTT effect; the remaining 79% is capacity.** The trace is the clean version of the same
mechanism with capacity held fixed: `cwnd` doubling ×2.0 per RTT and the transfer ending at
8.6 RTTs with 60% of the offered window unused.

## Task 3 · beat the fixed window

**Why the baseline is the worst sender despite the highest goodput:** because goodput
measures what it got and every other number measures what it did to everyone else. It buys
its last 3% with **37.4% loss and 2,340 retransmissions** against my 18 — traffic the link
carries, queues, and then discards. It holds the queue at **8.8 of 10**, and queue
occupancy is delay imposed on every other flow crossing the link, which is bufferbloat.
And it cannot coexist: two `FixedWindow`s never back off, so the queue stays saturated and
both spend their capacity retransmitting — congestion collapse, which is what actually
happened to the NSFNET in October 1986 and is why congestion control exists.

My window converges to a sawtooth of **mean 24.9, min 16.6, max 32.0**. The link's
BDP = 1 pkt/slot × 20 slots = **20**, and `mean window − BDP = 24.9 − 20 = 4.9`, against a
measured average queue of **4.6**. That equality is the whole idea: the pipe holds exactly
20, so **everything in flight beyond the BDP is by definition sitting in a queue**. Window
above BDP is not speed, it is standing delay.

Making the backoff gentler bought goodput monotonically and paid in queue, monotonically:
β = 0.50 → 87% (queue 3.21), 0.65 → 95% (4.15), **0.70 → 97% (4.55, chosen)**, 0.75 → 99%
but queue **5.13, which fails R4**. Both bounds fall out of the link rather than out of
tuning. Loss appears only above BDP + queue = 30, so the window peaks near 32; halving it
gives 16, *below* BDP = 20, so the link runs dry while the window climbs back — that is why
textbook Reno scores 87% here, not from backing off too often but from backing off past the
bottom of the pipe. Hence `β·W_peak ≥ BDP` → β ≥ 0.625, while average queue ≤ 5 caps β near
0.72. Final: **goodput 97% of baseline, loss 37.4% → 0.5%, retx 2340 → 18, queue 8.8 → 4.6.**

## Notes on provenance and limits

- **Part A uses the official Wireshark Lab trace, not my own capture — this is path (B).**
  Wireshark, tshark and Npcap could not be installed, and Windows' built-in `pktmon`
  refuses without administrator rights (`액세스가 거부되었습니다`, exit 5). `tshark` is
  also what one would normally read it with, so `task2_measure.py --analyze` parses the
  pcapng, Ethernet, IPv4, TCP and the TCP option list directly. Part B **is** my own link.
  > Wireshark lab trace files from J.F. Kurose and K.W. Ross, *Computer Networking: A
  > Top-Down Approach*, 9th ed. <https://gaia.cs.umass.edu/kurose_ross/>
  > Copyright 1996-2025 J.F. Kurose, K.W. Ross. All Rights Reserved.
- **Whose transfer is in the trace (path B asks):** not mine. 153 KB up against 777 B down
  — it is an upload, the lab's `alice.txt` POST to `gaia.cs.umass.edu:80`; the User-Agent
  is Firefox 85 on macOS 10.15 while I am on Windows; and the client `192.168.86.68` is
  behind NAT on a subnet that is not mine (`192.168.219.x`).
- **B1's second vantage is an exit node, not a second physical link, and that matters.**
  Tethering was unavailable, so the second measurement routes through my own laptop on the
  KU campus network as a Tailscale exit node. The egress genuinely changes — verified
  public IP `58.78.x.x` (home ISP) → `163.152.233.19` before measuring — but **the local Wi-Fi is
  shared by both measurements**. It is one local link with two egress paths, not two
  independent access networks, and the tunnel adds WireGuard encapsulation on top. Hence
  the decomposition in B5 rather than a bare attribution of the 48% to RTT. One record was
  discarded before analysis: the first exit-node run reported two handshakes of 0.0 ms,
  which is impossible through a tunnel and came from curl's timing during cold tunnel
  setup; it was re-run once warm and the contaminated record removed from
  `throughput.json`.
- **A harness bug, reported not patched.** `verify()` builds its payload with
  `bytes(random.Random(seed).getrandbits(8) for _ in range(size))`, which constructs a new
  `Random(seed)` every iteration — so all 2000 bytes are identical (`0xed` for seed 246).
  SHA-256 of that is invariant under permutation, so **the stated pass condition cannot
  detect a reordering bug**: a receiver that appends in arrival order passes it. I left
  `verify()` alone since it is the pass condition; `--selftest` runs the same transfer on
  genuinely random data, one impairment at a time, over five seeds (25/25 identical,
  including 30% loss / 10% dup / 30% reorder).

