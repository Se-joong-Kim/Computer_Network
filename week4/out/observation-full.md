# Week 4 · Observations

---

## Task 1 — reliable delivery over a bad channel

**Which protocol, and the case that forced it.** **Selective repeat**, with a 16-packet
window and a per-packet timer. The case that decided it is **reordering**, and I measured
it rather than assumed it. I wrote a Go-Back-N sender and receiver alongside mine and ran
both on the same channel with *only* reordering turned on (no loss, no duplication):

| channel | protocol | packets sent | steps | correctly-arrived packets discarded |
|---|---|---:|---:|---:|
| reordering only | selective repeat | **250** | 17 | **0** |
| reordering only | go-back-N | **643** | 627 | **393** |
| all three | selective repeat | **309** | 456 | **0** |
| all three | go-back-N | **1029** | 1239 | **700** |

250 is the minimum — 2000 bytes at 8 bytes a packet. Under pure reordering selective
repeat pays *nothing*, because nothing was actually lost; it just arrives scrambled and
gets buffered. Go-Back-N sends 2.6× the minimum for the same transfer, and the last column
is why: its receiver accepts only the next expected sequence number, so every packet that
overtook another is thrown away **even though it arrived intact**, and the sender then
resends the whole window. This channel reorders 10% of packets, which is exactly the
input Go-Back-N is worst at.

Stop-and-wait would also have passed. I swept the window size and it is worth being
precise about what a window actually buys here:

| window | packets sent | steps to finish |
|---:|---:|---:|
| 1 (stop-and-wait) | 309 | 1676 |
| 8 | 313 | 747 |
| 16 | 309 | **456** |
| 64 | 309 | 240 |

The packet count barely moves — the window buys **latency, not efficiency**. I kept 16
because it is where the step count stops falling steeply, and because a window that large
makes the reordering and duplication cases actually occur often enough to be tested.

**What reliability cost: 309 packets for 250 packets of data, a ratio of 1.24×.** That
number is not arbitrary and it is not a property of my protocol — stop-and-wait pays the
same 1.24×. It is the channel:

```
  250 / (1 - 0.10)²  =  250 / 0.81  =  308.6      measured: 309
```

Both the data packet **and** its acknowledgement have to survive a 10% loss, so the
expected transmissions per packet is 1/0.81. I checked the prediction at a different loss
rate: at 30% loss the model says 250/0.49 = 510 and the measurement is 499. The cost of
reliability on a lossy link is paid twice, once in each direction, and that is visible in
a two-line calculation.

**What broke first: duplication — and loss, through the duplication it causes.** I wrote
two deliberately naive variants and ran each impairment on its own:

| impairment | mine | receiver that appends instead of keying by seq | sender that counts ACKs instead of tracking seqs |
|---|---|---|---|
| loss only | ok | **broken** | ok |
| reordering only | ok | ok* | ok |
| duplication only | ok | **broken** | **broken** |
| all three | ok | **broken** (2288 bytes out of 2000) | **broken** (8 bytes) |

The appending receiver fails *silently and in the most misleading way*: it produces 2288
bytes for a 2000-byte file. Too long, not wrong — a length check catches it, a spot-check
of the first bytes does not. Note it breaks under **loss only**, with no duplication in
the channel at all, because loss causes my sender to retransmit and the retransmission
*is* the duplicate. The ACK-counting sender fails differently: a duplicated ACK advances
its window past data that never arrived, and it finishes having delivered 8 bytes while
believing it sent 2000.

So both halves of R3 are real, and they are genuinely different bugs: a duplicate **data**
packet corrupts the output, a duplicate **ACK** corrupts the sender's idea of what is
outstanding. My receiver is idempotent because it writes into a dict keyed by sequence
number, and it re-ACKs duplicates rather than ignoring them — which matters, because if
the receiver stayed silent on a packet it already had, a lost ACK would deadlock the
transfer forever.

**\*A finding about the harness, not my code.** Reordering-only shows "ok" for the
appending receiver, which cannot be right — and it is not. `verify()` builds its test
data as

```python
original = bytes(random.Random(seed).getrandbits(8) for _ in range(size))
```

which constructs a **new** `Random(seed)` on every iteration of the generator, so every
byte comes out identical: for seed 246 the payload is 2000 copies of `0xed`. SHA-256 of
that is invariant under permutation, so **the stated pass condition cannot detect a
reordering bug at all** — a receiver that appends packets in arrival order passes it.
I did not patch `verify()`, since it is the pass condition and `test_tasks.py` calls it;
instead `python task1_rdt.py --selftest` runs the same transfer against genuinely random
data, one impairment at a time, over 5 seeds:

```
  channel               seeds ok    sent   min   ratio
  loss only           5/5             313   250    1.25x
  reordering only     5/5             250   250    1.00x
  duplication only    5/5             250   250    1.00x
  all three           5/5             309   250    1.24x
  brutal (30% loss)   5/5             499   250    2.00x
```

---

## Task 2 — measure your own link, twice

**Provenance first.** Part A uses the official Wireshark Lab trace, not my own capture —
this is path (B), and the reason is concrete: Wireshark/tshark/Npcap could not be
installed on this machine, and Windows' built-in `pktmon` refuses without administrator
rights (`PktMon 드라이버와 통신하지 못했습니다: 액세스가 거부되었습니다`, exit 5). Part B
*is* my own machine and my own link.

> Wireshark lab trace files from J.F. Kurose and K.W. Ross,
> *Computer Networking: A Top-Down Approach*, 9th ed.
> <https://gaia.cs.umass.edu/kurose_ross/>
> Copyright 1996-2025 J.F. Kurose, K.W. Ross. All Rights Reserved.

`tshark` is also what one would normally use to read it, so I wrote the dissector:
`python task2_measure.py --analyze` parses the pcapng blocks, Ethernet, IPv4, TCP and the
TCP option list directly and prints everything below.

### A2 · the handshake

Frames **1**, **2**, **3** of `192.168.86.68:55639 ↔ 128.119.245.12:80`. SYN at t=0,
SYN-ACK at +22.414 ms, ACK at +22.505 ms. **The handshake cost 22.5 ms** — essentially
one round trip, and the ACK follows the SYN-ACK after 0.09 ms because the client has
nothing to wait for.

### A3 · the initial sequence numbers, and why they are not zero

```
  client ISN   4,236,649,187   (0xfc8622e3)
  server ISN   1,068,969,752   (0x3fb72f18)
```

They are not zero, they are not each other, and they are not close — they differ by
3.17 billion. Each end chooses its own, independently, and the SYN-ACK confirms the
convention by acknowledging `4236649188` = client ISN + 1 (the SYN consumes one sequence
number even though it carries no data).

Why not zero: **because the sequence number is the only thing identifying a byte's place
in a connection, and connections reuse the same four-tuple.** If both ends always started
at 0, a segment delayed in the network from a previous connection between the same
addresses and ports would carry sequence numbers that look perfectly valid in the new one,
and would be accepted as data. Randomising the ISN makes that collision improbable
(RFC 793's original motivation), and it also means an off-path attacker who can guess the
four-tuple still cannot guess where the window is, so they cannot inject a segment
(RFC 6528 — this is why the value must be hard to predict, not merely non-zero).

### A4 · options on the SYN

| | MSS | Window Scale | SACK permitted | Timestamps | raw window field |
|---|---:|---|---|---|---:|
| client SYN | 1460 | **6** (×64) | yes | yes | 65,535 |
| server SYN-ACK | 1460 | **7** (×128) | yes | yes | 28,960 |

MSS 1460 = 1500-byte Ethernet MTU − 20 IP − 20 TCP, so this is a plain Ethernet path with
no tunnel. The two ends chose **different** scale factors — the option is not negotiated
to a common value, each side announces the shift it will apply to *its own* advertised
window. Note the window scale has to be on the SYN: there is nowhere else to put it,
because from the second packet onward the window field has to be interpreted, and the
receiver can't retroactively agree on a multiplier.

### A5 · the advertised window, and what actually limited the transfer

```
  server advertised (scaled ×128):   min 31,872   median 160,768   max 194,816 bytes
  client's peak bytes unacknowledged:                               75,296 bytes
  -> the sender filled 38.6% of the window it was offered
```

So **the receive window was not the limit.** The raw window field of 28,960 would have
been the limit — that is under 20 segments — but scaled by 128 the server is offering up
to 190 KB, and the client never used more than 40% of it.

What was the limit: **the congestion window, still in slow start.** I measured the peak
bytes in flight per round trip:

| RTT elapsed | peak segments in flight | growth |
|---:|---:|---|
| 1 | 3 | |
| 2 | 6 | ×2.0 |
| 3 | 12 | ×2.0 |
| 4 | 24 | ×2.0 |
| 5 | 47 | ×2.0 |
| 6 | 52 | ×1.1 |

That is textbook slow start, doubling every RTT, with no loss to end it. The whole
transfer is 153,425 bytes — 105 segments — and it finished in **8.6 RTTs**. `cwnd` was
still doubling when the sender ran out of data. It never got near the 133 segments the
receiver was offering, so `rwnd` never became the binding constraint. §3.7's
`min(cwnd, rwnd)` had `cwnd` as the smaller term for the entire connection, and a transfer
this short is over before the two can even converge.

### path (B) · whose transfer was this, and how I can tell from the capture alone

From the payload of the client's own packets:

```
POST /wireshark-labs/lab3-1-reply.htm HTTP/1.1
Host: gaia.cs.umass.edu
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:85.0) Gecko/20100101 Firefox/85.0
Content-Type: multipart/form-data; boundary=---------------------------19395076943
```

It is not mine, and the capture says so four ways. The **direction** is inverted from
normal browsing — 153 KB up, 777 bytes down — because this is a file being *uploaded*, the
`alice.txt` POST the lab instructs you to perform. The **User-Agent** is Firefox 85 on
macOS 10.15, while I am on Windows. The **client address** `192.168.86.68` is RFC1918
private space behind NAT, and `192.168.86.x` is not my subnet (mine is `192.168.219.x`).
And the **destination** is `gaia.cs.umass.edu:80` — plaintext HTTP on port 80, which is
also why the payload is readable at all; my own `--label` transfers go to
`speed.cloudflare.com` over TLS on 443, where none of this would be visible.

### B3 · the two networks

Phone tethering was not available, so the second vantage is my own laptop on the **KU
campus network**, enabled as a Tailscale exit node. My traffic then leaves the internet
from the campus rather than from my home ISP, which I verified before measuring rather
than assumed:

```
  before:  public IP 58.78.x.x       (home ISP, KR)    handshake 20.4 ms
  after:   public IP 163.152.233.19  (Korea University) handshake 66.2 ms   <- cold tunnel
```

**What this is and is not.** The egress genuinely changes, and so does the path and the
apparent source network. But **the local Wi-Fi link is shared by both measurements** — it
is one local link with two egress paths, not two independent access networks — and the
tunnel adds WireGuard encapsulation on top. That is why B5 below decomposes the result
instead of attributing all of it to RTT.

The two measured vantages are one minute apart, so local conditions are as close to
identical as I can make them. A third row is included deliberately as a control: the same
home network, 52 minutes earlier.

| label | when | median | min–max | spread | median handshake |
|---|---|---:|---|---:|---:|
| `home-wifi afternoon` | 2026-09-22 14:03 | **137.02 Mbps** | 97.43 – 147.61 | **37%** | **8.5 ms** |
| `KU campus via Tailscale exit node` | 2026-09-22 14:02 | **71.21 Mbps** | 61.03 – 77.17 | **23%** | **22.5 ms** |
| `home-wifi afternoon` *(control)* | 2026-09-22 13:11 | 110.96 Mbps | 79.87 – 128.49 | 44% | 8.2 ms |

**One record was discarded before analysis, and it is worth saying why.** The first
exit-node run reported handshakes of `0.0 ms` on two of its five transfers — physically
impossible through a tunnel. Breaking out curl's full timing showed the cause: during cold
tunnel setup `time_namelookup` and `time_connect` coincide, so `connect − namelookup`
collapses to zero, and that run's first transfer also carried a 103 ms TTFB against a
later median of 76 ms. I re-ran once the tunnel was warm (steady state: namelookup 5.5 ms,
connect 27 ms, so a ~22 ms handshake) and removed the contaminated record from
`throughput.json`. Its throughput figures were actually fine — median 70.97 against the
clean run's 71.21 — but its handshake median was not, and B3 asks for exactly that.

**B4 · explaining the spread — 37-44% across five runs on one unchanged network.** Nothing
about the link changed between run 1 and run 5; they are a minute apart on the same Wi-Fi,
to the same host. Note the exit-node vantage is *tighter* (23%), not looser - the tunnel's
own bottleneck dominates and masks the local variation. What varies:

- **Slow start, every time.** Each run is a fresh TCP connection, so each one starts at a
  small `cwnd` and doubles. A 5 MB transfer at ~110 Mbps is over in ~0.36 s, which at an
  8 ms RTT is only ~45 round trips — a meaningful fraction of the transfer is spent
  *ramping*, not at full rate. This is the same effect the trace shows in A5, and it is
  why the first run (79.87 Mbps) is the slowest: nothing is warm.
- **The Wi-Fi link itself**, which is a shared half-duplex radio: interference, rate
  adaptation, and other devices on the same channel all move the achievable rate
  second to second. The adapter negotiates 780 Mbps and delivers ~110.
- **The far end.** `speed.cloudflare.com` is anycast; which POP answers and how loaded it
  is varies. Run 5's handshake of 27.9 ms against a median of 8.2 ms is a 3.4× jump with
  no local cause — that is the server side or the path, not my laptop.
- **TTFB**, which ranged 46.8 – 285.8 ms. The 285.8 ms outlier was run 1, again the
  cold-start effect (TLS negotiation, connection setup at the POP).

This is the finding, not noise to be averaged away: **a single throughput number is not a
property of a link.** The median is 110.96 and the honest statement is "roughly 80–130
Mbps depending on when you ask", which is why B2 asks for five runs.

**B5 · handshake time and throughput are not independent.** Between the two contemporaneous
vantages the handshake got **2.6× worse (8.5 → 22.5 ms)** and throughput fell **48%
(137.02 → 71.21 Mbps)**. The mechanism is §3.7's:

> Throughput during slow start is bounded by `cwnd / RTT`, and `cwnd` doubles once per
> RTT. So the *time* to reach any given window is proportional to RTT, and the number of
> bytes you can deliver in a fixed-length transfer scales roughly as `1/RTT` while you are
> still ramping.

The handshake time **is** a measurement of that RTT — it is one round trip, made visible
before any data moves. So a network with a worse handshake is not merely "slower to
start": every subsequent doubling of the congestion window also takes proportionally
longer, and a short transfer may finish before the window ever opens. The trace is the
clean demonstration: 22.5 ms handshake, `cwnd` doubling every 22.5 ms, transfer over at
8.6 RTTs with `cwnd` still climbing and 60% of the offered receive window unused. Had the
RTT been 5 ms instead, the same 153 KB would have been delivered in the same 8.6 RTTs —
but that is 43 ms instead of 194 ms, a 4.5× higher throughput **from an identical link
capacity**. Capacity sets the ceiling; RTT sets how long you take to reach it, and for
short transfers you never do.

**How much of my 48% is actually RTT?** Not all of it, and claiming otherwise would be the
easy mistake here — the exit node changed capacity too (WireGuard encapsulation, the campus
PC's uplink, and a doubled traversal of the public internet). The two effects can be
separated with the model above. Reaching the bandwidth-delay product from an initial window
of 10 segments takes about `log₂(BDP/IW)` round trips:

| | median | handshake | transfer of 5 MB | BDP | ramp | ramp time |
|---|---:|---:|---:|---:|---:|---:|
| home direct | 137.02 Mbps | 8.5 ms | 292 ms | 100 seg | 3.3 RTT | **28 ms** |
| KU exit node | 71.21 Mbps | 22.5 ms | 562 ms | 137 seg | 3.8 RTT | **85 ms** |

The transfer got 270 ms slower. **57 ms of that — about 21% — is the longer slow-start
ramp, which is the pure RTT effect. The remaining 79% is capacity**, and I cannot claim it
for §3.7. (The 79% is itself the reason this vantage is imperfect: B5 asks about two
networks whose *raw capacity is the same*, and mine are not.)

**The control row is what makes even the 21% believable.** The same home network measured
52 minutes apart moved 110.96 → 137.02 Mbps, a 23% swing — while its handshake did not move
at all (8.2 → 8.5 ms). So throughput varying on its own is *not* evidence of an RTT effect;
within-network noise on this link is about 23%, and the cross-vantage difference is 48%,
roughly twice that. The effect is real but it is not enormous compared with the noise, and
a single pair of measurements without that control would not have been able to tell the
difference.

The trace remains the cleaner demonstration precisely because capacity is held fixed there:
`cwnd` doubling ×2.0 per RTT, no loss, and the transfer ending at 8.6 RTTs with 60% of the
offered receive window still unused.

---

## Task 3 — beat the fixed window

```
  baseline   goodput  986.8/1000 slots   loss  37.4%   retx  2340   avg queue   8.8
  yours      goodput  955.2/1000 slots   loss   0.5%   retx    18   avg queue   4.6
  -> strong  (97% of baseline goodput, loss 0.5%, queue 4.6)
```

**R5 · the baseline has the highest goodput here. Why is it still the worst sender?**

Because goodput measures what *it* got, and every other number measures what it did to
everyone else. Three ways to say the same thing:

1. **It buys its last 3% of goodput with 37% loss.** Of everything `FixedWindow` puts on
   the link, better than one packet in three is dropped and sent again — 2,340
   retransmissions against my 18. The link carries that traffic. It occupies the queue,
   consumes the radio or the fibre, and is then discarded. The baseline's *goodput* is
   986.8; its *throughput* is far higher and the difference is pure waste.
2. **It keeps the queue permanently full, and the queue is shared.** Average occupancy
   8.8 of 10. Queue occupancy is delay: at 1 packet per slot, 8.8 packets of standing
   queue is 8.8 slots of extra latency imposed on *every* packet crossing this link,
   including packets belonging to flows that did nothing wrong. This is bufferbloat, and
   it is why a single large download can make a video call unusable on the same
   connection. The baseline does not pay that cost; it exports it.
3. **It cannot coexist.** With one sender the benchmark flatters it. Put two
   `FixedWindow`s on this link and neither backs off, so the queue stays saturated, the
   loss rate rises for both, and both spend most of their capacity retransmitting. That is
   not a thought experiment — it is congestion collapse, the thing that actually happened
   to the NSFNET in October 1986, when throughput between LBL and Berkeley fell by a
   factor of a thousand. Congestion control was invented in response, and its purpose is
   not to make one flow faster, it is to make *n* flows possible.

The one-sentence version: the baseline is optimal for a sender that is alone on the link
and believes it always will be, and the entire point of §3.7 is that this belief is what
destroys a shared network.

**What my window converges to, and how that relates to the link.** Measured over the
second half of the run: **min 16.6, mean 24.9, max 32.0 packets.**

```
  BDP = capacity × RTT = 1 packet/slot × 20 slots = 20 packets
  queue depth 10, so drops begin above 20 + 10 = 30 in flight
  mean window − BDP  =  24.9 − 20  =  4.9   ≈  measured average queue 4.6
```

That last line is the whole idea made arithmetic. **Everything in flight beyond the
bandwidth-delay product is sitting in a queue, by definition** — the pipe holds exactly
20, so a window of 25 means 20 in transit and 5 waiting. Window size above BDP does not
buy speed; it converts directly into standing delay. So the target is not "as large as
possible", it is "the smallest window that still keeps the pipe full", which is BDP plus
a small margin to absorb jitter. My sawtooth oscillates between ~22 and ~32 around a mean
of 25, i.e. BDP + 5.

**What happened when I made the backoff gentler, and what it cost.** I swept β, the
multiplicative decrease factor, holding everything else fixed:

| β | goodput | share of baseline | loss | avg queue | queue margin |
|---:|---:|---:|---:|---:|---:|
| 0.50 (textbook Reno) | 853.8 | 87% | 0.4% | 3.21 | 36% |
| 0.55 | 883.2 | 90% | 0.4% | 3.51 | 30% |
| 0.60 | 902.5 | 91% | 0.4% | 3.75 | 25% |
| 0.65 | 935.8 | 95% | 0.5% | 4.15 | 17% |
| **0.70 (chosen)** | **955.2** | **97%** | **0.5%** | **4.55** | **9%** |
| 0.72 | 962.8 | 98% | 0.5% | 4.70 | 6% |
| 0.75 | 975.2 | 99% | 0.6% | **5.13** | **−3% — fails R4** |
| 0.80 | 977.8 | 99% | 0.6% | 5.95 | −19% — fails R4 |
| 0.90 | 977.8 | 99% | 1.1% | 8.00 | −60% — fails R4 |

Gentler backoff bought goodput monotonically and paid for it in standing queue,
monotonically. The trade is not subtle and it is not free, and the two bounds that pin β
down are both computable from the link:

- **Lower bound.** Loss appears only above 30 in flight, so the window peaks near 32.
  Halving it gives 16, which is *below* BDP = 20 — so after every loss the link literally
  runs dry while the window climbs back. That is why textbook Reno scores 87% here and
  not more: it is not backing off too often, it is backing off **past the bottom of the
  pipe**. The condition is `β·W_peak ≥ BDP`, i.e. `β ≥ 20/32 = 0.625`, and the sweep's
  knee is exactly there — 0.60 gives 91%, 0.65 gives 95%.
- **Upper bound.** Mean window is about `(1+β)/2 · W_peak`, and R4's average queue ≤ 5
  means mean window ≤ 25, which caps β near 0.72. The table shows it failing at 0.75.

β = 0.70 sits inside both with margin on each. I deliberately did not take 0.75 (99%,
queue 5.13) or even 0.72 (98%, queue 4.70): the requirement is a hard limit at 5.0 and a
6% margin on a tuned constant is not a design, it is a fit to one benchmark.

**One thing the code does that is not in the textbook formula, and an honest note about
it.** The harness reports loss by calling `on_loss()` once *per timed-out packet*, and a
queue overflow drops several packets at once — so one congestion event can produce a burst
of `on_loss()` calls in the same slot. Applying β to each would multiply the window by
β^n and collapse it. Real TCP reduces at most once per RTT; with no clock here, the
stand-in is "a window's worth of ACKs has arrived since the last reduction".

I then measured whether it actually does anything on this benchmark, and it does not:

| β | guard | goodput | loss | avg queue |
|---:|---|---:|---:|---:|
| 0.70 | none — cut on every loss | 955.2 | 0.5% | 4.55 |
| 0.70 | **1 window of ACKs (mine)** | **955.2** | **0.5%** | **4.55** |
| 0.70 | 2 windows of ACKs | 977.8 | 0.8% | 6.43 — fails R4 |
| 0.50 | none | 853.8 | 0.4% | 3.21 |
| 0.50 | 2 windows of ACKs | 950.2 | 0.5% | 4.58 |

At β = 0.70 the guard is **exactly neutral** — identical to the fourth decimal — because
only 18 packets are ever retransmitted in 4000 slots and the losses never arrive in
bursts big enough to matter. So it is insurance this particular run never claims, kept
because the failure it prevents is catastrophic and its cost here is provably zero, not
because it earns anything.

And the row above it is a trap worth naming. Widening the guard to two windows *looks*
like a free +23 goodput, but what it actually does is suppress legitimate reductions —
which is just a gentler backoff wearing a different hat, and it shows up immediately as
queue 6.43 and a failed R4. Every apparent free lunch in this task turns out to be the
same trade priced differently: goodput against the queue you leave behind for everyone
else.
