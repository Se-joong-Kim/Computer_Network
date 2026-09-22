# Week 4 — TCP: Reliability, Measurement, Congestion

Lab for *Computer Networking: A Top-Down Approach* §3.4 (reliable data transfer), §3.5
(handshake and sequence numbers) and §3.7 (congestion control).

| | Task | Built | Result |
|---|---|---|---|
| 1 | Reliable delivery over a bad channel | selective-repeat sender and receiver | **IDENTICAL** on every seed, incl. a 30%-loss stress case |
| 2 | Measure your own link, twice | a throughput study + a TCP/pcapng dissector | home **137 Mbps** / 8.5 ms vs KU campus **71 Mbps** / 22.5 ms |
| 3 | Beat the fixed window | slow start + AIMD with β = 0.70 | **strong** — 97% goodput, loss 37.4% → **0.5%**, queue 8.8 → **4.6** |

## Running it

Python 3.12, standard library only. No `dnspython`, no Wireshark, no `tshark`.

```bash
python task1_rdt.py --verify                   # the stated pass condition
python task1_rdt.py --verify --seed 999        # a different seed
python task1_rdt.py --selftest                 # stricter - see "A harness bug" below
python task2_measure.py --fetch-trace          # restore out/tcp.pcapng (not in this repo)
python task2_measure.py --analyze              # Part A: answers A2-A5 from the capture
python task2_measure.py --label "home-wifi X"  # Part B: 5 transfers, appends to out/
python bench.py --yours                        # Task 3
python test_tasks.py                           # all of it
python ../check.py w04                         # submission format
```

## What is here

| File | |
|---|---|
| `task1_rdt.py` | selective-repeat sender and receiver, plus `--selftest` |
| `task2_measure.py` | throughput measurement **and** a pure-Python pcapng/Ethernet/IPv4/TCP dissector with full TCP option parsing |
| `task3_congestion.py` | `YourControl` (`FixedWindow` is the assignment's, untouched) |
| `bench.py`, `test_tasks.py` | the course harness, unmodified |
| `out/observation.md` | **the write-up — this is the actual submission** |
| `out/throughput.json` | the measured transfers |
| `out/capture-analysis.json` | machine-readable A2–A5 answers |
| `out/bench.txt` | `python bench.py --yours` output |

## Two caveats on the measurements

**1. `out/tcp.pcapng` is not in this repository.** Part A uses the official Wireshark Lab
trace, which is the textbook authors' material and marked *All Rights Reserved*, so it is
not redistributed here. One command restores it:

```bash
python task2_measure.py --fetch-trace
```

> Wireshark lab trace files from J.F. Kurose and K.W. Ross,
> *Computer Networking: A Top-Down Approach*, 9th ed.
> <https://gaia.cs.umass.edu/kurose_ross/>
> Copyright 1996-2025 J.F. Kurose, K.W. Ross. All Rights Reserved.

Why path (B) rather than my own capture: Wireshark, `tshark` and Npcap could not be
installed on this machine, and Windows' built-in `pktmon` refuses without administrator
rights (`액세스가 거부되었습니다`, exit 5). Part B **is** my own link and my own machine.

**2. B1's second vantage is an exit node, not a second physical link.** Phone tethering was
not available, so the second measurement routes through my own laptop on the KU campus
network, enabled as a Tailscale exit node. The egress genuinely changes — verified public
IP `58.78.x.x` (home ISP) → `163.152.233.19` before measuring — but **the local Wi-Fi is shared by
both measurements**. It is one local link with two egress paths, not two independent access
networks, and the tunnel adds WireGuard encapsulation. That is why B5 decomposes the result
rather than attributing all of it to RTT.

## The three findings worth reading

**Task 1 — reordering is what picks the protocol, and I measured it.** On a channel with
*only* reordering (no loss, no duplication), selective repeat sends 250 packets — the
theoretical minimum — while Go-Back-N sends **643** and discards **393 correctly-arrived
packets**, because its receiver refuses anything but the next expected sequence number.
Separately, the cost of reliability turns out to be exactly predictable: 309 transmissions
for 250 packets of data is `250/(1−0.10)² = 308.6`, because the data *and* its ACK each
have to survive the loss. At 30% loss the model says 510 and the measurement is 499.

**A harness bug worth knowing about.** `verify()` builds its test payload with
`bytes(random.Random(seed).getrandbits(8) for _ in range(size))`, which constructs a
**new** `Random(seed)` every iteration — so all 2000 bytes are identical (`0xed` for seed
246). SHA-256 of that is invariant under permutation, so **the stated pass condition
cannot detect a reordering bug**: a receiver that just appends packets in arrival order
passes it. I did not patch `verify()` (it is the pass condition and `test_tasks.py` calls
it); `--selftest` runs the same transfer against genuinely random data, one impairment at
a time, across five seeds.

**Task 2 — the receive window was never the limit.** The server advertised up to 194,816
bytes after scaling (×128, from `WindowScale=7` on the SYN-ACK) and the client never had
more than 75,296 bytes outstanding — 38.6% of what it was offered. Measuring peak bytes in
flight per round trip shows why: **3 → 6 → 12 → 24 → 47 segments, exactly ×2.0 each RTT.**
That is slow start, never terminated by a loss, and the transfer ran out of data at 8.6
RTTs. `min(cwnd, rwnd)` had `cwnd` as the smaller term for the whole connection.

**Task 3 — the backoff factor is pinned between two computable bounds.** Loss appears only
above BDP + queue = 30 in flight, so the window peaks near 32. Halving it (textbook Reno)
gives 16, which is *below* BDP = 20, so the link runs dry while the window climbs back —
that is why Reno scores 87% here, not because it backs off too often but because it backs
off past the bottom of the pipe. The condition is `β·W_peak ≥ BDP`, i.e. `β ≥ 0.625`. From
the other side, average queue ≤ 5 caps β near 0.72. β = 0.70 sits inside both with margin,
and the mean window lands at 24.9 = BDP + 4.9 — which is the measured average queue of
4.6, because **everything in flight beyond the bandwidth-delay product is by definition
sitting in a queue.**
