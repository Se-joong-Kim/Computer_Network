# Week 7 — Ethernet, ARP and Switching

Lab for *Computer Networking: A Top-Down Approach* §6.4.1 (MAC addresses, ARP) and §6.4.3
(link-layer switches).

| | Task | Built | Result |
|---|---|---|---|
| 1 | A learning switch | `Switch`: learning, flooding, aging | **all ok** (7 checks) |
| 2 | Watch ARP happen | my ARP table cleared as Administrator, refilled, captured with pktmon | gateway back **78 ms** after the clear · request → `ff:ff:ff:ff:ff:ff`, reply → my MAC, **3.8 ms** later · 21 ARP frames/min |
| 3 | A switch that runs out of room | LFU eviction from a count-min sketch, with admission control | **strong**: 49% fewer wasted deliveries, 0 missed |

## Running it

```bash
python task1_switch.py --verify
python bench.py --yours
python task3_compare.py        # each half of YourSwitch swapped out, measured
python task3_attack.py         # R6: the MAC-flooding attack, measured
python task2_arp.py            # reads the Task 2 capture back; needs no admin
python test_tasks.py           # 6 passed, 0 failed, 2 skipped
```

Task 2's measurement needs Administrator, because clearing the ARP cache and pktmon both
require it. On Windows:

```powershell
Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','task2_arp.ps1'
```

There are two skips. `test_tasks.py` checks the capture's ARP opcodes with tshark, which is
not installed here. The same check done with scapy finds opcodes 1 and 2: 11 requests and
10 replies. R6 is graded by a human.

## What is here

| File | |
|---|---|
| `task1_switch.py` | `Switch` |
| `task2_arp.ps1` | the measurement: snapshot, clear, watch the refill, ping, curl, 60 s of capture |
| `task2_arp.py` | reads the capture (802.11 or Ethernet), lines it up with the clear, writes `arp-analysis.json` |
| `task3_flooding.py` | `YourSwitch` (`NaiveSwitch` is the assignment's, untouched) |
| `task3_compare.py` | the policy comparison below |
| `task3_attack.py` | R6: fake source MACs injected from one port, against both switches |
| `bench.py`, `test_tasks.py` | the course files, unmodified |
| `out/observation.md` | the write-up |
| `out/arp-before.txt`, `out/arp-after.txt` | A1 |
| `out/arp-cleared.txt`, `out/arp-refill-log.txt` | the table 0.11 s after the clear, then every 0.5 s (A2) |
| `out/arp-run.log` | every step with its Unix-ms timestamp |
| `out/arp.pcapng` | Part B, as Ethernet II |
| `out/arp-pktmon-raw.pcapng` | the same capture exactly as pktmon wrote it |
| `out/arp-analysis.json` | every frame timed from the clear, and the A2–B4 answers |
| `out/bench.txt`, `out/compare.txt`, `out/attack.txt` | Task 3's numbers |

## Problems met on the way

**1. On Wi-Fi, pktmon writes 802.11 frames into a file labelled Ethernet.** Wireshark is not
installed here, so Windows' built-in `pktmon` did the capture. `pktmon etl2pcap` marks the
interface as linktype 1 (Ethernet). On a Wi-Fi adapter, though, each frame it records is an
802.11 data frame: a 24-byte 802.11 header, then LLC/SNAP, then ARP. Read as Ethernet, every
frame is nonsense (destination `08:42:30:00:58:86`, type `0x4b02`). `tshark -Y arp`, the check
`test_tasks.py` runs, would find nothing.

`task2_arp.py` fixes this:
- It decodes the 802.11 header. Which address field holds the destination depends on the
  ToDS and FromDS bits.
- It keeps pktmon's file as `arp-pktmon-raw.pcapng`.
- It writes `arp.pcapng` as Ethernet II, with the same MACs, the same ARP bytes and the same
  timestamps. That is how Wireshark shows Wi-Fi traffic on Windows anyway.

Read back with scapy, the new file holds 21 ARP frames.

**2. Two of `task2.md`'s commands do not work as written on Windows.** The command block is
labelled for Windows as well:
- `ping -c 3` does not set a count on Windows, where `-c` is a routing compartment. The count
  flag is `-n`.
- `tee` in Windows PowerShell 5.1 writes UTF-16.

`task2_arp.ps1` uses `-n` and writes ASCII.

**3. The trace is 48,954 frames, not "~58,000".** That is the figure `task3.md` gives.
`bench.py` draws 60,000 frames and drops each one whose destination came out the same as its
source. With these traffic weights, that drops 18% of them. Nothing depends on the number, but
the figures in `bench.txt` are out of 48,954.

## Findings worth reading

**I did not cause the first entry to come back.** My machine sent an ARP request for the
gateway 78 ms after the clear (frame 5), and the entry was in the table by 0.11 s
(`arp-cleared.txt`). The script did not ping anything for another 4.4 s. Background traffic
(Tailscale, Windows) leaves the subnet, and the gateway is the next hop for all of it. So the
Part B request/reply pair is that one, and the ping later found the entry already there.

**Windows broadcasts only when the cache is empty.** In one minute my machine asked who has
`.100` in three ways:

| when | how it asked | frames |
|---|---|---|
| 2 s before the clear | unicast, to `.100`'s known MAC | 3 |
| right after the clear | broadcast | 7 |
| after that, every ~10 s | unicast | 9–20 |

The gateway does the same to me, by unicast, every 39 s (frames 1 and 16). Windows checks
neighbours it already knows by asking them directly. So one ARP broadcast in that minute was not
caused by my clearing the table: frame 13, where `.101` asks for the gateway. Its reply never
reached me, which is B3 in a single frame.

**On Wi-Fi, a broadcast goes through the access point.** My broadcast request went to the AP
first, with 802.11 receiver address `80:ca:4b:02:76:37`. That is the router's radio; its LAN
MAC ends in `:35`. The AP then sent the request on to every station. Frame 13 is one of those
re-sends, received with receiver address `ff:ff:ff:ff:ff:ff`.

**Not every row of `arp -a` comes from ARP.**
- The 7 "static" rows on Wi-Fi are broadcast and multicast addresses. Their MAC is computed
  from the IP (`01:00:5e` plus the low 23 bits), so no one is asked. They come back only when
  used: `224.0.0.113` and `239.255.255.250` had returned a few minutes later.
- Tailscale's interface lists "dynamic" neighbours with no MAC at all. It is a layer-3 tunnel,
  so there is no link layer for ARP to resolve.

**Task 3: either half of the policy does most of the work.** From `compare.txt`:

| policy | wasted | cut |
|---|---:|---:|
| baseline: evict the oldest arrival | 323,380 | — |
| LRU, always admit | 218,500 | 32% |
| LFU, always admit | 168,360 | 48% |
| LRU, decline newcomers less popular than the victim | 166,980 | 48% |
| **LFU, decline (submitted)** | **163,806** | **49%** |
| same, counters never halved | 159,436 | 51% |
| same, sketch 4 × 64 | 213,578 | 34% |

LFU eviction and declining fix the same failure: a station heard once pushes out a busy one. LFU
removes the newcomer at the next miss; declining never lets it in. The halving costs 2% here only
because no station in this trace ever moves or leaves. Without halving, a station that left would
keep its standing forever, which is Task 1's aging problem again. A sketch only 64 counters wide
mixes stations up and loses most of the gain.

**R6, measured.** In `task3_attack.py`, during the middle third of the trace, one port sends 3
frames from fresh fake source MACs for every real frame. That window holds 15,451 real unicast
frames:

| switch | no attack | under attack |
|---|---|---|
| baseline | 15% flooded | 49% flooded; 7,541 copies of other people's frames reach the attacker's port |
| mine | 8% flooded | 13% flooded; 17% when the attacker reuses each fake MAC 5 times to look popular |

Under the attack the baseline switch has turned into a hub, and the attacker reads traffic
meant for others. Declining newcomers raises the attacker's cost but does not stop the attack.
Per-port MAC limits (port security) do.
