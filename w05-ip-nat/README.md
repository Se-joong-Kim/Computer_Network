# Week 5 — Addresses, Subnets, NAT, DHCP

Lab for *Computer Networking: A Top-Down Approach* §4.3.2 (IPv4 addressing, CIDR,
DHCP) and §4.3.3 (NAT, forwarding).

| | Task | Built | Result |
|---|---|---|---|
| 1 | Subnets and longest-prefix match | a CIDR parser and forwarding table from 32-bit integers, no `ipaddress` | **10/10** |
| 2 | Where exactly am I? | address study on two networks, NAT count, and a DHCP dissector | home **1 NAT** · tethering **2 NATs** (NAT64) · IPv6 **0** · DORA fully decoded |
| 3 | Make the lookup fast | one hash table per prefix length, longest first | **strong** — 1782× in `bench.txt`, 0 wrong, 0.3 MB |

## Running it

Python 3.12, standard library only. No Wireshark, no `tshark`.

```bash
python task1_forward.py --verify             # 10 cases
python task2_myaddr.py --collect "label"     # raw facts for this network -> out/addresses.json
python task2_myaddr.py --fetch-trace         # official DHCP trace -> out/dhcp.pcapng
python task2_myaddr.py --analyze-dhcp        # C1-C4 -> out/dhcp-analysis.json
python task2_myaddr.py --report              # everything -> out/report.md
python bench.py --yours                      # Task 3
python test_tasks.py
```

## What is here

| File | |
|---|---|
| `task1_forward.py` | `parse_cidr`, `network_range`, `ForwardingTable` — shifts and masks only |
| `task2_myaddr.py` | the given `--collect`, plus traceroute capture, a pcapng/UDP/BOOTP/DHCP dissector, and a report generator |
| `task3_lpm.py` | `YourTable` (`LinearTable` is the assignment's, untouched) |
| `bench.py`, `test_tasks.py` | the course harness, unmodified |
| `out/report.md` | the Task 2 analysis — A1–A5, C1–C4, and the path (B) question |
| `out/observation.md` | the write-up |
| `out/addresses.json`, `out/dhcp-analysis.json`, `out/bench.txt` | the evidence |

`--collect` still stores raw OS output and parses nothing, as `task2.md` asks. All parsing
happens at `--report` time, so the report can always be regenerated from the evidence.

## One caveat

**`out/dhcp.pcapng` is not in this repository.** Part C uses the official DHCP trace
(path B — no Wireshark, tshark or Npcap here, and `pktmon` needs administrator rights).
It is the authors' material, so `--fetch-trace` restores it rather than redistributing it.

> Wireshark lab trace files from J.F. Kurose and K.W. Ross,
> *Computer Networking: A Top-Down Approach*, 9th ed.
> <https://gaia.cs.umass.edu/kurose_ross/>
> Copyright 1996-2025 J.F. Kurose, K.W. Ross. All Rights Reserved.

## Findings worth reading

**The second network crosses two NATs, and traceroute alone could not show it.** On phone tethering (SK Telecom) the resolver synthesises AAAA records for `ipv4only.arpa` — `64:ff9b::c000:aa`, the RFC 6052 NAT64 prefix — so IPv4 is translated by the phone and again by the carrier's NAT64. Two more signs: the public IPv4 changed between requests a second apart (`211.234.201.129`, `211.234.201.66`), which a router you own never does, and hops 2–5 never answer in IPv4. On the same connection IPv6 crosses no NAT at all: the outside saw exactly the address the machine holds.

**The brief's CGNAT rule fails twice on one machine.** `task2.md` says a `100.64.x` address
means carrier-grade NAT and two layers. Here traceroute hops 4–8 are in `100.64/10` — but
they come *after* my packets already carry a public address, so they are ISP backbone, not a
NAT in front of me. And my Tailscale interface holds `100.111.74.12` — but it is a `/32`
with no gateway, origin `Manual`, that the default route does not use. An address range is
a registry convention, not a topology.

**The DHCP question's premise does not match the trace.** It asks why Discover is broadcast
and Ack "may not be". In the trace the Offer and Ack are both unicast, the broadcast flag is
clear in all six messages, and the *Request* is broadcast — for a different reason
(RFC 2131 §3.1: so other servers learn their offer was declined). And option 51 appears in
the Discover as 90 days: that is the client asking; the server granted 24 hours.

**`10.20.30.70` matches five entries, not four** — the brief does not count the default
route. And in Python the hash table beats the bit-walk trie 5.7×, which is exactly why
hardware builds the trie anyway: its cost is fixed and pipelineable, and a router has to
meet its worst case, not its average.
