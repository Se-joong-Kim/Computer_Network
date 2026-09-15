# Week 3 — DNS Hierarchy and CDNs

Lab for *Computer Networking: A Top-Down Approach* §2.4.2–2.4.3 (DNS hierarchy and
records) and §2.5 (video streaming and CDNs).

Three questions: **who actually answered, whose machine is it, and how long may we keep
the answer?**

| | Task | Built | Result |
|---|---|---|---|
| 1 | Resolve a name yourself | an iterative resolver, root → TLD → authoritative | **5/5** names agree with the system resolver |
| 2 | Does DNS really steer you? | 12 sites × 5 resolvers, plus a packet capture | **8 of 9** third-party sites answered differently |
| 3 | Beat the baseline cache | a TTL-respecting cache, and its floor | **275 upstream, 0 stale** — and 275 is the floor |

## Running it

Python 3.12, standard library only. No `dig`, no `dnspython`, no Wireshark required.

```bash
python task1_resolve.py --verify                 # 5 names, mine vs the system resolver
python task1_resolve.py www.adobe.com --trace    # the glue-less delegation, step by step
python task2_steering.py --capture               # Part A -> out/dns.pcapng
python task2_steering.py --verify-capture        # re-read and check that file
python task2_steering.py --collect --network X   # Part B -> out/chains.json
python task2_steering.py --report                # -> out/report.md
python bench.py --yours                          # Task 3, side by side
python test_tasks.py                             # 6 passed, 0 failed, 3 skipped
```

## What is here

| File | |
|---|---|
| `task1_resolve.py` | the iterative resolver **and** the DNS wire implementation everything else rides on — message parser, name-compression decoder, EDNS0, UDP with a TCP fallback |
| `task2_steering.py` | the steering measurement, the classification rule, the report generator, and the pcapng writer |
| `task3_cache.py` | `YourCache` (`BaselineCache` is the assignment's, left untouched) |
| `bench.py`, `test_tasks.py` | the course harness, unmodified, included so this folder runs standalone |
| `out/observation.md` | **the write-up — this is the actual submission** |
| `out/report.md` | the Task 2 study: classification table, steering number, Part A packet analysis |
| `out/chains.json` | raw measurement data; every table in `report.md` is generated from it |
| `out/dns.pcapng`, `out/capture-index.md` | the capture and its frame-by-frame index |
| `out/bench.txt` | `python bench.py --yours` output |

## Notes on the environment

This was done on Windows with no `dig`, no `dnspython`, no Docker and no packet capture
driver, which shaped three decisions worth flagging:

**DNS is implemented from scratch** on `socket` + `struct` rather than shelling out to
`dig`. The assignment allows either transport; doing it directly also meant Task 2 could
tap the resolver's own sockets. EDNS0 turned out to be load-bearing rather than optional:
the root's `com` delegation comes back **491 bytes with `TC=1`** without it and **838
bytes** with a 1232-byte buffer advertised.

**`dig_answer()` falls back to `socket.getaddrinfo`** when `dig` is absent. That asks the
same recursive resolver `dig +short` would ask, so the comparison is unchanged; only the
transport differs. Without this, `--verify` compares against an empty list and reports
four fictitious failures.

**`out/dns.pcapng` was not taken with Wireshark.** Wireshark/tshark/Npcap could not be
installed, so `--capture` writes the file itself from the resolver's own sockets. **The
DNS payload of every packet is the exact byte string this machine sent or received**, with
real transaction IDs, real ephemeral source ports and real timestamps — but the
Ethernet/IPv4/UDP framing around it is reconstructed, the MACs are placeholders, and the
IPv4 TTL is set to 64 and is *not* an observed value. This is stated in the file's own
metadata, on every packet comment, in `report.md §7` and in `observation.md`.

To replace it with a genuine capture:

```powershell
winget install --id WiresharkFoundation.Wireshark -e   # keep Npcap checked
# capture filter: port 53, on the interface you actually use
python task1_resolve.py www.adobe.com
# stop, File -> Save As -> out/dns.pcapng
```

That also installs `tshark.exe`; putting it on `PATH` turns the one Task 2 `skip` in
`test_tasks.py` into a real `PASS`.

**Task 2 requirement B3 asks for a second network** (campus Wi-Fi *and* phone tethering).
Only one was available, so this uses the path (B) route the assignment allows — five
resolvers at different distances, two of them domestic. The steering number is therefore
a **lower bound**, and `report.md §6` says what that weakens. Adding the second vantage
point needs no code change:

```bash
python task2_steering.py --collect --network phone-tether   # while tethered
python task2_steering.py --report                           # merges both runs
```

## The three findings worth reading

**Task 1 — where the recursion actually is.** `.com` delegates `adobe.com` to six
out-of-bailiwick nameservers with no glue, so resolving `www.adobe.com` requires
suspending the walk and starting a *second* walk from the roots for
`a1-217.akam.net` first. That is 3 extra queries, 13 total, against 3 for the fully
glued `www.korea.ac.kr`.

**Task 2 — the naive rule fails in both directions.** Comparing the last two labels
calls `www.wikipedia.org` third-party (it is not — `wikipedia.org` and `wikimedia.org`
publish the identical NS RRset, and the address PTRs to `text-lb.eqsin.wikimedia.org`)
and calls `www.github.com` first-party (it is not — four resolvers return
`20.200.245.247` and Quad9 returns `20.27.177.113`, two Azure addresses for a name with
zero CNAMEs). It also computes a public suffix rather than a domain for `www.bbc.co.uk`
and `www.korea.ac.kr`, getting those right by luck.

**Task 3 — the optimum is the naive algorithm.** The baseline's two faults are one bug:
it discards the TTL for a fixed 60 s, which serves short-TTL records after they died (all
266 stale answers come from the two names with TTL < 60; 189 of them from
`www.microsoft.com` alone, which is both the shortest-TTL *and* most-requested name) and
throws away long-TTL records that were still valid (145 wasted round trips;
`a.root-servers.net` has an 86400-second TTL and is refetched 20 times an hour). A dict
storing `now + ttl` scores 275/0 — and 275 is provably the floor, because a cache can
only fetch at a query instant and a fetch at `t` covers exactly `[t, t+TTL)`, so the
fetch times must be an interval cover and greedy is optimal. There is nothing clever
left to gain, which is the point of having a TTL at all.
