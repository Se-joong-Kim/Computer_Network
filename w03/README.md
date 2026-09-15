# Week 3 · DNS Hierarchy and CDNs

Three tasks: resolve a name without `dig`, measure whether DNS really steers you
to a nearby replica, and beat a deliberately bad cache.

The write-up is [`out/observation.md`](out/observation.md); the measurement is
[`out/report.md`](out/report.md).

## Results

| | | |
|---|---|---|
| **Task 1** | iterative resolver, root → TLD → authoritative | **5/5** names agree with a recursive resolver |
| **Task 2** | 12 sites × 5 resolvers, CNAME chains and steering | **8 of 9** CDN-hosted sites answered differently to a different resolver |
| **Task 3** | TTL-respecting cache | **275 upstream, 0 stale** — down from the baseline's 325 upstream and 266 stale, and equal to the theoretical floor |

## Files

| file | what |
|---|---|
| `dnsproto.py` | DNS messages over raw UDP — build, parse (including 0xC0 compression pointers), EDNS0, TCP fallback, and a pcapng writer/reader |
| `task1_resolve.py` | the iterative resolver |
| `task2_steering.py` | the CNAME/steering measurement and the report generator |
| `task3_cache.py` | `YourCache`, plus `--floor` for the lower-bound argument |
| `bench.py`, `test_tasks.py` | the course's harnesses, **unmodified** |
| `out/` | everything that gets submitted |

## Running it

```bash
cd w03

# Task 1
python3 task1_resolve.py www.korea.ac.kr --trace     # watch the walk
python3 task1_resolve.py --verify                    # five names vs a recursive resolver
python3 task1_resolve.py www.nytimes.com --trace     # a delegation with no glue

# Task 2
python3 task1_resolve.py www.korea.ac.kr www.microsoft.com --pcap out/dns.pcapng
python3 task2_steering.py --collect --network home-wsl
python3 task2_steering.py --report

# Task 3
python3 bench.py --yours
python3 task3_cache.py --floor

# checks
python3 test_tasks.py
```

No dependencies. `dig`, `dnspython` and `tshark` are all optional — `dnsproto.py`
speaks DNS directly, and `task1_resolve.py` falls back to a public recursive
resolver for the reference comparison when `dig` is absent.

## Three things this submission is honest about

1. **`out/dns.pcapng` is a log written by the resolver, not a Wireshark capture
   off the interface.** Every DNS payload in it is real, byte for byte, with the
   real addresses, ports and timestamps; the IPv4/UDP headers around each payload
   are reconstructed, because a userspace program never sees the headers the
   kernel builds. This machine is a WSL2 guest with no capture privilege.
2. **Task 2 Part B has one vantage point, not two** — path (B) from `task2.md`:
   resolvers at different distances instead of two networks. `out/report.md` says
   what that weakens. Adding the second network is one command:
   ```bash
   python3 task2_steering.py --collect --network tethering && python3 task2_steering.py --report
   ```
   Every number in the steering section updates from the merged data.
3. **`www.github.com` defeats my third-party rule**, and the report says why
   rather than patching the rule to hide it.
