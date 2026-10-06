# Week 6 — Routing and Reconvergence

Lab for *Computer Networking: A Top-Down Approach* §5.2 (link state, distance vector)
and §5.3 (OSPF).

| | Task | Built | Result |
|---|---|---|---|
| 1 | Link state by hand | Dijkstra and the forwarding table it produces, `heapq` only | **all ok** (10 checks) |
| 2 | Break a real network | four traceroutes, and three FRR routers in Docker timed through six events | link-down **0.32 s** · silent cut **35–38 s** · repair **7–15 s** · cost change **0.4 s** |
| 3 | Reconverge without recomputing the world | a router that keeps distances and propagates improvements | **strong** — 79% of SPF runs avoided (212 vs 1001), 0 wrong |

## Running it

```bash
python task1_linkstate.py --verify
python bench.py --yours
python test_tasks.py           # 9 passed, 0 failed, 1 skipped (R5 is graded by a human)
```

Task 2 Parts B and C need the lab repository's `compose.yml` and Docker. Here Docker ran
inside WSL2 (Ubuntu 24.04, `apt install docker.io docker-compose-v2`), and the measurement
ran there as root, because the silent cut detaches a veth on the host:

```bash
docker compose --profile routing up -d r1 r2 r3
python3 task2_ospf.py --out out
```

## What is here

| File | |
|---|---|
| `task1_linkstate.py` | `dijkstra`, `forwarding_table` |
| `task2_ospf.py` | the reconvergence measurement (written for this week, see below) |
| `task3_reconverge.py` | `YourRouter` (`FullRecompute` and `dijkstra_table` are the assignment's, untouched) |
| `bench.py`, `test_tasks.py`, `scenario.sh`, `topology/` | the course files, unmodified |
| `out/observation.md` | the write-up |
| `out/reconverge.txt` | every measured time, per router, with the method |
| `out/route-before.txt`, `out/route-after.txt` | all three routers' tables, plus neighbours and timers |
| `out/cost-change.txt` | Part C, tables before and after |
| `out/traceroute.txt` | Part A |
| `out/ospf-timeline.json` | every table change with its timestamp |

## Four problems in the course files, found while doing this

**1. The router image in `compose.yml` does not exist.** `frrouting/frr:v9.1.0` cannot be
pulled. Docker Hub's `frrouting/frr` stops at `v8.4.1` (December 2022), and FRR 9.1.0 is
published as `quay.io/frrouting/frr:9.1.0`, with no `v` prefix. I used that image, changing
only my working copy of `compose.yml`.

**2. `scenario.sh cut` cannot measure reconvergence.** It reports "reconverged" as soon as
r1's `show ip route ospf` text changes. That text includes a per-route uptime counter that
changes every second. Two snapshots 2.2 s apart, with nothing changed, differed in 4 lines
(`reconverge.txt` shows them), so the script would report about one second for any cut.
`task2_ospf.py` compares only prefix, metric and next hops. It watches all three routers and
also times the repairs. `cut` also saves only r1's table, while B1 asks for all three.

**3. The hello and dead intervals are not in `frr.conf`.** `task2.md` says to find them
there. They are FRR's defaults (Hello 10 s, Dead 40 s, Wait 40 s), read here from
`show ip ospf interface`.

**4. Interface numbering is not stable.** In this run Docker attached r3's net_a as `eth0`,
while r3's `frr.conf` description says `eth0` is net_c. `task2_ospf.py` identifies each
network by its subnet instead.

## Findings worth reading

**Link-down does not wait for the dead interval, and a silent cut does.** Bringing r1's
interface down (what `scenario.sh` does) reconverged everywhere in 0.32 s. The router sees
its own link go down and floods a new LSA at once, so hello and dead play no part. When the
link was cut silently (detached from its bridge, with both interfaces still UP), nothing
changed for 35 s. Then the dead timer expired: 40 s minus the time since the last hello.
Repair was 7–15 s either way, because a new neighbour can only be seen at its next hello.
A cost change took 0.4 s, since nothing has to be detected, only flooded.

**`www.stanford.edu` never crosses the ocean.** It is AWS Global Accelerator anycast and
answers in 7 ms from an edge in Korea. `web.stanford.edu`, on Stanford's own network, shows
the crossing: +98 ms between Hurricane Electric's Tokyo and Seattle routers.

**Task 3's hint undersells what the third case needs.** It says the first two cases reach
about 45% and the third gets past 75%. Measured, the first two give 47%. Handling the third
case with an SPF only reaches 64%. Getting to 79% needed the improvement to be propagated
incrementally, with no SPF at all.
