# Week 7 · Observations

Full evidence: `arp-analysis.json` (every frame, timed from the clear), `arp-run.log`, `bench.txt`, `compare.txt`, `attack.txt`.
Task 2 was measured as Administrator on my Wi-Fi (pktmon); `arp.pcapng` is that capture in Ethernet II form.

## Task 1 · a learning switch

`--verify` 7/7. Never back out the arrival port: if S2 bounced A's broadcast to S1, S1 would flood it back to S2 —
a storm on one cable, no loop needed — and S1 would learn A on the uplink and send A's unicast the wrong way.
Flood vs drop: a switch's "unknown" is a station not heard yet in one small LAN; the flood reaches it and its reply
teaches the switch. A router's "unknown" is no route on the whole internet — flooding would copy it everywhere, so drop.
Time-based aging: a station that moves or leaves silently is still sent down the old port for up to 300 s, and a quiet
one still there is forgotten. More direct: flush a port on link-down, STP's topology-change notice, or a gratuitous ARP.

## Task 2 · watch ARP happen

A2 gateway `.1` first: asked for 78 ms after the clear, 4.4 s before my ping (frame 5) — every off-link packet's next hop.
A3 Wi-Fi 10 → 2: only what I sent to (`.1`, `.100`) returned, not `.107`; the 7 static multicast/broadcast are not ARP.
A4 `163.152.6.10` (korea.ac.kr) is absent: ARP resolves only next hops on my link; off-link, I send to the gateway's MAC.
B1 frames 5/6, 3.8 ms apart. B2 request → `ff:ff:ff:ff:ff:ff` (broadcast), reply → `58:86:94:fe:83:ab` (my own MAC).
B3 every station got the request (I heard `.101` ask for `.1`, frame 13), only the asker the reply (never saw `.101`'s).
B4 21 ARP frames/min, 3 broadcast. × 1,000 hosts (assumed, a /22): 21,000/min, and each host gets 17–50 broadcasts/s.

## Task 3 · a switch that runs out of room

Evidence: a 4×256 count-min sketch of how often each MAC is heard *or asked for*, halved every 2,000 updates.
Fixed size, no ports in it. Eviction: lowest estimate leaves, ties → least recent. **49% cut, missed 0 → strong.**
Admission: when full, a newcomer gets in only if its estimate beats the victim's. From LRU's 32%, either fix alone
reaches 48% (both stop one-time speakers pushing out busy ones); together 49%. Never halving: 51%, as nobody moves here.
R6: fake source MACs from one port push everyone out — the baseline floods 49% of real unicast (15% without), 7,541
copies to the attacker: a hub, so eavesdropping. Mine: 13–17%, still leaks. The fix is port security: cap MACs per port.
