# Week 3 · Observations

---

## Task 1 — the iterative resolver

**Why the root did not just hand me the address.** Because it does not know it, and
the design is deliberate about that. A root server is authoritative for the root zone
only, and the root zone contains exactly one kind of information: which servers are
authoritative for each TLD. When I asked `a.root-servers.net` for `www.adobe.com` it
returned `ANCOUNT=0` and thirteen `NS` records for `com` — not an answer, a pointer.
That is what makes DNS scale: the root is asked about every name on the internet, so
it must answer in O(1) knowledge, and it does that by knowing only the next step.
Storing every address at the root would mean the root had to be updated whenever any
zone anywhere changed a record.

**What I did when a delegation arrived without glue, and what it cost.**
`www.adobe.com` is the real case in the fixture list. `.com` delegates `adobe.com` to
`a1-217.akam.net`, `a10-64.akam.net` and four more — all of them out of bailiwick, so
`.com` has no authority to publish their addresses and the additional section comes
back empty of usable glue. I cannot ask a nameserver whose address I do not have, so I
suspended the walk and started a **second full walk from the roots** for
`a1-217.akam.net`, then resumed with the address it produced. That nested walk cost
**3 extra queries** (root → `.net` → `akam.net`), taking `www.adobe.com` from what
would have been ~4 queries to **13**. Compare `www.korea.ac.kr`, which is fully glued
end to end: **3 queries**. This is where the recursion in "recursive resolver" actually
lives — it is not the CNAME chasing, it is this.

I also had to guard it. A nameserver name that lives *inside* the zone being delegated
(`ns1.adobe.com` for `adobe.com`) is unresolvable without glue by construction —
finding its address would mean asking the very servers I am trying to locate — so I
skip those names rather than recursing into a loop. And the nested walk spends from the
*same* query and wall-clock budget as the outer one, so a glue-less nameserver whose
own nameserver is also glue-less cannot escape the depth cap by recursing.

**How many servers for one name.** 3 for `www.korea.ac.kr`, 3 for `dns.google`, 6 for
`en.wikipedia.org`, 6 for `www.stanford.edu`, 10 for `www.microsoft.com`, 13 for
`www.adobe.com`. My laptop normally asks **one** question and gets one answer, because
the ISP resolver at `61.41.153.2` absorbs all of that work — and, far more importantly,
*caches* it. The 13 queries for `www.adobe.com` are the cold-cache cost. A real
resolver pays it once and then serves `.com`'s nameservers out of cache for two days.
Task 3 is the other half of this same story: the reason one question suffices is that
somebody upstream is doing what Task 1 does and then honouring the TTL.

**The CDN name did match, and that is slightly lucky.** `www.microsoft.com` came back
`104.94.218.45` from my walk and the same address from the system resolver. It did not
have to: Akamai answers `www.microsoft.com` differently depending on which resolver
asks and from where, and in Task 2 the same name returns `23.41.38.100` to Quad9 in the
same minute. The two agreed here because my walk and my system resolver are both in
Seoul on the same network, so Akamai steered both to the same POP. `www.adobe.com` is
the counterexample within my own data — Task 2 recorded **5 distinct address sets** for
it across 5 resolvers.

**One change to the harness, declared.** `dig` is not installed on this machine
(Windows; `dig` ships with BIND), so `dig_answer()` would have returned an empty list
for every name and `--verify` would have reported 0/5 with four fictitious failures. I
left the `dig` path in place and added a fallback to `socket.getaddrinfo`, which goes
through the OS stub resolver and therefore asks *the same* recursive resolver that
`dig +short` would have asked. The comparison being made is unchanged — my iterative
walk against the system's recursive answer — only the transport differs. Two caveats:
`getaddrinfo` may be served from the Windows DNS Client cache, and it returns the A
RRset without the TTL or the CNAME chain. Result: **5/5 ok**.

---

## Task 2 — on the wire, and does DNS really steer you?

**Delegation vs. answer, in one sentence, from the packets.** They are the *same
message format* — frame 2 (838 bytes, from `198.41.0.4`) and frame 10 (60 bytes, from
`193.108.91.67`) have the identical 12-byte header and the identical four-section
layout; the delegation has `ANCOUNT=0` with 13 `NS` records sitting in the **authority**
section and 27 glue records in the additional section, while the answer has `ANCOUNT=1`
with an `A` record in the **answer** section and `AA=1`. A delegation is not a different
kind of packet or a different message type: it is the same packet with a different
section filled in. Reading that off parsed text in Task 1 genuinely did not convey it —
I had inferred "a delegation" as a concept, and it is really just an empty answer
section.

**The largest response, and why.** **854 bytes** — the `com` delegation from a root
server. It is large because a delegation has to be self-contained: 13 `NS` records
naming the servers, plus 27 additional records carrying an `A` and an `AAAA` for almost
every one of them, because a resolver told "ask `a.gtld-servers.net`" and given no
address would be stuck. I checked what happens without EDNS0 by asking the same
question twice: **491 bytes with `TC=1` and only 11 additional records** — the server
drops most of the glue and tells you to come back over TCP. Advertising a 1232-byte
EDNS0 buffer gets all 838 bytes in one datagram. The 512-byte limit in RFC 1035 is the
reason EDNS0 exists, and I hit it on the very first query of the very first walk.

**My third-party rule.** Content delivered by infrastructure a *different organisation*
operates — explicitly not "somebody else hosts the DNS", because Netflix's DNS is on
AWS Route 53 while its video comes off Netflix's own Open Connect boxes. "Same domain"
means the registrable domain under the Public Suffix List, not the last two labels.
Then, in order: known-CDN-operator suffix ⇒ third party; left the origin domain but the
two zones publish the identical NS RRset (or the PTR lands back in the origin) ⇒ own
infrastructure under a second brand; left the origin and matched nothing ⇒ flagged as
third party with the operator *unclassified* rather than guessed; and no CNAME at all ⇒
do not stop, look at whether the resolvers disagree and where the PTR points.

**The two sites the naive rule gets wrong.**

- **`www.wikipedia.org` — false positive.** Naive compares `wikipedia.org` with
  `wikimedia.org`, sees different labels, says third party. It is not: the two zones
  publish the **identical NS RRset** (`ns0/ns1/ns2.wikimedia.org`) and the address
  `103.102.166.224` PTRs to `text-lb.eqsin.wikimedia.org` — the Wikimedia Foundation's
  own Singapore load balancer. All five resolvers return that one address. The naive
  rule mistook a brand boundary for an organisational one.
- **`www.github.com` — false negative, and the more interesting one.** The chain is
  `www.github.com → github.com`, so naive compares `github.com` with `github.com` and
  concludes "no CDN". But four resolvers return `20.200.245.247` and Quad9 returns
  `20.27.177.113` — two different addresses in Microsoft Azure space for a name with
  **zero CNAMEs**. Something is selecting a replica. "No CNAME ⇒ no CDN" is exactly the
  blind spot, and it is invisible to any rule that only reads names.

Two more sites are right for the wrong reason: `www.bbc.co.uk` and `www.korea.ac.kr`.
The naive rule's "domain" for them is `co.uk` and `ac.kr` — **public suffixes**, which
nobody owns. It computed a meaningless value for 2 of 12 sites and got the verdict by
luck. Had the BBC CNAMEd to a third-party edge at, say, `edge.somecdn.co.uk`, naive
would compare `co.uk` with `co.uk`, call them equal, and report "not third party".

And `www.apple.com` is right only because I followed the chain to the *end*: its first
hop is `www-apple-com.v.aaplimg.com`, and `aaplimg.com` publishes the identical NS
RRset as `apple.com` — it is Apple's. A rule judging on the first hop would have called
Apple third-party-delivered on the strength of a domain Apple owns. The genuine third
party is two hops further on at `akamaiedge.net`.

**The steering number: 8 of 9 third-party-delivered sites answered differently to a
different resolver.** Does that support claim (b)? **Partly, and I do not think it
supports it as strongly as the raw count suggests.**

For it: `www.adobe.com` returned **five distinct address sets to five resolvers**. My
ISP's own resolver (`61.41.153.2`) and Google (`8.8.8.8`) both landed on
`121.254.136.x` — a Korean Akamai POP — while Quad9 got `23.54.118.x`, Cloudflare
`23.59.72.x` and KT `23.35.218.x`. `www.apple.com` gave four distinct answers. That is
DNS-based replica selection, working on the mechanism the lecture describes.

But the detail that complicates it is worth stating: **KT's resolver is also in Seoul,
and it did *not* get the Korean POP for Adobe** — it got the same non-Korean Akamai
range as the anycast resolvers. So "resolver near me ⇒ replica near me" failed on one
of the two domestic resolvers I tested. The two that hit the Korean POP were my ISP's
resolver and Google, and Google is the one resolver in the set that **sends EDNS Client
Subnet** — it forwards my `/24` to Akamai, so Akamai is steering on *my* address rather
than on Google's. That is a better explanation of the data than proximity: what predicts
a nearby replica here is whether the resolver tells the CDN where the client is, not
where the resolver itself sits.

Against it, three things the count hides. First, **all the public resolvers are
anycast** — queried from Seoul, `8.8.8.8`, `9.9.9.9` and `1.1.1.1` all land on nearby
Asian POPs, so they are not three vantage points but roughly one, and I cannot
manufacture geographic distance by choosing a US-branded IP. Second, much of the
variance is **ECS policy rather than geography**: Google sends EDNS Client Subnet,
Quad9 and Cloudflare deliberately do not, which is why Quad9 is the odd one out on
Microsoft and GitHub. Third, **some replica selection happens below DNS entirely** —
`www.stanford.edu` returns the identical pair `15.197.167.90, 3.33.186.135` to every
resolver because Netlify fronts it with AWS Global Accelerator anycast, and
`www.wikipedia.org` likewise. For those, BGP chooses the replica and DNS has nothing to
steer. Counting "different address ⇒ DNS steering works" would credit DNS with BGP's
work.

**B3 and what it is worth.** Phone tethering was not available, so I took the path (B)
route the task allows — five resolvers at different distances, two of them definitively
Korean — and I want to be clear that this changes the question from "does DNS steer by
*where I am*" to "does DNS steer by *which resolver I ask*". Only the second is tested.
**The number is therefore a lower bound.** `--collect --network <label>` merges a second
run, so one command on tethering would complete B3 properly.

**About `out/dns.pcapng`.** Wireshark, tshark and Npcap could not be installed here, so
there was no capture driver. The file was written by `task2_steering.py --capture`,
which taps the resolver's own sockets: **the DNS payload of every packet is the exact
byte string this machine sent or received, with the real transaction IDs, real ephemeral
source ports and real timestamps**, but the Ethernet/IPv4/UDP framing around it is
reconstructed — the MACs are placeholders (`02:00:00:00:00:01/02`) and the IPv4 TTL is
set to 64 in both directions and is **not** an observed value. Everything above the UDP
header is genuine traffic; everything below it is reconstruction. This is stated in the
file's own section-header comment, on every individual packet comment, and in
`report.md §7`. It is not a substitute for a real capture and I have not treated it as
one.

---

## Task 3 — the cache, and its floor

**The two defects, and the one root cause.** `BaselineCache` does
`address, ttl = self.upstream(name)` and then **throws `ttl` away**, keeping everything
for a hard-coded `FIXED_LIFETIME = 60`. One discarded variable, wrong in both
directions:

- **Correctness.** Every one of the 266 stale answers comes from the two names whose
  TTL is *under* 60 s: `www.microsoft.com` (TTL 20) contributes 189 and `www.cnn.com`
  (TTL 30) contributes 77. The worst single answer was served **39.81 seconds** past
  its expiry — roughly three TTLs of shelf life on a 20-second record; the mean overrun
  was 19.27 s.
- **Performance.** The seven names whose TTL is *over* 60 s get thrown away while still
  valid, costing **145 needless round trips**. `a.root-servers.net` has an **86400-second
  TTL and is refetched 20 times in one hour**. `www.stanford.edu` (TTL 3600) costs 27
  fetches where 1 would do.

They net out to 325 against a floor of 275. The short-TTL names appear to "save" 95
fetches, but only by handing out 266 expired records — that is not a saving, it is the
bug.

**The record it handles worst: `www.microsoft.com`.** It is worst on *both* axes at
once. Shortest TTL in the fixture (20 s, a 3× mismatch against the fixed 60) and top
Zipf weight (index 0, weight 1/1, **322 of the 1000 queries**). The two multiply:
**189 of the 266 stale answers — 71% — are this one name.** That is realistic rather
than a quirk of the fixture, because CDN names carry short TTLs precisely *because* they
are hot and need re-steering, so a fixed lifetime does its maximum damage exactly where
the traffic is. The tell is `www.netflix.com`: its TTL is exactly 60, and the baseline
is perfectly correct on it — 37 fetches, which is its own floor, and 0 stale. The
baseline is not a cache with a tuning parameter; it is a cache that is right for one
TTL value out of ten.

**The floor is 275, and my cache is already sitting on it.**

The cache has no clock of its own. Its only entry point is `lookup(name, now)`, so every
upstream call it will ever make happens at one of the 1000 query instants. A fetch at
time `t` covers exactly `[t, t+TTL)` — it cannot cover anything earlier (the record did
not exist yet) and correctness forbids anything at or after `t+TTL`. Since the cache
starts empty, every query for a name must fall inside some fetch's window: **the fetch
times must be an interval cover of that name's query times, using windows of length TTL
whose left endpoints are themselves query times.**

Greedy — fetch at the first query, then at the first query at or after the current
record expires — is optimal, by the standard stays-ahead argument. If `g_i ≥ f_i` for
any correct cache's i-th fetch, then `g_i + TTL ≥ f_i + TTL`, so greedy's first i
windows cover at least what the other cache's do; the first query greedy leaves
uncovered is therefore at or after the first one the other leaves uncovered, and the
other cache must spend a fetch no later than greedy does. So it can never use fewer.

Summing the per-name greedy covers: 118 + 76 + 37 + 23 + 11 + 6 + 1 + 1 + 1 + 1 =
**275**. I computed this independently of the cache and then confirmed that the cache's
actual per-name fetch counts equal it name by name.

The three things that might look like a way under it, and why none is:

- **Prefetching or early refresh?** No. A fetch is still one `up.calls` increment
  whenever you make it, and making it *earlier* than the first uncovered query ends the
  window earlier, covering a strict subset of the queries for the same price. Refreshing
  early is never better and is usually worse.
- **One fetch serving two names?** No. `Upstream.__call__(name)` takes a single name and
  does `self.calls += 1` — no batching, no wildcard, no zone transfer. The ten names are
  ten independent subproblems, which is why the floor is a clean sum.
- **A better data structure?** No, and this is the part worth saying out loud. The
  upstream count is a function of *which queries get covered*, not of how fast you find
  an entry. A dict, a trie, an expiry heap and an LRU all produce 275. `sim time` in the
  harness is literally `up.calls × 20 ms`, so it is the same number in different units.
  Replacing the baseline's linear scan with a dict fixes CPU time, which the harness
  never measures.

So the striking conclusion is that **the optimum is the naive algorithm**: a plain dict
of `name → (address, expires_at)` that fetches on a miss and expires at `now >=
expires_at` scores 275/0, and there is nothing clever left to gain. That is exactly what
the TTL is for — the authoritative server, not the cache, decides how long its answer
lives, and a correct cache does not get a vote.

**One harness loophole I noticed and did not use.** The staleness check is external and
only asks `if up.calls > before`, so a cache that called `upstream(B)` during a
`lookup(A)` would make the harness credit `fresh_until[A]` and silently mask a stale A.
It is an accounting artifact, not a win — hiding one stale A costs exactly the one round
trip that honestly refetching A would have cost — and it would violate R2 in spirit, so
`YourCache` does not do it.

**Minor things also wrong with the baseline, none of which change the score.** The
linear scan is O(n) where a dict is O(1); `self.entries.remove(entry)` mutates the list
while iterating over it (the `break` immediately after makes it accidentally safe, so
it is latent rather than live) and is itself a second O(n) scan; nothing is ever evicted
unless the same name is looked up again, so entries leak; and `stats()` reports
`len(self.entries)` as if it were a live-record count when it includes expired
records. All real, all worth fixing, and **none of them moves a single number in the
harness output** — only the discarded TTL does. That separation is the lesson the task
was pointing at: one of these problems is worse than being slow.
