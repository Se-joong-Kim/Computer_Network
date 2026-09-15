# Week 3 · Observations

## Task 1 · The iterative resolver

**Why the root did not just hand me the address.** It does not have it. The root
zone contains delegations, not addresses: asked for `www.korea.ac.kr` it answered
with six `NS` records for `kr` and their glue, and an empty answer section. That is
the whole design — the root knows only who runs each TLD, so it stays small and
almost never changes, and the people who run `korea.ac.kr` can change their web
server's address without asking anyone above them. The price is that finding one
address takes several questions instead of one.

**When a delegation arrived without glue.** Glue is only present when the
nameserver lives *inside* the zone being delegated — `kr` must ship an address for
`c.dns.kr`, because there is no other way to find it. When the nameserver lives
elsewhere there is no glue and none is needed. `www.nytimes.com` hits this:
`xovr.nyt.net` is delegated to `dns1.p06.nsone.net`, and the reply names it without
an address. My resolver suspends the walk, resolves that name from the root with
the same code (`_servers_for` → `_resolve`, depth-capped at 3), and resumes. It
cost **3 extra queries** — a full root → `net` → `nsone.net` walk — out of 16 for
that name. This is the recursion in "recursive resolver": not a loop over one list
of servers, but a resolver calling itself on a different name.

**How many servers for one name.** `www.korea.ac.kr` took 3, `www.microsoft.com`
took 10 (three CNAME restarts, each from the root), `www.nytimes.com` took 16.
My laptop normally asks **one** question and gets the answer in one round trip,
because its resolver has done all of this already and cached every step — which is
also why Task 3 matters: the walk is expensive exactly once, and cheap forever
after, and that difference *is* the cache.

**The CDN name.** `--verify` sometimes matches `www.microsoft.com` exactly and
sometimes returns a different address than the reference resolver got a second
earlier. I know that is the CDN and not a bug in my walk because the *path* is
identical every time — the same CNAME chain, `www.microsoft.com` →
`www.microsoft.com-c-3.edgekey.net` → `e13678.dscb.akamaiedge.net`, ending at the
same Akamai authoritative servers — and only the final A record moves. A broken
resolver would end up at different servers or the wrong name, not at the same
server with a different answer. Asking that one authoritative server twice is
enough to see it hand out two addresses.

## Task 2 · The capture, and the steering

**Delegation vs answer, from the file.** Packet #2 and packet #6 in
`out/dns.pcapng` are the same message format with different sections filled in:
#2 (from the root) has ANSWER=0 and six `NS` records in AUTHORITY, meaning "not
mine, ask `kr`", while #6 (from `163.152.11.6`) has one `A` record in ANSWER with
the AA bit set, meaning "it is mine, and it is 163.152.6.10". In Task 1 a
delegation was a branch in my code; in the capture it is a count in a header.
The file is a log written by the resolver rather than a Wireshark capture off the
interface — the DNS payloads are real bytes, the IP/UDP framing is reconstructed,
and `out/report.md` says so where it matters.

**My rule, and the site it got wrong.** Follow the CNAME chain to its end, compare
**organisations** rather than domains — eTLD+1 first, so `www.korea.ac.kr` belongs
to `korea.ac.kr` and not to the `ac.kr` registry, then a table saying that
`wikipedia.org` and `wikimedia.org` are one foundation — and where there is no
CNAME, fall back to the addresses' PTR records. The naive "compare the last two
labels" rule is wrong on **2 of 12**: it calls `www.wikipedia.org` third-party
(different registrable domain, same foundation) and clears `www.github.com`.
Mine fixes the first and **still gets `www.github.com` wrong**: the CNAME points
inside `github.com`, which is what a self-hosted site looks like, but the address
`20.200.245.247` is Azure's. Azure publishes no PTR for it, so both my signals are
silent. Deciding it needs whois or an ASN table — data DNS does not carry. A rule
that got it right would contain a hard-coded fact, not a measurement.

**The steering number: 8 of 9 third-party-served sites answered differently to a
different resolver** (8 of 12 overall), from one network. It supports claim (a)
outright and claim (b) only partly. The strongest evidence is that four unrelated
Fastly sites split the same way every time — `{kt, system}` get `146.75.x`, the
three anycast resolvers get `151.101.x`. The strongest *counter*-evidence is
`www.adobe.com`: Google and the local resolver get Korean in-ISP addresses while
**KT's own resolver** gets the global range. Distance cannot explain that; EDNS
Client Subnet can, since Google forwards the client's prefix and other resolvers
do not. So part of what looks like "steering by location" is really "steering by
how much your resolver tells the CDN about you". And a different resolver is not a
different place: this is path (B), one vantage point, and claim (b) is about where
the *client* is. Testing it properly needs the second network (B3).

## Task 3 · The cache

**Two faults, one root cause.** The baseline replaces every record's TTL with
`FIXED_LIFETIME = 60`. That single decision produces both problems. *Correctness:*
anything with a TTL under 60 s is served after it expired — 266 of 1,000 answers.
*Performance:* anything with a TTL over 60 s is thrown away while it is still
valid, so the cache goes back upstream for an answer it was entitled to keep. The
linear scan of `self.entries` is a third fault, but it costs CPU only; it does not
change a single number the harness reports. Replacing the list with a dict keyed by
name and storing `now + ttl` fixes all three: **275 upstream, 72.5% hit rate, 0
stale.**

**The floor is 275, and it is not a property of my code.** An answer fetched at
time *t* is valid on `[t, t+ttl)` and nowhere else, so a cache that never serves an
expired record must cover every query time for a name with intervals of length
`ttl`. Covering points with fixed-length intervals takes fewest intervals when each
one is placed as far left as it can go while still covering the leftmost uncovered
point — and "fetch only when nothing valid is held" places them exactly there.
Fetching *earlier* only slides the window left and loses coverage on the right, so
prefetching cannot help. **No correct cache beats 275, not even one that knows the
entire future workload**; the number is set by the TTLs in the fixture and the
arrival times, and a cleverer data structure cannot move it. `python3
task3_cache.py --floor` recomputes it. Reaching the floor took a dict and one
comparison, which is the point: there was nothing to be clever about.

**The record it handles worst: `www.microsoft.com`** (TTL 20 s, 322 of the 1,000
queries). It is the fixture's shortest TTL and its most popular name at once, so
the 60-second lifetime is wrong for it for 40 out of every 60 seconds, and it is
asked often enough to be wrong constantly — most of the 266 stale answers are this
one name. `dns.google` (TTL 86400) is the same mistake in the other direction and
costs only round trips: one fetch would have covered the whole hour. Both come from
the same line of code, which is why naming them as one bug and two symptoms is more
useful than counting two bugs.
