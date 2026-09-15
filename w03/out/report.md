# Week 3 · Task 2 — On the wire, and does DNS really steer you?

Collected 2026-09-15T13:34:14+09:00 from 12 sites × 5 resolvers.
Vantage points on file: home-wsl.

## How this was measured, and what it is not

Neither `dig` nor `tshark` nor dnspython is installed on this machine, and
it is a WSL2 guest with no capture privilege on the interface, so two
things were done differently from the way the lab describes. Both are
weaker than the real thing and both are named where they matter:

- **Transport** is `dnsproto.py` in this folder — DNS messages built and
  parsed from raw UDP. Nothing is lost here; it is the same queries.
- **`out/dns.pcapng` is a log written by the resolver, not a capture taken
  off the interface.** The DNS payload of every packet in it is real, byte
  for byte as it left and entered this machine, with the real addresses,
  ports and timestamps. The IPv4/UDP headers around each payload are
  *reconstructed*: a userspace program never sees the headers the kernel
  builds. So the file proves what was asked and answered; it does not prove
  the traffic was observed independently of the program that made it.
- **Part B has one network, not two.** This is path (B) from `task2.md`:
  two resolvers at very different distances instead of two networks. See
  the steering section for what that weakens.

## Part A · The exchange on the wire

`out/dns.pcapng` — 26 datagrams, 13 queries and 13 responses, all of
them this resolver's own walk for `www.korea.ac.kr` and
`www.microsoft.com`. Nothing else on the machine is in the file, which
is the privacy problem a real `port 53` capture has and this does not.

**A2 · a query and its response.** Packet **#1** (192.168.219.111 → 198.41.0.4) and packet **#2** (198.41.0.4 → 192.168.219.111) both carry transaction ID **0xf16d**, and both carry the same question, `www.korea.ac.kr`. That ID is the only thing tying them together:
UDP has no connection, so a resolver with several questions in
flight matches replies to questions by this number and the question
section, and throws away anything that matches neither.

**A3 · a delegation and an answer — the same packet format.**

| | packet | from | ANSWER | AUTHORITY | ADDITIONAL | what it means |
|---|---|---|---|---|---|---|
| delegation | **#2** | 198.41.0.4 | 0 | 6 | 11 | “not mine — ask kr” |
| answer | **#6** | 163.152.11.6 | 1 | 0 | 1 | “www.korea.ac.kr is 163.152.6.10”, AA set |

Same header, same question section, same record format. The only
difference is **which section the records are in**: packet #2 puts 6 NS records in AUTHORITY and leaves ANSWER empty, packet #6 puts an A record in ANSWER.
In Task 1 a delegation was a branch in the code; here it is a count
in a header.

**A4 · the largest response: packet #14, 855 bytes** of DNS payload (883 bytes on the wire once the reconstructed
IP and UDP headers are counted). It came from 198.41.0.4 in reply to a question about `www.microsoft.com-c-3.edgekey.net`, and it is a delegation of the `net` zone.

It is large because a delegation has to name *every* server in the
zone and then give their addresses: **13 NS records** in the
authority section, and **13 A** plus **13 AAAA** glue
records in the additional section. That is 39 records to
answer one question.

It is also over the 512-byte limit a DNS response had before EDNS0,
which is not incidental: the first version of this resolver, asking
the classic way, got TC=1 from every `.com` server and no records at
all. Advertising a 4096-byte buffer (RFC 6891) is what makes a reply
this size possible over UDP; without it the walk needs a TCP retry.

## Part B · The chains

**The rule.** Two signals, because one is not enough:

1. **Follow the CNAME chain to its end and compare organisations, not
   domains.** The comparison is on eTLD+1 (so `www.korea.ac.kr` belongs to
   `korea.ac.kr`, not to the `ac.kr` registry) and then through a table of
   which registrable domains belong to the same organisation — because
   `wikipedia.org` and `wikimedia.org` are one foundation, and
   `akamaiedge.net` is not Microsoft no matter who points at it.
2. **When the chain says nothing, reverse-map the addresses.** A site can
   sit behind a CDN with no CNAME at all. The operator of an anycast
   address usually names it in PTR, and that name is a second opinion.

A site is third-party-served if either signal says an outside organisation
is answering for it.

| site | chain | final zone | third party? | naive rule | my rule |
|---|---|---|---|---|---|
| `www.microsoft.com` | 2 hops | `akamaiedge.net` | **yes** | yes | yes (Akamai) |
| `www.netflix.com` | 1 hop | `netflix.com` | **no** | no | no (Netflix) |
| `www.adobe.com` | 2 hops | `akamai.net` | **yes** | yes | yes (Akamai) |
| `www.cnn.com` | 1 hop | `fastly.net` | **yes** | yes | yes (Fastly) |
| `www.apple.com` | 3 hops | `akamaiedge.net` | **yes** | yes | yes (Akamai) |
| `www.korea.ac.kr` | 0 hops | `korea.ac.kr` | **no** | no | no (korea.ac.kr) |
| `www.stanford.edu` | 1 hop | `netlifyglobalcdn.com` | **yes** | yes | yes (Netlify) |
| `www.bbc.co.uk` | 2 hops | `fastly.net` | **yes** | yes | yes (Fastly) |
| `www.spotify.com` | 1 hop | `fastly.net` | **yes** | yes | yes (Fastly) |
| `www.github.com` | 1 hop | `github.com` | **yes** | no ❌ | no ❌ (GitHub) |
| `www.wikipedia.org` | 1 hop | `wikimedia.org` | **no** | yes ❌ | no (Wikimedia) |
| `www.nytimes.com` | 3 hops | `fastly.net` | **yes** | yes | yes (Fastly) |

Full chains, every resolver's answers and the PTR records are in
`out/chains.json`.

### Where the rules are wrong

**The naive rule — compare the last two labels — is wrong on 2 of 12 sites.**

- **`www.github.com`** — it compares `github.com` with `github.com` and says **not third party**. It is Microsoft Azure. There is no CNAME out of github.com and no PTR, but 20.200.245.247 is in Azure's range - GitHub has been on Azure since the acquisition.
- **`www.wikipedia.org`** — it compares `wikipedia.org` with `wikimedia.org` and says **third party**. It is Wikimedia's own load balancers - wikimedia.org is a different registrable domain but the same foundation, and the PTR says text-lb.eqsin.wikimedia.org, their Singapore site.

It also mis-*names* a zone it happens to judge correctly: for
`www.korea.ac.kr` the last two labels are `ac.kr`, which is a public
suffix — the registry for Korean academic institutions, not Korea
University. The verdict comes out right only because the site has no
CNAME, so the rule compares `ac.kr` with itself. On any Korean university
that did use a CDN, the same rule would be comparing the wrong thing.

**My rule is wrong on 1 site too:**

- **`www.github.com`** — my rule says **not third party** because the chain ends at github.com, which is GitHub's own; no PTR record for any of the addresses. It is Microsoft Azure. There is no CNAME out of github.com and no PTR, but 20.200.245.247 is in Azure's range - GitHub has been on Azure since the acquisition.

This is the case `task2.md` warns about, and neither signal reaches it.
The CNAME is honest and tells you nothing — it points inside the site's
own zone, which is exactly what a site running its own servers looks
like. The PTR fallback does not rescue it because Azure publishes no
PTR for that address, so DNS has genuinely run out of things to say.
Answering it needs data DNS does not carry: the address has to be
looked up in a routing registry — `whois` or an ASN table — to see
whose network it is announced from. A DNS-only rule cannot decide this
site, and any rule that gets it right has a hard-coded fact in it
rather than a measurement.

## Part B · The steering number

**8 of 9 third-party-served sites answered differently to a different resolver** (8 of 12 counting every site).

Not *how many* addresses differ but *who agrees with whom*, because the
grouping is the evidence:

| site | sets | who agreed on what |
|---|---|---|
| `www.microsoft.com` | 3 | **{google, kt, system}** → 104.94.218.45 · **{cloudflare}** → 23.49.206.40 · **{quad9}** → 23.63.226.92 |
| `www.adobe.com` | 5 | **{cloudflare}** → 23.59.72.42, 23.59.72.43… · **{google}** → 121.254.136.11, 121.254.136.153… · **{kt}** → 23.35.218.146, 23.35.218.147… · **{quad9}** → 23.210.250.154, 23.210.250.184 · **{system}** → 121.254.136.10, 121.254.136.11… |
| `www.cnn.com` | 2 | **{cloudflare, google, quad9}** → 151.101.131.5, 151.101.195.5… · **{kt, system}** → 146.75.51.5 |
| `www.apple.com` | 3 | **{cloudflare, google}** → 23.49.205.28 · **{kt, system}** → 104.94.216.37 · **{quad9}** → 184.31.228.249 |
| `www.bbc.co.uk` | 2 | **{cloudflare, google, quad9}** → 151.101.0.81, 151.101.128.81… · **{kt, system}** → 146.75.48.81 |
| `www.spotify.com` | 2 | **{cloudflare, google, quad9}** → 151.101.131.42, 151.101.195.42… · **{kt, system}** → 146.75.51.42 |
| `www.github.com` | 2 | **{cloudflare, google, kt, system}** → 20.200.245.247 · **{quad9}** → 20.27.177.113 |
| `www.nytimes.com` | 2 | **{cloudflare, google, quad9}** → 151.101.1.164, 151.101.129.164… · **{kt, system}** → 146.75.49.164 |

**Does this support claim (b)?** Partly, and the interesting part is where
it does not.

The commonest split is {cloudflare, google, quad9} vs {kt, system}, and it
repeats across 4 sites that have nothing to do with
each other: `www.cnn.com`, `www.bbc.co.uk`, `www.spotify.com`, `www.nytimes.com`. A split
that repeats across unrelated sites is not noise — the same CDN is
making the same distinction about who is asking, every time. `system`
here is the WSL stub forwarding to the network's own resolver, which is
why it lands with `kt` rather than with the anycast three.

**The exception is the one worth writing down.** On `www.adobe.com` the
resolvers do *not* split by country. Google and this machine's own
resolver both land in `121.254.x` — `121.254.136.11, 121.254.136.153` and `121.254.136.10, 121.254.136.11` —
while **KT's own resolver**, the Korean ISP's, returns `23.35.218.146, 23.35.218.147`, in the CDN's global range. The answer that
looks local came back through the resolver that is furthest away, and
the Korean ISP's resolver got the far one.

Distance cannot explain that; a second mechanism can. **EDNS Client
Subnet**: Google Public DNS forwards a truncated prefix of the client's
address to the authoritative server, so the CDN maps the *client*. A
resolver that does not forward ECS can only be mapped by where the
resolver itself sits. So what is being measured across resolvers is
partly steering by location and partly a difference in what each
resolver is willing to tell the CDN about you. Claim (b) survives — the
mapping plainly exists — but “DNS steers you to a nearby replica” is
doing two jobs in one sentence, and this measurement cannot separate
them.

Sites that did not follow the commonest split: `www.adobe.com`, `www.apple.com`, `www.github.com`, `www.microsoft.com`.

**What this measurement cannot do.** A different resolver is not a
different place. Google, Quad9 and Cloudflare are anycast, so asking them
from Seoul most likely reaches a node in or near Asia — the contrast here
is not Seoul-versus-elsewhere, it is five different resolver *policies*
seen from one spot. Claim (b) is about where the **client** is, so testing
it properly needs the client to move. That is B3, and it is the one part of
this lab that has not been done here: everything above is a single vantage
point. Running the collector again on phone tethering adds the second one
and every number in this section updates:

```bash
python3 task2_steering.py --collect --network tethering
python3 task2_steering.py --report
```

One more caveat that a bigger table would not fix: the addresses the
local resolvers get for `www.adobe.com` sit outside the
CDN's
usual range and publish no PTR at all, which is what a cache *inside* a
Korean ISP looks like — but confirming whose network announces them
needs whois or an ASN table. That is the same gap that defeats
`www.github.com` above. DNS will tell you that the answer changed. It
will not tell you whose machine you were sent to.

*Sources: `out/chains.json` (raw), `out/dns.pcapng` (Part A). Generated by `task2_steering.py --report`.*
