#!/usr/bin/env python3
"""Week 3 · Task 2 — Does DNS actually steer you? Measure it.

Textbook §2.4.3 (records) and §2.5 (CDNs).

The lecture claims two things:

    (a) most large sites are served by a CDN, reached through a CNAME chain
    (b) DNS steers each user to a *nearby* replica

    python3 task2_steering.py --collect                  # gather the raw data
    python3 task2_steering.py --collect --network tether # a second vantage point
    python3 task2_steering.py --report                   # the analysis

Transport is `dnsproto.py`, for the same reason as Task 1: no `dig` on this
machine. `dig()` below keeps its original shape and shells out when dig *is*
installed, so the two paths give the same shaped answer.

Part A (the capture) is produced by Task 1 with `--pcap`; `--report` reads that
file back and answers A2-A4 from what is in it. How the file was produced is
stated in the report, because it matters: it is a log written by the resolver,
not a capture taken off the interface.
"""
import argparse, datetime, json, os, shutil, subprocess, sys

import dnsproto
from dnsproto import DNSError, TYPE_A, TYPE_CNAME, TYPE_NS, TYPE_PTR

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")
CHAINS = os.path.join(OUT, "chains.json")
PCAP = os.path.join(OUT, "dns.pcapng")

SITES = [
    "www.microsoft.com",     # Akamai, multi-hop
    "www.netflix.com",       # own CDN
    "www.adobe.com",
    "www.cnn.com",
    "www.apple.com",
    "www.korea.ac.kr",       # no CDN at all
    "www.stanford.edu",
    "www.bbc.co.uk",
    "www.spotify.com",
    "www.github.com",
    "www.wikipedia.org",
    "www.nytimes.com",
]

# The three the lab ships with, plus two chosen for distance. Claim (b) is
# about *where the asker is*, so the resolvers have to sit in different places
# for the comparison to mean anything: KT's resolver is in Seoul and serves
# Korean eyeballs only; Google and Quad9 are anycast and answer from whichever
# of their sites is closest, which is not necessarily one in Korea.
RESOLVERS = {
    "system": None,          # whatever is in your resolv.conf
    "google": "8.8.8.8",
    "quad9":  "9.9.9.9",
    "kt":     "168.126.63.1",    # KT, Korean ISP - the near vantage point
    "cloudflare": "1.1.1.1",
}

RESOLVER_NOTES = {
    "system": "whatever resolv.conf points at on this network",
    "google": "Google Public DNS, anycast",
    "quad9": "Quad9, anycast",
    "kt": "KT (Korea Telecom) recursive resolver, Seoul",
    "cloudflare": "Cloudflare, anycast",
}


# ------------------------------------------------------------------ transport
def system_resolver():
    """The resolver this machine would use if we did not name one."""
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("nameserver"):
                    return line.split()[1]
    except OSError:
        pass
    return "8.8.8.8"


def dig(name, rtype="A", server=None):
    """Raw lookup. Transport only - the thinking is yours.

    Uses `dig` when it is installed and dnsproto when it is not; both return
    the same thing, the rdata of the answer section as a list of strings.
    """
    if shutil.which("dig"):
        args = ["dig", "+short", name, rtype]
        if server:
            args.insert(1, f"@{server}")
        out = subprocess.run(args, capture_output=True, text=True).stdout
        return [l.strip() for l in out.splitlines() if l.strip()]

    qtype = {"A": TYPE_A, "CNAME": TYPE_CNAME, "PTR": TYPE_PTR}[rtype]
    try:
        reply = dnsproto.ask(server or system_resolver(), name, qtype,
                             rd=True, timeout=5.0)
    except DNSError:
        return []
    return [str(r["rdata"]) for r in reply.answer]


def lookup(name, resolver_ip, timeout=5.0):
    """One recursive query, returning the chain and the addresses separately.

    A recursive resolver hands back the whole CNAME chain in the answer
    section, so one query is enough to see every hop: the alias records come
    first, the addresses of whatever the chain ends at come last.
    """
    reply = dnsproto.ask(resolver_ip, name, TYPE_A, rd=True, timeout=timeout)

    aliases = {r["name"].lower(): r["rdata"].rstrip(".")
               for r in reply.answer if r["type"] == TYPE_CNAME}
    chain, current, guard = [name], name.lower(), 0
    while current in aliases and guard < 16:
        current = aliases[current].lower()
        chain.append(current)
        guard += 1

    addresses = sorted(r["rdata"] for r in reply.answer if r["type"] == TYPE_A)
    ttls = {r["name"].lower(): r["ttl"] for r in reply.answer}
    return {"chain": chain, "addresses": addresses,
            "final": chain[-1], "ttl": ttls.get(chain[-1])}


def ptr(address, resolver_ip):
    """Reverse lookup. The operator of an anycast address often names it."""
    reverse = ".".join(reversed(address.split("."))) + ".in-addr.arpa"
    try:
        reply = dnsproto.ask(resolver_ip, reverse, TYPE_PTR, rd=True,
                             timeout=4.0)
    except DNSError:
        return None
    names = [r["rdata"] for r in reply.answer if r["type"] == TYPE_PTR]
    return names[0] if names else None


# ------------------------------------------------------------- name arithmetic
# The public suffix is the part of a name nobody can register: `com`, but also
# `co.uk` and `ac.kr`. This is the shortest table that covers the sites in
# SITES and the CDN zones they end at. The real list has ~9,000 entries.
MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk",
    "ac.kr", "co.kr", "or.kr", "go.kr", "ne.kr", "re.kr",
    "co.jp", "ne.jp", "or.jp", "com.au", "net.au", "com.br",
    "com.cn", "net.cn", "co.in", "co.nz", "co.za", "com.tr", "com.mx",
}


def registrable(name):
    """eTLD+1: the shortest part of `name` somebody actually registered."""
    labels = name.rstrip(".").lower().split(".")
    if len(labels) < 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def naive_registrable(name):
    """The rule the lab warns about: just take the last two labels.

    Kept here on purpose so the report can show where it breaks.
    """
    labels = name.rstrip(".").lower().split(".")
    return ".".join(labels[-2:])


# Which organisation owns a registrable domain, where it is not obvious from
# the name itself. Everything absent from this table is its own organisation.
ORG_OF = {
    # third-party CDNs
    "akamaiedge.net": "Akamai", "akamai.net": "Akamai",
    "akamaized.net": "Akamai", "akamaitechnologies.com": "Akamai",
    "edgekey.net": "Akamai", "edgesuite.net": "Akamai",
    "akadns.net": "Akamai", "akamaihd.net": "Akamai",
    "fastly.net": "Fastly", "fastlylb.net": "Fastly",
    "cloudfront.net": "Amazon CloudFront",
    "azureedge.net": "Microsoft Azure CDN", "azurefd.net": "Microsoft Azure CDN",
    "trafficmanager.net": "Microsoft Azure", "msedge.net": "Microsoft",
    "cloudflare.net": "Cloudflare", "cloudflare.com": "Cloudflare",
    "cloudflare-dns.com": "Cloudflare",
    "llnwd.net": "Limelight", "edgecastcdn.net": "Edgecast",
    "impervadns.net": "Imperva", "incapdns.net": "Imperva",
    "cachefly.net": "CacheFly", "stackpathdns.com": "StackPath",
    "nsone.net": "NS1 (managed DNS)", "b-cdn.net": "Bunny CDN",
    "gccdn.net": "ChinaCache", "cdn77.org": "CDN77",
    "netlifyglobalcdn.com": "Netlify", "netlify.com": "Netlify",
    "awsglobalaccelerator.com": "Amazon AWS",
    "footprintdns.com": "Microsoft", "voxcdn.net": "Vox",
    # cloud platforms - hosting, not a CDN, but still a third party
    "amazonaws.com": "Amazon AWS", "awsdns-51.org": "Amazon AWS",
    "googleusercontent.com": "Google", "1e100.net": "Google",
    "googlehosted.com": "Google", "google.com": "Google",
    # sites that run their own edge under a second name
    "wikipedia.org": "Wikimedia", "wikimedia.org": "Wikimedia",
    "wikimedia.dns": "Wikimedia",
    "apple.com": "Apple", "aaplimg.com": "Apple", "apple-dns.net": "Apple",
    "netflix.com": "Netflix", "nflxvideo.net": "Netflix",
    "nflxso.net": "Netflix", "netflix.net": "Netflix", "nflximg.net": "Netflix",
    "microsoft.com": "Microsoft", "microsoft.com.edgekey.net": "Akamai",
    "bbc.co.uk": "BBC", "bbc.com": "BBC", "bbci.co.uk": "BBC",
    "nytimes.com": "New York Times", "nyt.net": "New York Times",
    "spotify.com": "Spotify", "spotifycdn.com": "Spotify", "scdn.co": "Spotify",
    "adobe.com": "Adobe", "adobe.io": "Adobe", "omtrdc.net": "Adobe",
    "cnn.com": "CNN", "turner.com": "CNN", "cnn.io": "CNN",
    "github.com": "GitHub", "githubassets.com": "GitHub",
    "github.io": "GitHub", "githubusercontent.com": "GitHub",
}

# Organisations that exist to serve somebody else's content.
THIRD_PARTY_ORGS = {
    "Akamai", "Fastly", "Amazon CloudFront", "Microsoft Azure CDN",
    "Microsoft Azure", "Cloudflare", "Limelight", "Edgecast", "Imperva",
    "CacheFly", "StackPath", "Bunny CDN", "ChinaCache", "CDN77",
    "Amazon AWS", "Google", "NS1 (managed DNS)", "Vox", "Netlify",
}


def org_of(name):
    return ORG_OF.get(registrable(name), registrable(name))


# ------------------------------------------------------------------- collect
def collect(network, sites=None, timeout=5.0):
    """Ask every resolver for every site and write it all to out/chains.json.

    The file is keyed by site name, with each site holding its chain and one
    block per vantage point. Running this again from a different network adds
    a vantage point to every site rather than replacing one (B3).
    """
    os.makedirs(OUT, exist_ok=True)
    sites = sites or SITES
    resolvers = {k: (v or system_resolver()) for k, v in RESOLVERS.items()}
    print(f"\n  collecting from network {network!r} "
          f"({len(sites)} sites x {len(resolvers)} resolvers)\n")

    data = {}
    if os.path.exists(CHAINS):
        with open(CHAINS, encoding="utf-8") as fh:
            data = json.load(fh)

    meta = data.setdefault("_meta", {})
    meta["sites"] = sites
    meta["resolvers"] = {k: {"ip": v, "note": RESOLVER_NOTES.get(k, "")}
                         for k, v in resolvers.items()}
    meta.setdefault("networks", {})[network] = {
        "collected_at": datetime.datetime.now().astimezone().isoformat(
            timespec="seconds"),
        "resolvers": resolvers,
    }

    for site in sites:
        record = data.setdefault(site, {"by_network": {}})
        here = {"by_resolver": {}, "ptr": {}}

        for label, ip in resolvers.items():
            # One retry. A single UDP timeout is not a measurement, and a
            # resolver missing from one row distorts the agreement grouping
            # far more than it distorts any single address.
            result, error = None, None
            for attempt in range(2):
                try:
                    result = lookup(site, ip, timeout)
                    break
                except DNSError as e:
                    error = str(e)
            if result is not None:
                here["by_resolver"][label] = result
                mark = f"{len(result['addresses'])} addr"
            else:
                here["by_resolver"][label] = {"error": error, "chain": [site],
                                              "addresses": [], "final": site}
                mark = f"no answer ({error})"
            print(f"  {site:<20} {label:<11} {mark}")

        # Reverse-map a few addresses: the only signal available for a site
        # that sits behind a CDN with no CNAME at all.
        seen = sorted({a for r in here["by_resolver"].values()
                       for a in r.get("addresses", [])})
        for address in seen[:4]:
            name = ptr(address, resolvers["google"])
            if name:
                here["ptr"][address] = name
        record["by_network"][network] = here

        # The chain is a property of the name, not of who asked, so take the
        # longest one seen anywhere - a resolver answering from cache can hand
        # back a shorter one. Same for PTR: merge across vantage points.
        chains = [r["chain"] for block in record["by_network"].values()
                  for r in block["by_resolver"].values() if r.get("chain")]
        record["chain"] = max(chains, key=len) if chains else [site]
        record["chain_length"] = len(record["chain"]) - 1
        record["final"] = record["chain"][-1]
        record["final_zone"] = registrable(record["final"])
        record["naive_final_zone"] = naive_registrable(record["final"])
        record["ptr"] = {a: n for block in record["by_network"].values()
                         for a, n in block["ptr"].items()}

    with open(CHAINS, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print(f"\n  {len(sites)} sites -> {CHAINS}")
    print(f"  vantage points on file: "
          f"{', '.join(sorted(meta['networks']))}\n")
    return data


# ------------------------------------------------------------- classification
# B4. There is no single right rule, so this one is layered and each layer is
# named in the output. Two signals:
#
#   1. the CNAME chain - who does the name finally point into?
#   2. the addresses' PTR records - who does the operator say owns them?
#
# Signal 2 exists because signal 1 goes blind on a site that sits behind a CDN
# with no CNAME at all, which the lab warns about. It does not rescue every
# such case, and the report says which one it fails on.

def classify(site, entry):
    """Is this site served by a third party? Returns (verdict, org, reason)."""
    site_org = org_of(site)
    final_org = org_of(entry["final"])

    cname_says, cname_reason = None, ""
    if entry["chain_length"] > 0:
        if final_org == site_org:
            cname_says = False
            cname_reason = (f"the chain ends at {entry['final_zone']}, which is "
                            f"{site_org}'s own")
        elif final_org in THIRD_PARTY_ORGS:
            cname_says = True
            cname_reason = f"the chain ends in {final_org}'s zone"
        else:
            cname_says = True
            cname_reason = (f"the chain ends at {entry['final_zone']}, "
                            f"registered to somebody other than {site_org}")

    ptr_says, ptr_reason = None, ""
    ptr_orgs = {org_of(name) for name in entry.get("ptr", {}).values()}
    outsiders = {o for o in ptr_orgs if o in THIRD_PARTY_ORGS and o != site_org}
    if outsiders:
        ptr_says = True
        ptr_reason = f"the addresses reverse-map into {', '.join(sorted(outsiders))}"
    elif ptr_orgs and ptr_orgs <= {site_org}:
        ptr_says = False
        ptr_reason = "the addresses reverse-map into the site's own zone"
    elif not entry.get("ptr"):
        ptr_reason = "no PTR record for any of the addresses"

    if cname_says is None and ptr_says is None:
        return False, site_org, "no CNAME and " + (ptr_reason or "no other signal")
    if cname_says or ptr_says:
        org = final_org if cname_says else sorted(outsiders)[0]
        reasons = [r for r in (cname_reason if cname_says else "",
                               ptr_reason if ptr_says else "") if r]
        return True, org, "; ".join(reasons)
    return False, site_org, "; ".join(r for r in (cname_reason, ptr_reason) if r)


def classify_naive(site, entry):
    """The rule the lab warns about: compare the last two labels, nothing else."""
    site_zone = naive_registrable(site)
    final_zone = naive_registrable(entry["final"])
    return site_zone != final_zone, site_zone, final_zone


# What is actually true, decided by hand from the chains, the PTR records and
# what the operators publish. This is the column the two rules are scored
# against; it is a judgement, and the reasoning is in the report.
TRUTH = {
    "www.microsoft.com": (True,  "Akamai - the chain ends at akamaiedge.net"),
    "www.netflix.com":   (False, "Netflix Open Connect; the chain stays in "
                                 "netflix.com and the PTR says prod.ftl4.netflix.com"),
    "www.adobe.com":     (True,  "Akamai - akamai.net, and the addresses are "
                                 "Akamai caches inside Korean ISPs"),
    "www.cnn.com":       (True,  "Fastly"),
    "www.apple.com":     (True,  "Akamai. Apple's own aaplimg.com is only the "
                                 "first hop; the chain ends at akamaiedge.net"),
    "www.korea.ac.kr":   (False, "Korea University's own servers - no CNAME, and "
                                 "163.152.6.10 reverse-maps to 60.korea.ac.kr"),
    "www.stanford.edu":  (True,  "Netlify, fronted by AWS Global Accelerator"),
    "www.bbc.co.uk":     (True,  "Fastly"),
    "www.spotify.com":   (True,  "Fastly"),
    "www.github.com":    (True,  "Microsoft Azure. There is no CNAME out of "
                                 "github.com and no PTR, but 20.200.245.247 is "
                                 "in Azure's range - GitHub has been on Azure "
                                 "since the acquisition"),
    "www.wikipedia.org": (False, "Wikimedia's own load balancers - wikimedia.org "
                                 "is a different registrable domain but the same "
                                 "foundation, and the PTR says text-lb.eqsin."
                                 "wikimedia.org, their Singapore site"),
    "www.nytimes.com":   (True,  "Fastly"),
}


# ------------------------------------------------------------------ steering
def address_sets(block):
    """resolver label -> the addresses it returned, as a comparable tuple."""
    return {label: tuple(sorted(r.get("addresses", [])))
            for label, r in block["by_resolver"].items()
            if r.get("addresses")}


def agreement_groups(steer):
    """[(resolver labels that agreed, the addresses they agreed on)], biggest first."""
    by_answer = {}
    for vantage, addrs in steer["vantages"].items():
        by_answer.setdefault(addrs, []).append(vantage.split("/")[-1])
    return sorted(((tuple(sorted(labels)), addrs)
                   for addrs, labels in by_answer.items()),
                  key=lambda g: (-len(g[0]), g[0]))


def steering_for(record):
    """Did this site answer differently to a different resolver or network?"""
    by_vantage = {}
    for net_label, block in record["by_network"].items():
        for resolver_label, addrs in address_sets(block).items():
            by_vantage[f"{net_label}/{resolver_label}"] = addrs

    distinct = set(by_vantage.values())
    return {"vantages": by_vantage, "distinct": len(distinct),
            "differs": len(distinct) > 1}


# -------------------------------------------------------------------- part A
def part_a():
    """Answer A2-A4 out of the pcapng, not out of memory."""
    if not os.path.exists(PCAP):
        return None
    packets = dnsproto.read_pcapng(PCAP)

    pair = None
    for p in packets:
        if p["dir"] == "query":
            match = next((q for q in packets
                          if q["dir"] == "response" and q["msg"].id == p["msg"].id
                          and q["no"] > p["no"]), None)
            if match:
                pair = (p, match)
                break

    delegation = next((p for p in packets
                       if p["dir"] == "response" and p["msg"].is_delegation()), None)
    answer = next((p for p in packets
                   if p["dir"] == "response" and p["msg"].is_answer()), None)
    largest = max((p for p in packets if p["dir"] == "response"),
                  key=lambda p: p["dns_bytes"], default=None)
    return {"packets": packets, "pair": pair, "delegation": delegation,
            "answer": answer, "largest": largest}


# -------------------------------------------------------------------- report
def report():
    """Read out/chains.json (and out/dns.pcapng) and write out/report.md."""
    if not os.path.exists(CHAINS):
        sys.exit(f"no {CHAINS} - run --collect first")
    with open(CHAINS, encoding="utf-8") as fh:
        data = json.load(fh)
    meta = data["_meta"]
    networks = meta["networks"]
    primary = sorted(networks)[0]
    sites = meta["sites"]

    rows, wrong_naive, wrong_mine = [], [], []
    for site in sites:
        entry = data[site]
        mine, org, reason = classify(site, entry)
        naive, naive_site_zone, naive_final_zone = classify_naive(site, entry)
        truth, why = TRUTH.get(site, (mine, "not judged"))
        row = {"site": site, "entry": entry, "mine": mine, "org": org,
               "reason": reason, "naive": naive, "truth": truth, "why": why,
               "naive_site_zone": naive_site_zone,
               "naive_final_zone": naive_final_zone,
               "steering": steering_for(entry)}
        rows.append(row)
        if naive != truth:
            wrong_naive.append(row)
        if mine != truth:
            wrong_mine.append(row)

    cdn_rows = [r for r in rows if r["truth"]]
    steered = [r for r in cdn_rows if r["steering"]["differs"]]
    all_steered = [r for r in rows if r["steering"]["differs"]]
    a = part_a()

    L = []
    w = L.append
    w("# Week 3 · Task 2 — On the wire, and does DNS really steer you?")
    w("")
    w(f"Collected {networks[primary]['collected_at']} from "
      f"{len(sites)} sites × {len(meta['resolvers'])} resolvers.")
    w(f"Vantage points on file: {', '.join(sorted(networks))}.")
    w("")
    w("## How this was measured, and what it is not")
    w("")
    w("Neither `dig` nor `tshark` nor dnspython is installed on this machine, and")
    w("it is a WSL2 guest with no capture privilege on the interface, so two")
    w("things were done differently from the way the lab describes. Both are")
    w("weaker than the real thing and both are named where they matter:")
    w("")
    w("- **Transport** is `dnsproto.py` in this folder — DNS messages built and")
    w("  parsed from raw UDP. Nothing is lost here; it is the same queries.")
    w("- **`out/dns.pcapng` is a log written by the resolver, not a capture taken")
    w("  off the interface.** The DNS payload of every packet in it is real, byte")
    w("  for byte as it left and entered this machine, with the real addresses,")
    w("  ports and timestamps. The IPv4/UDP headers around each payload are")
    w("  *reconstructed*: a userspace program never sees the headers the kernel")
    w("  builds. So the file proves what was asked and answered; it does not prove")
    w("  the traffic was observed independently of the program that made it.")
    w("- **Part B has one network, not two.** This is path (B) from `task2.md`:")
    w("  two resolvers at very different distances instead of two networks. See")
    w("  the steering section for what that weakens.")
    w("")

    # ---------------------------------------------------------------- part A
    w("## Part A · The exchange on the wire")
    w("")
    if not a:
        w("`out/dns.pcapng` is missing — generate it with:")
        w("")
        w("```bash")
        w("python3 task1_resolve.py www.korea.ac.kr www.microsoft.com --pcap out/dns.pcapng")
        w("```")
    else:
        packets, pair = a["packets"], a["pair"]
        w(f"`out/dns.pcapng` — {len(packets)} datagrams, "
          f"{sum(1 for p in packets if p['dir'] == 'query')} queries and "
          f"{sum(1 for p in packets if p['dir'] == 'response')} responses, all of")
        w("them this resolver's own walk for `www.korea.ac.kr` and")
        w("`www.microsoft.com`. Nothing else on the machine is in the file, which")
        w("is the privacy problem a real `port 53` capture has and this does not.")
        w("")
        if pair:
            q, r = pair
            w(f"**A2 · a query and its response.** Packet **#{q['no']}** "
              f"({q['src']} → {q['dst']}) and packet **#{r['no']}** "
              f"({r['src']} → {r['dst']}) both carry transaction ID "
              f"**0x{q['msg'].id:04x}**, and both carry the same question, "
              f"`{q['msg'].qname}`. That ID is the only thing tying them together:")
            w("UDP has no connection, so a resolver with several questions in")
            w("flight matches replies to questions by this number and the question")
            w("section, and throws away anything that matches neither.")
            w("")
        d, ans = a["delegation"], a["answer"]
        if d and ans:
            dm, am = d["msg"], ans["msg"]
            w(f"**A3 · a delegation and an answer — the same packet format.**")
            w("")
            w("| | packet | from | ANSWER | AUTHORITY | ADDITIONAL | what it means |")
            w("|---|---|---|---|---|---|---|")
            w(f"| delegation | **#{d['no']}** | {d['src']} | {len(dm.answer)} | "
              f"{len(dm.authority)} | {len(dm.additional)} | "
              f"“not mine — ask {dm.authority[0]['name'] or '.'}” |")
            w(f"| answer | **#{ans['no']}** | {ans['src']} | {len(am.answer)} | "
              f"{len(am.authority)} | {len(am.additional)} | "
              f"“{am.answer[0]['name']} is {am.answer[0]['rdata']}”"
              f"{', AA set' if am.aa else ''} |")
            w("")
            w("Same header, same question section, same record format. The only")
            w("difference is **which section the records are in**: packet "
              f"#{d['no']} puts {len(dm.authority)} NS records in AUTHORITY and "
              f"leaves ANSWER empty, packet #{ans['no']} puts an A record in "
              "ANSWER.")
            w("In Task 1 a delegation was a branch in the code; here it is a count")
            w("in a header.")
            w("")
        big = a["largest"]
        if big:
            bm = big["msg"]
            ns_count = len(bm.records("authority", TYPE_NS))
            glue_a = sum(1 for r in bm.additional if r["type_name"] == "A")
            glue_aaaa = sum(1 for r in bm.additional if r["type_name"] == "AAAA")
            zone = bm.records("authority", TYPE_NS)[0]["name"] or "."
            w(f"**A4 · the largest response: packet #{big['no']}, "
              f"{big['dns_bytes']} bytes** of DNS payload "
              f"({big['frame_bytes']} bytes on the wire once the reconstructed")
            w(f"IP and UDP headers are counted). It came from {big['src']} in reply "
              f"to a question about `{bm.qname}`, and it is a delegation of the "
              f"`{zone}` zone.")
            w("")
            w(f"It is large because a delegation has to name *every* server in the")
            w(f"zone and then give their addresses: **{ns_count} NS records** in the")
            w(f"authority section, and **{glue_a} A** plus **{glue_aaaa} AAAA** glue")
            w(f"records in the additional section. That is {ns_count * 3} records to")
            w(f"answer one question.")
            w("")
            w("It is also over the 512-byte limit a DNS response had before EDNS0,")
            w("which is not incidental: the first version of this resolver, asking")
            w("the classic way, got TC=1 from every `.com` server and no records at")
            w("all. Advertising a 4096-byte buffer (RFC 6891) is what makes a reply")
            w("this size possible over UDP; without it the walk needs a TCP retry.")
            w("")

    # ---------------------------------------------------------------- part B
    w("## Part B · The chains")
    w("")
    w("**The rule.** Two signals, because one is not enough:")
    w("")
    w("1. **Follow the CNAME chain to its end and compare organisations, not")
    w("   domains.** The comparison is on eTLD+1 (so `www.korea.ac.kr` belongs to")
    w("   `korea.ac.kr`, not to the `ac.kr` registry) and then through a table of")
    w("   which registrable domains belong to the same organisation — because")
    w("   `wikipedia.org` and `wikimedia.org` are one foundation, and")
    w("   `akamaiedge.net` is not Microsoft no matter who points at it.")
    w("2. **When the chain says nothing, reverse-map the addresses.** A site can")
    w("   sit behind a CDN with no CNAME at all. The operator of an anycast")
    w("   address usually names it in PTR, and that name is a second opinion.")
    w("")
    w("A site is third-party-served if either signal says an outside organisation")
    w("is answering for it.")
    w("")
    w("| site | chain | final zone | third party? | naive rule | my rule |")
    w("|---|---|---|---|---|---|")
    for r in rows:
        e = r["entry"]
        chain = " → ".join(h.replace(r["site"], "*", 1) if i else h
                           for i, h in enumerate(e["chain"]))
        mark = lambda v, ok: ("yes" if v else "no") + ("" if ok else " ❌")
        w(f"| `{r['site']}` | {e['chain_length']} hop"
          f"{'s' if e['chain_length'] != 1 else ''} | `{e['final_zone']}` | "
          f"**{'yes' if r['truth'] else 'no'}** | "
          f"{mark(r['naive'], r['naive'] == r['truth'])} | "
          f"{mark(r['mine'], r['mine'] == r['truth'])} ({r['org']}) |")
    w("")
    w(f"Full chains, every resolver's answers and the PTR records are in")
    w(f"`out/chains.json`.")
    w("")

    # ------------------------------------------------------------ where wrong
    w("### Where the rules are wrong")
    w("")
    w("**The naive rule — compare the last two labels — is wrong on "
      f"{len(wrong_naive)} of {len(rows)} sites.**")
    w("")
    for r in wrong_naive:
        w(f"- **`{r['site']}`** — it compares `{r['naive_site_zone']}` with "
          f"`{r['naive_final_zone']}` and says "
          f"**{'third party' if r['naive'] else 'not third party'}**. "
          f"It is {r['why']}.")
    w("")
    w("It also mis-*names* a zone it happens to judge correctly: for")
    w("`www.korea.ac.kr` the last two labels are `ac.kr`, which is a public")
    w("suffix — the registry for Korean academic institutions, not Korea")
    w("University. The verdict comes out right only because the site has no")
    w("CNAME, so the rule compares `ac.kr` with itself. On any Korean university")
    w("that did use a CDN, the same rule would be comparing the wrong thing.")
    w("")
    if wrong_mine:
        w(f"**My rule is wrong on {len(wrong_mine)} site"
          f"{'s' if len(wrong_mine) != 1 else ''} too:**")
        w("")
        for r in wrong_mine:
            e = r["entry"]
            w(f"- **`{r['site']}`** — my rule says "
              f"**{'third party' if r['mine'] else 'not third party'}** because "
              f"{r['reason']}. It is {r['why']}.")
        w("")
        w("This is the case `task2.md` warns about, and neither signal reaches it.")
        w("The CNAME is honest and tells you nothing — it points inside the site's")
        w("own zone, which is exactly what a site running its own servers looks")
        w("like. The PTR fallback does not rescue it because Azure publishes no")
        w("PTR for that address, so DNS has genuinely run out of things to say.")
        w("Answering it needs data DNS does not carry: the address has to be")
        w("looked up in a routing registry — `whois` or an ASN table — to see")
        w("whose network it is announced from. A DNS-only rule cannot decide this")
        w("site, and any rule that gets it right has a hard-coded fact in it")
        w("rather than a measurement.")
        w("")

    # --------------------------------------------------------------- steering
    w("## Part B · The steering number")
    w("")
    w(f"**{len(steered)} of {len(cdn_rows)} third-party-served sites answered "
      f"differently to a different resolver** "
      f"({len(all_steered)} of {len(rows)} counting every site).")
    w("")
    w("Not *how many* addresses differ but *who agrees with whom*, because the")
    w("grouping is the evidence:")
    w("")
    w("| site | sets | who agreed on what |")
    w("|---|---|---|")
    for r in rows:
        if not r["steering"]["differs"]:
            continue
        groups = agreement_groups(r["steering"])
        text = " · ".join(
            f"**{{{', '.join(labels)}}}** → {', '.join(addrs[:2])}"
            f"{'…' if len(addrs) > 2 else ''}"
            for labels, addrs in groups)
        w(f"| `{r['site']}` | {len(groups)} | {text} |")
    w("")

    # The interesting number is not the count, it is whether the same split
    # repeats across sites that have nothing to do with each other.
    signatures = {}
    for r in all_steered:
        sig = tuple(tuple(labels) for labels, _ in agreement_groups(r["steering"]))
        signatures.setdefault(sig, []).append(r["site"])
    common_sig, common_sites = max(signatures.items(), key=lambda kv: len(kv[1]))
    exceptions = [s for sig, sites_ in signatures.items() if sig != common_sig
                  for s in sites_]

    w("**Does this support claim (b)?** Partly, and the interesting part is where")
    w("it does not.")
    w("")
    if len(common_sites) > 1:
        w(f"The commonest split is "
          f"{' vs '.join('{' + ', '.join(g) + '}' for g in common_sig)}, and it")
        w(f"repeats across {len(common_sites)} sites that have nothing to do with")
        w(f"each other: {', '.join('`' + s + '`' for s in common_sites)}. A split")
        w("that repeats across unrelated sites is not noise — the same CDN is")
        w("making the same distinction about who is asking, every time. `system`")
        w("here is the WSL stub forwarding to the network's own resolver, which is")
        w("why it lands with `kt` rather than with the anycast three.")
        w("")

    # A resolver that is *further away* getting a *closer* answer is the
    # signature of EDNS Client Subnet rather than of distance. Compare address
    # blocks, not exact sets: a CDN rotates addresses inside one cluster, so
    # two answers from the same cluster are the same finding even when the
    # lists differ.
    def net16(addrs):
        return frozenset(".".join(a.split(".")[:2]) for a in addrs)

    ecs_cases = []
    for r in all_steered:
        v = {k.split("/")[-1]: a for k, a in r["steering"]["vantages"].items()}
        if not {"google", "system", "kt"} <= set(v):
            continue
        far, local, isp = net16(v["google"]), net16(v["system"]), net16(v["kt"])
        if (far & local) and not (isp & far) and not (isp & local):
            ecs_cases.append((r, v))

    if ecs_cases:
        r, v = ecs_cases[0]
        w(f"**The exception is the one worth writing down.** On `{r['site']}` the")
        w("resolvers do *not* split by country. Google and this machine's own")
        w(f"resolver both land in `{'`, `'.join(sorted(net16(v['google'])))}.x` — "
          f"`{', '.join(v['google'][:2])}` and `{', '.join(v['system'][:2])}` —")
        w(f"while **KT's own resolver**, the Korean ISP's, returns "
          f"`{', '.join(v['kt'][:2])}`, in the CDN's global range. The answer that")
        w("looks local came back through the resolver that is furthest away, and")
        w("the Korean ISP's resolver got the far one.")
        w("")
        w("Distance cannot explain that; a second mechanism can. **EDNS Client")
        w("Subnet**: Google Public DNS forwards a truncated prefix of the client's")
        w("address to the authoritative server, so the CDN maps the *client*. A")
        w("resolver that does not forward ECS can only be mapped by where the")
        w("resolver itself sits. So what is being measured across resolvers is")
        w("partly steering by location and partly a difference in what each")
        w("resolver is willing to tell the CDN about you. Claim (b) survives — the")
        w("mapping plainly exists — but “DNS steers you to a nearby replica” is")
        w("doing two jobs in one sentence, and this measurement cannot separate")
        w("them.")
        w("")
    if exceptions:
        w(f"Sites that did not follow the commonest split: "
          f"{', '.join('`' + s + '`' for s in sorted(set(exceptions)))}.")
        w("")
    w("**What this measurement cannot do.** A different resolver is not a")
    w("different place. Google, Quad9 and Cloudflare are anycast, so asking them")
    w("from Seoul most likely reaches a node in or near Asia — the contrast here")
    w("is not Seoul-versus-elsewhere, it is five different resolver *policies*")
    w("seen from one spot. Claim (b) is about where the **client** is, so testing")
    w("it properly needs the client to move. That is B3, and it is the one part of")
    w("this lab that has not been done here: everything above is a single vantage")
    w("point. Running the collector again on phone tethering adds the second one")
    w("and every number in this section updates:")
    w("")
    w("```bash")
    w("python3 task2_steering.py --collect --network tethering")
    w("python3 task2_steering.py --report")
    w("```")
    w("")
    if ecs_cases:
        w("One more caveat that a bigger table would not fix: the addresses the")
        w(f"local resolvers get for `{ecs_cases[0][0]['site']}` sit outside the")
        w("CDN's")
        w("usual range and publish no PTR at all, which is what a cache *inside* a")
        w("Korean ISP looks like — but confirming whose network announces them")
        w("needs whois or an ASN table. That is the same gap that defeats")
        w("`www.github.com` above. DNS will tell you that the answer changed. It")
        w("will not tell you whose machine you were sent to.")
        w("")
    w(f"*Sources: `out/chains.json` (raw), `out/dns.pcapng` (Part A). "
      f"Generated by `task2_steering.py --report`.*")

    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, "report.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")
    print(f"\n  {len(steered)}/{len(cdn_rows)} third-party sites steered   "
          f"naive rule wrong on {len(wrong_naive)}   "
          f"my rule wrong on {len(wrong_mine)}")
    print(f"  -> {path}\n")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--collect", action="store_true")
    p.add_argument("--report", action="store_true")
    p.add_argument("--network", default="home-wsl",
                   help="label for this vantage point (B3)")
    a = p.parse_args()
    os.makedirs(OUT, exist_ok=True)
    if a.collect:
        collect(a.network)
    elif a.report:
        report()
    else:
        p.print_help()
