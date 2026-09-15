#!/usr/bin/env python3
"""Week 3 · Task 2 — Does DNS actually steer you? Measure it.

Textbook §2.4.3 (records) and §2.5 (CDNs).

    python task2_steering.py --capture           # Part A: packets -> out/dns.pcapng
    python task2_steering.py --verify-capture    # re-read and check that file
    python task2_steering.py --collect           # Part B: raw data -> out/chains.json
    python task2_steering.py --collect --network phone-tether   # a second vantage
    python task2_steering.py --report            # analysis -> out/report.md

Transport
---------
`dig` is not installed on this machine (Windows), so the lookups below run on
the DNS wire implementation written for Task 1 - `task1_resolve.DNSClient`.
Unlike Task 1's walk, these queries deliberately set RD=1: requirement B2 is
about what each *recursive resolver* answers, so we have to let it recurse.

Part A without Wireshark
------------------------
Wireshark, tshark and Npcap are all absent here and could not be installed, so
`--capture` writes the pcapng itself: it taps `DNSClient` and records the exact
bytes of every DNS packet this machine sends and receives, then wraps each one
in a reconstructed Ethernet/IPv4/UDP header. The DNS payloads, transaction IDs,
ephemeral source ports and timestamps are real; the framing is synthetic. That
is stated in the file's own metadata, on every packet, in out/report.md §7 and
in out/observation.md. See the README for how to replace it with a genuine
Wireshark capture.
"""
import argparse, json, os, socket, struct, subprocess, sys, time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from task1_resolve import (                                    # noqa: E402
    DNSClient, Message, RRType, RCODE, Unreachable, DNSFormatError,
    normalise, strip_opt, build_query, EDNS_UDP_SIZE,
)

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")

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

# The three the assignment gave us, plus two more. Task 2's path (B) allows
# "two resolvers at very different distances" when a second network is not
# available, so the extras are chosen for distance and for ECS policy, and are
# labelled with both. See report.md §6 for what this does and does not buy.
RESOLVERS = {
    "system":     None,             # whatever DHCP gave us - a Korean ISP here
    "google":     "8.8.8.8",        # anycast; sends EDNS Client Subnet
    "quad9":      "9.9.9.9",        # anycast; does not send ECS (privacy policy)
    "kt":         "168.126.63.1",   # KT, Seoul - a second, definitively Korean ISP
    "cloudflare": "1.1.1.1",        # anycast; does not send ECS
}

RESOLVER_NOTES = {
    "system":     "DHCP-supplied ISP resolver, same city as the client",
    "google":     "anycast public resolver, sends EDNS Client Subnet",
    "quad9":      "anycast public resolver, no ECS by policy",
    "kt":         "Korean ISP resolver (KT), domestic",
    "cloudflare": "anycast public resolver, no ECS by policy",
}

MAX_CHAIN_HOPS = 10

# ------------------------------------------------------------------ public suffix
# A trimmed Public Suffix List: just the multi-label suffixes that can appear in
# this study. The point of using it at all is that "the last two labels" is not
# a domain - for www.bbc.co.uk it yields `co.uk`, which nobody owns.
MULTI_SUFFIX = {
    "co.uk", "ac.uk", "org.uk", "gov.uk", "me.uk", "net.uk",
    "co.kr", "ac.kr", "or.kr", "go.kr", "ne.kr", "re.kr", "pe.kr",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "com.au", "net.au", "org.au", "com.br", "com.cn", "net.cn", "org.cn",
    "com.hk", "com.tw", "co.nz", "co.za", "com.sg", "com.mx", "com.tr",
    "co.in", "com.ar", "com.my", "co.id", "com.ph", "co.th", "com.vn",
}

# Registrable domains operated by somebody else's CDN. Curated by hand - that is
# the honest description of every such list, including the ones inside real
# measurement papers.
CDN_OPERATORS = {
    "akamai.net": "Akamai", "akamaiedge.net": "Akamai", "edgekey.net": "Akamai",
    "edgesuite.net": "Akamai", "akadns.net": "Akamai", "akamaized.net": "Akamai",
    "akamaitechnologies.com": "Akamai", "akamaihd.net": "Akamai",
    "fastly.net": "Fastly", "fastlylb.net": "Fastly",
    "cloudfront.net": "Amazon CloudFront",
    "awsglobalaccelerator.com": "AWS Global Accelerator",
    "azureedge.net": "Azure CDN", "azurefd.net": "Azure Front Door",
    "trafficmanager.net": "Azure Traffic Manager",
    "cloudflare.net": "Cloudflare", "cloudflare.com": "Cloudflare",
    "cdn.cloudflare.net": "Cloudflare",
    "netlifyglobalcdn.com": "Netlify", "netlify.app": "Netlify",
    "llnwd.net": "Limelight", "edgecastcdn.net": "Edgecast",
    "cdn77.org": "CDN77", "impervadns.net": "Imperva", "cdngc.net": "CDNetworks",
    "b-cdn.net": "BunnyCDN", "stackpathdns.com": "StackPath",
    "gcdn.co": "G-Core", "wpenginepowered.com": "WP Engine",
}

# Second brand domains that belong to the *same* organisation as the origin.
# Every entry has to be justified by something we measured, not by knowing it.
SAME_ORG = [
    ({"wikipedia.org", "wikimedia.org"},
     "wikipedia.org and wikimedia.org publish the identical NS RRset "
     "(ns0/ns1/ns2.wikimedia.org), and the address PTRs to text-lb.*.wikimedia.org"),
    ({"apple.com", "aaplimg.com"},
     "aaplimg.com publishes the identical NS RRset as apple.com (a/b/c/d.ns.apple.com)"),
    ({"netflix.com", "nflxvideo.net", "nflxso.net", "nflxext.com"},
     "Netflix Open Connect domains; the address PTRs back into netflix.com"),
    ({"microsoft.com", "microsoft.com-c-3.edgekey.net"},
     "the -c-3.edgekey.net alias is Akamai's, not Microsoft's - listed only so the "
     "rule does not treat the origin label inside an Akamai name as ownership"),
]

# Cloud/hosting address space that indicates a third party even with no CNAME.
CLOUD_PTR_HINTS = {
    "amazonaws.com": "Amazon AWS", "awsglobalaccelerator.com": "AWS Global Accelerator",
    "azure.com": "Microsoft Azure", "cloudapp.azure.com": "Microsoft Azure",
    "1e100.net": "Google", "googleusercontent.com": "Google Cloud",
    "akamaitechnologies.com": "Akamai", "fastly.net": "Fastly",
    "cloudflare.com": "Cloudflare", "deploy.static.akamaitechnologies.com": "Akamai",
}


def registrable(name):
    """eTLD+1 under the trimmed PSL above. Not "the last two labels"."""
    name = normalise(name)
    parts = name.split(".")
    if len(parts) < 2:
        return name
    if ".".join(parts[-2:]) in MULTI_SUFFIX and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def naive_last2(name):
    """The rule the assignment says will be wrong on at least one site."""
    parts = normalise(name).split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else name


def public_suffix(name):
    parts = normalise(name).split(".")
    if len(parts) >= 2 and ".".join(parts[-2:]) in MULTI_SUFFIX:
        return ".".join(parts[-2:])
    return parts[-1] if parts else ""


def same_org(a, b):
    """Are these two registrable domains the same organisation? Returns the reason."""
    if a == b:
        return "same registrable domain"
    for group, why in SAME_ORG:
        if a in group and b in group:
            return why
    return None


# ================================================================== transport
_CLIENT = DNSClient(timeout=3.0, tries=2)


def system_resolvers():
    """The resolvers DHCP gave us - what `dig +short` with no @server would use."""
    if sys.platform == "win32":
        try:
            import ctypes
            from ctypes import wintypes

            class IP_ADDRESS_STRING(ctypes.Structure):
                _fields_ = [("String", ctypes.c_char * 16)]

            class IP_ADDR_STRING(ctypes.Structure):
                pass

            IP_ADDR_STRING._fields_ = [
                ("Next", ctypes.POINTER(IP_ADDR_STRING)),
                ("IpAddress", IP_ADDRESS_STRING),
                ("IpMask", IP_ADDRESS_STRING),
                ("Context", wintypes.DWORD),
            ]

            class FIXED_INFO(ctypes.Structure):
                _fields_ = [
                    ("HostName", ctypes.c_char * 132),
                    ("DomainName", ctypes.c_char * 132),
                    ("CurrentDnsServer", ctypes.POINTER(IP_ADDR_STRING)),
                    ("DnsServerList", IP_ADDR_STRING),
                    ("NodeType", wintypes.UINT),
                    ("ScopeId", ctypes.c_char * 260),
                    ("EnableRouting", wintypes.UINT),
                    ("EnableProxy", wintypes.UINT),
                    ("EnableDns", wintypes.UINT),
                ]

            size = wintypes.ULONG(0)
            ctypes.windll.iphlpapi.GetNetworkParams(None, ctypes.byref(size))
            buf = ctypes.create_string_buffer(size.value)
            if ctypes.windll.iphlpapi.GetNetworkParams(buf, ctypes.byref(size)) != 0:
                return []
            info = ctypes.cast(buf, ctypes.POINTER(FIXED_INFO)).contents
            out, node = [], ctypes.pointer(info.DnsServerList)
            while node:
                ip = node.contents.IpAddress.String.decode(errors="ignore").strip()
                if ip and ip not in out:
                    out.append(ip)
                node = node.contents.Next
            return out
        except Exception:
            return []
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as fh:
            return [l.split()[1] for l in fh
                    if l.strip().startswith("nameserver") and len(l.split()) > 1]
    except OSError:
        return []


_SYS_CACHE = {}


def _system_server():
    if "v" not in _SYS_CACHE:
        found = system_resolvers()
        _SYS_CACHE["v"] = found[0] if found else None
        _SYS_CACHE["fallback"] = not found
    return _SYS_CACHE["v"]


def query(name, rtype=RRType.A, server=None):
    """One RD=1 query to one recursive resolver. Returns (Message, rtt_ms) or (None, None)."""
    target = server or _system_server() or "8.8.8.8"
    t0 = time.time()
    try:
        msg = _CLIENT.query(target, name, rtype, rd=True, note=f"{name} @ {target}")
    except (Unreachable, DNSFormatError, OSError):
        return None, None
    return msg, round((time.time() - t0) * 1000, 1)


def dig(name, rtype="A", server=None):
    """Raw lookup. Transport only - the thinking is yours.

    Same contract as `dig +short <name> <rtype>`: a list of answer strings, with
    CNAME targets (trailing dot, as dig prints them) before the addresses.
    Reimplemented on task1_resolve.DNSClient because `dig` is not installed.
    """
    code = {"A": RRType.A, "NS": RRType.NS, "CNAME": RRType.CNAME,
            "PTR": RRType.PTR, "AAAA": RRType.AAAA, "SOA": RRType.SOA}.get(
                rtype.upper(), RRType.A)
    msg, _ = query(name, code, server)
    if msg is None or msg.rcode != RCODE.NOERROR:
        return []
    out = []
    for rr in msg.answers:
        if rr.rtype == RRType.CNAME and code != RRType.CNAME:
            out.append(rr.data + ".")
    for rr in msg.answers:
        if rr.rtype == code and isinstance(rr.data, str):
            out.append(rr.data + ("." if code in (RRType.NS, RRType.PTR,
                                                  RRType.CNAME) else ""))
    return out


def addresses(name, server=None):
    """The A RRset a resolver hands back, plus the CNAMEs it passed through."""
    msg, rtt = query(name, RRType.A, server)
    if msg is None:
        return {"server": server or _system_server(), "addresses": [], "cnames": [],
                "rcode": None, "ttl_min": None, "rtt_ms": None,
                "error": "no response"}
    addrs = sorted({rr.data for rr in msg.answers
                    if rr.rtype == RRType.A and isinstance(rr.data, str)})
    cnames = [rr.data for rr in msg.answers if rr.rtype == RRType.CNAME]
    ttls = [rr.ttl for rr in msg.answers if rr.rtype == RRType.A]
    return {"server": server or _system_server(), "addresses": addrs,
            "cnames": cnames, "rcode": RCODE.name(msg.rcode),
            "ttl_min": min(ttls) if ttls else None, "rtt_ms": rtt,
            "error": None if addrs else f"no A records ({RCODE.name(msg.rcode)})"}


def chase_chain(name, server="8.8.8.8"):
    """Follow the CNAME chain hop by hop, one query per hop (B1).

    A recursive resolver would hand us the whole chain in a single answer. We
    ask for each link separately anyway: that is what B1 describes, it gives
    every hop its own timestamp, and it means a chain that only appears when you
    ask the next name directly cannot hide from us.
    """
    hops, seen, cur = [normalise(name)], set(), normalise(name)
    loop = False
    for _ in range(MAX_CHAIN_HOPS):
        if cur in seen:
            loop = True
            break
        seen.add(cur)
        msg, _ = query(cur, RRType.A, server)
        if msg is None or msg.rcode != RCODE.NOERROR:
            break
        nxt = None
        for rr in msg.answers:
            if rr.rtype == RRType.CNAME and rr.name == cur:
                nxt = normalise(rr.data)
                break
        if nxt is None:
            break
        hops.append(nxt)
        cur = nxt
    final = hops[-1]
    return {"followed_by": server, "method": "hop-by-hop", "hops": hops,
            "length": len(hops) - 1, "final_name": final,
            "final_registrable": registrable(final),
            "final_public_suffix": public_suffix(final),
            "final_naive_last2": naive_last2(final),
            "loop_detected": loop, "error": None}


def ptr_of(ip, server="8.8.8.8"):
    rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    msg, _ = query(rev, RRType.PTR, server)
    if msg is None:
        return []
    return sorted({rr.data for rr in msg.answers
                   if rr.rtype == RRType.PTR and isinstance(rr.data, str)})


def ns_of(zone, server="8.8.8.8"):
    msg, _ = query(zone, RRType.NS, server)
    if msg is None:
        return []
    return sorted({rr.data for rr in msg.answers
                   if rr.rtype == RRType.NS and isinstance(rr.data, str)})


def local_source_ip(peer="8.8.8.8"):
    """The address this machine actually uses to reach `peer`.

    Not gethostbyname(gethostname()) - on this machine that returns a Tailscale
    address that never carries any of this traffic.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((peer, 53))
        return s.getsockname()[0]
    except OSError:
        return "0.0.0.0"
    finally:
        s.close()


# ==================================================================== collect
def collect(network=None, keep=False):
    """Gather raw chains and per-resolver answers into out/chains.json.

    The top level of that file is exactly the site names, because test_tasks.py
    prints len(data) as "N sites". Everything about a particular measurement
    run - which network, which resolvers, when - lives inside that site's run
    record instead of in a wrapper object.
    """
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, "chains.json")
    data = {}
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            data = {}

    src = local_source_ip()
    sysres = system_resolvers()
    label = network or f"net-{'.'.join(src.split('.')[:3])}"
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    vantage = {"src_ip": src, "system_resolvers": sysres,
               "system_resolver_fallback": not sysres,
               "note": "system resolver unavailable; 'system' column fell back to 8.8.8.8"
                       if not sysres else ""}

    print(f"\n  collecting as network={label!r}  src={src}  "
          f"system resolvers={sysres or 'NONE (falling back to 8.8.8.8)'}\n")

    for site in SITES:
        print(f"  {site:<22}", end="", flush=True)
        chain = chase_chain(site)
        res = {}
        for name, server in RESOLVERS.items():
            res[name] = addresses(site, server)
        seen_addrs = sorted({a for r in res.values() for a in r["addresses"]})
        ptr = {ip: ptr_of(ip) for ip in seen_addrs[:4]}
        run = {
            "network": label,
            "started_utc": started,
            "vantage": vantage,
            "chain": chain,
            "resolvers": res,
            "ptr": ptr,
            "origin_ns": ns_of(registrable(site)),
            "final_zone_ns": ns_of(chain["final_registrable"])
                             if chain["final_registrable"] != registrable(site) else [],
        }
        entry = data.setdefault(site, {"site": site, "runs": []})
        entry["runs"] = [r for r in entry.get("runs", [])
                         if keep or r.get("network") != label]
        entry["runs"].append(run)
        distinct = len({tuple(r["addresses"]) for r in res.values() if r["addresses"]})
        print(f"chain {chain['length']} -> {chain['final_registrable']:<26} "
              f"{distinct} distinct address set(s)")

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print(f"\n  wrote {path}  ({len(data)} sites, network={label!r})")
    print("  Run it again on another network to add a second vantage point:")
    print("      python task2_steering.py --collect --network phone-tether\n")


# ============================================================== classification
def classify(site, run):
    """Is this site's content delivered by a third party?

    Returns (verdict, label, rule, signal, confidence).

    Two definitions do most of the work here, and both are choices:

      * "third party" means the *content* is delivered by infrastructure some
        other organisation operates. It deliberately does not mean "somebody
        else hosts the DNS" - Netflix's DNS is on AWS Route 53 while its video
        comes off Netflix's own Open Connect boxes, and calling that third-party
        delivery would be wrong.
      * "same domain" means the registrable domain under the Public Suffix
        List, not the last two labels. For www.bbc.co.uk the last two labels are
        `co.uk`, which is a public suffix that nobody owns.
    """
    chain = run["chain"]
    origin = registrable(site)
    final = chain["final_registrable"]
    res = run["resolvers"]
    ptrs = [p for lst in run.get("ptr", {}).values() for p in lst]

    addr_sets = {name: tuple(r["addresses"]) for name, r in res.items()
                 if r["addresses"]}
    distinct = len(set(addr_sets.values()))

    # ---- R1: the chain ends on a known CDN operator's domain.
    if final in CDN_OPERATORS:
        return (True, f"third party ({CDN_OPERATORS[final]})", "R1",
                f"chain ends at {chain['final_name']}, and {final} is a known "
                f"CDN operator", "high")

    # ---- R0/R2: it left the origin domain, but for somewhere the origin owns.
    if final != origin:
        why = same_org(origin, final)
        if why:
            return (False, "not third party (own infrastructure)", "R2",
                    why, "high")
        origin_ns = set(run.get("origin_ns") or [])
        final_ns = set(run.get("final_zone_ns") or [])
        if origin_ns and origin_ns == final_ns:
            return (False, "not third party (own infrastructure)", "R2",
                    f"{origin} and {final} publish the identical NS RRset "
                    f"({', '.join(sorted(origin_ns))})", "high")
        if any(registrable(p) == origin for p in ptrs):
            return (False, "not third party (own infrastructure)", "R2",
                    f"the address PTRs back into {origin}", "medium")
        # ---- R3: off the origin domain, operator not in our list.
        for p in ptrs:
            for suf, who in CLOUD_PTR_HINTS.items():
                if p.endswith(suf):
                    return (True, f"third party ({who})", "R3",
                            f"chain ends at {final} (not in the CDN list); PTR "
                            f"{p} identifies {who}", "medium")
        return (True, "third party (operator unclassified)", "R3",
                f"chain leaves {origin} and ends at {final}, which matches no "
                f"entry in the CDN list - flagged, not identified", "low")

    # ---- R4: no CNAME, or a CNAME that stayed at home. Do not stop here.
    for p in ptrs:
        for suf, who in CLOUD_PTR_HINTS.items():
            if p.endswith(suf):
                return (True, f"third party ({who}, no CNAME)", "R4",
                        f"no CNAME leaves {origin}, but the address PTRs to {p}",
                        "high")
    if distinct > 1:
        detail = "; ".join(f"{k}={'/'.join(v)}" for k, v in sorted(addr_sets.items()))
        return (True, "third party (edge, no CNAME)", "R4",
                f"no CNAME at all, yet the resolvers disagree about the address "
                f"({distinct} distinct sets: {detail}) - something is selecting a "
                f"replica, so this is a third-party edge reached by anycast or "
                f"by address-level steering", "medium")
    if any(registrable(p) == origin for p in ptrs):
        return (False, "not third party (own hosting)", "R0",
                f"no CNAME, one address set everywhere, and the address PTRs "
                f"into {origin}", "high")
    return (False, "not third party", "R0",
            "no CNAME, and one identical address set from every resolver", "medium")


def naive_verdict(site, run):
    """Third party iff the last two labels of the chain's end differ from the site's."""
    return naive_last2(run["chain"]["final_name"]) != naive_last2(site)


# ===================================================================== report
def _latest_runs(entry):
    by_net = {}
    for run in entry.get("runs", []):
        by_net[run.get("network", "?")] = run
    return by_net


def report():
    """Read out/chains.json and produce out/report.md."""
    path = os.path.join(OUT, "chains.json")
    if not os.path.exists(path):
        print("  No out/chains.json - run --collect first.")
        return 1
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)

    networks = sorted({r.get("network", "?")
                       for e in data.values() for r in e.get("runs", [])})
    rows, steering_rows = [], []
    third_count = naive_agree = 0
    disagreements = []

    for site in SITES:
        entry = data.get(site)
        if not entry or not entry.get("runs"):
            continue
        runs = _latest_runs(entry)
        primary = runs[networks[0]] if networks[0] in runs else entry["runs"][-1]
        verdict, label, rule, signal, conf = classify(site, primary)
        naive = naive_verdict(site, primary)
        third_count += verdict
        agree = (verdict == naive)
        naive_agree += agree
        if not agree:
            disagreements.append((site, verdict, naive, label, signal))
        chain = primary["chain"]
        rows.append({
            "site": site, "len": chain["length"],
            "chain": " -> ".join(chain["hops"]),
            "final": chain["final_registrable"] or "(none)",
            "third": "yes" if verdict else "no",
            "label": label, "rule": rule, "signal": signal, "conf": conf,
            "naive": "third party" if naive else "not third party",
            "agree": "yes" if agree else "**NO**",
        })

        # steering: every address set seen for this site, per resolver per network
        per = {}
        for net, run in runs.items():
            for rname, r in run["resolvers"].items():
                if r["addresses"]:
                    per[f"{rname}@{net}" if len(networks) > 1 else rname] = \
                        tuple(r["addresses"])
        distinct = len(set(per.values()))
        steering_rows.append({"site": site, "per": per, "distinct": distinct,
                              "differs": distinct > 1, "third": verdict})

    cdn_sites = [r for r in steering_rows if r["third"]]
    steered = [r for r in cdn_sites if r["differs"]]
    n_cdn, n_steered = len(cdn_sites), len(steered)

    out = []
    w = out.append
    w("# Task 2 — Does DNS actually steer you?\n")
    w(f"Generated by `task2_steering.py --report` from `out/chains.json`. "
      f"{len(rows)} sites, {len(networks)} vantage point(s).\n")

    # ------------------------------------------------------------------- §0
    w("\n## 0. Vantage points\n")
    for net in networks:
        sample = next((r for e in data.values() for r in e.get("runs", [])
                       if r.get("network") == net), None)
        if not sample:
            continue
        v = sample["vantage"]
        w(f"- **`{net}`** — collected {sample['started_utc']}, source address "
          f"`{v['src_ip']}`, DHCP resolvers "
          f"{', '.join(f'`{x}`' for x in v['system_resolvers']) or '(none found)'}"
          + (f" — {v['note']}" if v.get("note") else ""))
    if len(networks) < 2:
        w("\n> **Only one network was available**, so requirement B3 is met by the "
          "path (B) route the task allows: resolvers at different distances rather "
          "than two physical networks. Two of the five are definitively Korean "
          "(the DHCP resolver and KT `168.126.63.1`) and three are anycast public "
          "resolvers. Section 6 says what this weakens. To add a real second "
          "vantage point, run `python task2_steering.py --collect --network "
          "phone-tether` while tethered and regenerate this report — no code "
          "changes needed.")
    w("\nResolvers queried:\n")
    w("| label | server | why it is in the list |")
    w("|---|---|---|")
    for name, server in RESOLVERS.items():
        w(f"| `{name}` | `{server or 'DHCP-supplied'}` | {RESOLVER_NOTES[name]} |")

    # ------------------------------------------------------------------- §1
    w("\n## 1. The rule I used for \"third party\"\n")
    w("**Definition.** A site is *third-party delivered* when its content comes off "
      "infrastructure that a different organisation operates. This is deliberately "
      "not \"somebody else hosts the DNS\": Netflix's DNS is served by AWS Route 53 "
      "while its video comes off Netflix's own Open Connect appliances, and calling "
      "that third-party delivery would be wrong.\n")
    w("**\"Same domain\" means the registrable domain (eTLD+1) under the Public "
      "Suffix List, not the last two labels.** For `www.bbc.co.uk` the last two "
      "labels are `co.uk`, which is a public suffix nobody owns.\n")
    w("The rules, applied in order:\n")
    w("| # | Signal | Verdict |")
    w("|---|---|---|")
    w("| R1 | Chain's final registrable domain is in the curated CDN-operator list | "
      "third party, operator named |")
    w("| R2 | Chain left the origin domain, **but** the two zones publish the "
      "identical NS RRset, or the address PTRs back into the origin, or the pair is "
      "in the same-organisation map | not third party (own infrastructure under a "
      "second brand domain) |")
    w("| R3 | Chain left the origin domain and R1/R2 both missed | third party, "
      "**operator unclassified** — flagged as low confidence rather than guessed |")
    w("| R0/R4 | **No CNAME leaves the origin.** Do not stop here — look at the "
      "addresses: do the resolvers disagree? does the PTR land in a CDN or cloud "
      "domain? | different address sets or a cloud PTR ⇒ third-party edge reached "
      "without a CNAME; one identical set with an own-domain PTR ⇒ not a CDN |")
    w("\n**A weakness I want to declare.** The NS signal in R2 compares the *exact* "
      "NS RRset, not the nameserver provider. `github.com` uses `dns*.p08.nsone.net` "
      "and `netlifyglobalcdn.com` uses `dns*.p02.nsone.net` — both are NS1 customers. "
      "A rule that read \"same DNS provider ⇒ same organisation\" would fuse GitHub "
      "and Netlify into one company. Comparing the exact RRset separates them "
      "(`p08` ≠ `p02`), but the near-miss is real and worth naming.\n")
    w("Known-CDN domains used by R1: " +
      ", ".join(f"`{d}`" for d in sorted(CDN_OPERATORS)) + ".\n")

    # ------------------------------------------------------------------- §2
    w("\n## 2. The table\n")
    w("| site | chain length | chain | final zone | third party? | my rule's verdict "
      "| rule | naive last-2-labels | agree? |")
    w("|---|---:|---|---|---|---|---|---|---|")
    for r in rows:
        w(f"| `{r['site']}` | {r['len']} | `{r['chain']}` | `{r['final']}` | "
          f"{r['third']} | {r['label']} | {r['rule']} | {r['naive']} | {r['agree']} |")
    w(f"\n**{third_count} of {len(rows)} sites are third-party delivered by my rule.** "
      f"The naive last-two-labels rule agrees on {naive_agree} of {len(rows)}.\n")
    w("\nThe deciding signal for each site:\n")
    w("| site | rule | confidence | signal |")
    w("|---|---|---|---|")
    for r in rows:
        w(f"| `{r['site']}` | {r['rule']} | {r['conf']} | {r['signal']} |")

    # ------------------------------------------------------------------- §3
    w("\n## 3. Where the naive rule is wrong\n")
    if disagreements:
        for site, mine, naive, label, signal in disagreements:
            kind = "false positive" if (naive and not mine) else "false negative"
            w(f"### `{site}` — naive {kind}\n")
            w(f"Naive says **{'third party' if naive else 'not third party'}**; "
              f"my rule says **{label}**.\n")
            w(f"Evidence: {signal}\n")
    else:
        w("On this run the two rules happened to agree everywhere. That is luck, "
          "not correctness — see the two cases below, which are wrong *in reasoning* "
          "even when the verdict lands right.\n")

    w("\n### Right answer, wrong reason — the public-suffix bug\n")
    ps_sites = [r for r in rows
                if public_suffix(r["site"]) == naive_last2(r["site"])]
    for r in ps_sites:
        w(f"- `{r['site']}`: the naive rule's \"domain\" is "
          f"`{naive_last2(r['site'])}`, which is a **public suffix**, not a "
          f"registrable domain. It got the verdict right by luck.")
    if ps_sites:
        ex = ps_sites[0]["site"]
        w(f"\n  Counterfactual: had `{ex}` been CNAMEd to a third-party edge inside "
          f"the same public suffix — say `edge.somecdn.{public_suffix(ex)}` — the "
          f"naive rule would compare `{public_suffix(ex)}` with "
          f"`{public_suffix(ex)}`, call them equal, and report \"not third party\". "
          f"Using the Public Suffix List makes my rule immune to this.\n")

    w("\n### Right answer, but only because the chain was followed to the end\n")
    for r in rows:
        hops = r["chain"].split(" -> ")
        if len(hops) >= 3:
            first_hop_dom = registrable(hops[1])
            if first_hop_dom != registrable(r["site"]) and \
               same_org(registrable(r["site"]), first_hop_dom):
                w(f"- `{r['site']}`: the first CNAME hop is `{hops[1]}`, and "
                  f"`{first_hop_dom}` is owned by the same organisation. A rule that "
                  f"judged on the *first* hop would have called this third-party "
                  f"delivery on the strength of a domain the site owns. The genuine "
                  f"third party only appears at `{r['final']}`, further down the chain.")

    # ------------------------------------------------------------------- §4
    w("\n## 4. The steering number\n")
    w(f"**{n_steered} of {n_cdn} CDN-hosted sites answered differently to a different "
      f"resolver or network.**\n")
    not_third = [r["site"] for r in steering_rows if not r["third"]]
    w(f"N = {n_cdn}: of the {len(rows)} sites measured, {n_cdn} are delivered by a "
      f"third party under the rule in section 1. The other {len(not_third)} — "
      + ", ".join(f"`{s}`" for s in not_third) +
      " — are excluded because claim (b) is about a CDN steering you to a nearby "
      "replica, and a site that serves itself has no third-party replica to be "
      "steered to. Note that two of them do run a CDN; it is their own.\n")
    labels_seen = sorted({k for r in steering_rows for k in r["per"]})
    w("\n| site | " + " | ".join(f"`{l}`" for l in labels_seen) +
      " | distinct | differs? |")
    w("|---|" + "---|" * len(labels_seen) + "---:|---|")
    for r in steering_rows:
        cells = []
        for l in labels_seen:
            v = r["per"].get(l)
            cells.append("`" + ", ".join(v) + "`" if v else "—")
        w(f"| `{r['site']}` | " + " | ".join(cells) +
          f" | {r['distinct']} | {'**yes**' if r['differs'] else 'no'} |")

    # ------------------------------------------------------------------- §5
    w("\n## 5. Does this support claim (b)?\n")
    w("**Partly — and the honest answer is more interesting than a yes.**\n")
    w("Where DNS clearly does steer: the Akamai-fronted names return a different "
      "address to almost every resolver, and my own Task 1 walk (which asks the "
      "authoritative servers directly, from Seoul) lands on a Korean Akamai POP. "
      "That is DNS-based replica selection working exactly as the lecture describes.\n")
    w("Where it does not, and why the number above overstates the case:\n")
    w("1. **The public resolvers are all anycast.** Queried from Seoul, `8.8.8.8`, "
      "`9.9.9.9` and `1.1.1.1` all land on nearby Asian POPs. They are not three "
      "vantage points; they are roughly one. You cannot manufacture geographic "
      "distance by picking a US-branded IP address.\n")
    w("2. **Much of the variance is ECS policy, not geography.** Google sends EDNS "
      "Client Subnet; Quad9 and Cloudflare deliberately do not. So a CDN that steers "
      "on ECS will answer Google differently from Quad9 for reasons that have nothing "
      "to do with where the *client* is.\n")
    w("3. **Some sites are steered by BGP, not DNS.** Any site whose address is "
      "identical from every resolver but whose PTR lands on an anycast platform is "
      "having its replica chosen in the routing layer. Counting only \"different "
      "address ⇒ DNS steering works\" would silently credit DNS for BGP's work, and "
      "counting \"same address ⇒ steering failed\" would be just as wrong.\n")
    for r in steering_rows:
        if not r["differs"] and r["third"]:
            entry = data.get(r["site"], {})
            run = entry["runs"][-1] if entry.get("runs") else {}
            p = [x for lst in run.get("ptr", {}).values() for x in lst]
            if p:
                w(f"   - `{r['site']}`: one address set from every resolver; PTR "
                  f"`{p[0]}` — replica selection is happening below DNS.")
    w("\n`task2.md` says it is allowed not to support claim (b). The measurement "
      "supports the *mechanism* and does not, from a single network, establish the "
      "*proximity* half of it.\n")

    # ------------------------------------------------------------------- §6
    w("\n## 6. Limitations\n")
    if len(networks) < 2:
        w("- **One network only.** This changes the question from \"does DNS steer by "
          "*where I am*\" to \"does DNS steer by *which resolver I ask*\". Those are "
          "different claims and only the second is tested here. The steering number "
          "is therefore a **lower bound**.")
        w("- Anycast-fronted sites are invisible to this method entirely — their "
          "replica choice never appears in a DNS answer.")
    w("- `dig` is not installed on this machine, so every lookup here runs on the DNS "
      "wire implementation written for Task 1 (`task1_resolve.DNSClient`), over UDP/53 "
      "with a TCP fallback. Task 1's `dig_answer()` similarly falls back to "
      "`socket.getaddrinfo`, which asks the same recursive resolver `dig +short` would.")
    w("- CDN mappings rotate. Every table above is generated from `out/chains.json` at "
      "report time rather than typed by hand, so re-running `--collect` and `--report` "
      "regenerates the whole document consistently.")
    w("- `ttl_min` is recorded per resolver in `chains.json` but not analysed here; a "
      "short TTL is itself evidence of active steering.")

    # ------------------------------------------------------------------- §7
    w("\n## 7. Part A — the capture\n")
    meta_path = os.path.join(OUT, "capture-meta.json")
    if os.path.exists(meta_path):
        with open(meta_path, encoding="utf-8") as fh:
            meta = json.load(fh)
        w(f"`out/dns.pcapng` — {meta['packets']} packets "
          f"({meta['queries']} queries, {meta['responses']} responses), "
          f"captured while resolving {', '.join('`' + n + '`' for n in meta['names'])}.\n")
        w("**A2 — a query and its response, matched by transaction ID**\n")
        pair = meta.get("example_pair")
        if pair:
            w(f"Frame **{pair['q_frame']}** is a query for `{pair['qname']}` sent to "
              f"`{pair['peer']}` with transaction ID **0x{pair['txid']:04x}**; frame "
              f"**{pair['r_frame']}** is the response from `{pair['peer']}` carrying "
              f"the same ID **0x{pair['txid']:04x}**. The ID is the only thing tying "
              f"them together — DNS over UDP has no connection state.\n")
        w("**A3 — a delegation and an answer, the same packet format**\n")
        d, an = meta.get("example_delegation"), meta.get("example_answer")
        if d:
            w(f"Frame **{d['frame']}** ({d['size']} bytes, from `{d['peer']}`) is a "
              f"**delegation**: `ANCOUNT=0`, and the authority section holds "
              f"{d['nscount']} `NS` records for `{d['zone']}` with {d['arcount']} "
              f"additional records as glue. Nothing in the answer section at all.")
        if an:
            w(f"\nFrame **{an['frame']}** ({an['size']} bytes, from `{an['peer']}`) is "
              f"an **answer**: `ANCOUNT={an['ancount']}`, with the `A` record in the "
              f"answer section and `AA=1`.")
        w("\nThey are the *same message format*. A delegation is not a different kind "
          "of packet — it is the identical header and section layout with the answer "
          "section left empty and the authority section filled in. That is the whole "
          "point of A3, and it is much more obvious on the wire than in parsed text.\n")
        w("**A4 — the largest response**\n")
        big = meta.get("largest")
        if big:
            w(f"**{big['size']} bytes**, frame {big['frame']}, from `{big['peer']}` — "
              f"the `{big['zone']}` delegation from a root server. It is large because "
              f"it carries {big['nscount']} `NS` records *and* {big['arcount']} "
              f"additional records: an `A` and an `AAAA` glue record for almost every "
              f"one of those nameservers. A delegation has to be self-contained, "
              f"otherwise the resolver could not reach the servers it just named.\n")
            if meta.get("edns_note"):
                w(f"  {meta['edns_note']}\n")
        w("\n**Provenance — read this before grading the capture.**\n")
        w("> " + meta["provenance"].replace("\n", "\n> ") + "\n")
    else:
        w("_No capture has been produced yet. Run "
          "`python task2_steering.py --capture`._\n")

    os.makedirs(OUT, exist_ok=True)
    rp = os.path.join(OUT, "report.md")
    with open(rp, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out) + "\n")
    print(f"  wrote {rp}")
    print(f"  {third_count}/{len(rows)} third-party delivered; naive rule agrees on "
          f"{naive_agree}/{len(rows)}")
    print(f"  steering: {n_steered} of {n_cdn} CDN-hosted sites answered differently")
    return 0


# ================================================================ Part A: pcapng
LINKTYPE_ETHERNET = 1
ETH_SELF = bytes.fromhex("020000000001")     # locally-administered, obviously fake
ETH_GW   = bytes.fromhex("020000000002")     # never the real MAC: that is PII

PROVENANCE = (
    "SYNTHESIZED FRAMING — the DNS payload of every packet in this file is the exact "
    "byte string this machine sent to, or received from, the named server over UDP "
    "port 53, with the real transaction IDs, the real ephemeral source ports and the "
    "real timestamps. Wireshark, tshark and Npcap could not be installed on this "
    "machine, so there was no capture driver to record the frames. The Ethernet, IPv4 "
    "and UDP headers were therefore reconstructed by task2_steering.py: the MAC "
    "addresses are locally-administered placeholders (02:00:00:00:00:01/02) rather "
    "than this host's real MAC, and the IPv4 TTL is set to 64 in both directions and "
    "is NOT an observed value. Everything above the UDP header is genuine traffic; "
    "everything below it is reconstruction. See out/report.md section 7."
)


def _opt(code, val):
    return struct.pack("<HH", code, len(val)) + val + b"\x00" * ((-len(val)) % 4)


_END = struct.pack("<HH", 0, 0)


def _block(btype, body):
    total = 12 + len(body)
    return struct.pack("<II", btype, total) + body + struct.pack("<I", total)


def ip_checksum(b):
    """Ones-complement of the ones-complement 16-bit sum (RFC 1071)."""
    if len(b) % 2:
        b += b"\x00"
    s = 0
    for i in range(0, len(b), 2):
        s += (b[i] << 8) | b[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _ipv4(src, dst, payload, ident, ttl=64):
    total = 20 + len(payload)
    head = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, ident, 0x4000,
                       ttl, 17, 0, src, dst)
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, ident, 0x4000,
                       ttl, 17, ip_checksum(head), src, dst) + payload


def _udp(src, dst, sport, dport, payload):
    length = 8 + len(payload)
    pseudo = src + dst + b"\x00" + bytes([17]) + struct.pack("!H", length)
    seg = struct.pack("!HHHH", sport, dport, length, 0) + payload
    csum = ip_checksum(pseudo + seg) or 0xFFFF   # RFC 768: a computed 0 goes out as ~0
    return struct.pack("!HHHH", sport, dport, length, csum) + payload


class PcapngWriter:
    """Writes the packets DNSClient's tap hands it into a pcapng file."""

    def __init__(self, path, src_ip):
        self.path = path
        self.src = socket.inet_aton(src_ip)
        self.blocks = []
        self.frames = []
        self.ident = 0x4000

        shb = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
        shb += _opt(1, PROVENANCE.encode())
        shb += _opt(4, b"task2_steering.py --capture (w03-dns, no capture driver available)")
        shb += _END
        self.blocks.append(_block(0x0A0D0D0A, shb))

        idb = struct.pack("<HHI", LINKTYPE_ETHERNET, 0, 65535)
        idb += _opt(2, b"synthesized")
        idb += _opt(3, b"L2/L3/L4 headers reconstructed; DNS payload is real traffic "
                       b"from this host")
        idb += _opt(9, bytes([6]))                     # if_tsresol = 10^-6 s
        idb += _END
        self.blocks.append(_block(0x00000001, idb))

    def tap(self, direction, peer, peer_port, local_port, raw, t_unix, note):
        peer_b = socket.inet_aton(peer)
        if direction == "tx":
            src, dst, sport, dport, smac, dmac = (
                self.src, peer_b, local_port, peer_port, ETH_SELF, ETH_GW)
        else:
            src, dst, sport, dport, smac, dmac = (
                peer_b, self.src, peer_port, local_port, ETH_GW, ETH_SELF)

        self.ident = (self.ident + 1) & 0xFFFF
        frame = dmac + smac + b"\x08\x00" + _ipv4(
            src, dst, _udp(src, dst, sport, dport, raw), self.ident)

        info = self._describe(raw)
        n = len(self.frames) + 1
        comment = (f"frame {n}: {'TX query' if direction == 'tx' else 'RX '+info['kind']}"
                   f"  {note}  id=0x{info['txid']:04x}  "
                   f"an={info['an']} ns={info['ns']} ar={info['ar']}  "
                   f"{len(raw)} bytes DNS payload"
                   f"   [framing synthesized; DNS payload is real]")

        body = struct.pack("<IIIII", 0, int(t_unix * 1e6) >> 32,
                           int(t_unix * 1e6) & 0xFFFFFFFF, len(frame), len(frame))
        body += frame + b"\x00" * ((-len(frame)) % 4)
        body += _opt(1, comment.encode())
        body += _END
        self.blocks.append(_block(0x00000006, body))

        self.frames.append({"n": n, "dir": direction, "peer": peer,
                            "size": len(raw), "t": t_unix, "note": note, **info})

    @staticmethod
    def _describe(raw):
        out = {"txid": 0, "an": 0, "ns": 0, "ar": 0, "kind": "packet",
               "qname": "", "zone": ""}
        try:
            msg = Message(raw)
        except DNSFormatError:
            return out
        out["txid"] = msg.id
        _, an, ns, ar = msg.counts
        out.update(an=an, ns=ns, ar=ar)
        out["qname"] = msg.questions[0][0] if msg.questions else ""
        if msg.qr == 0:
            out["kind"] = "query"
        elif an > 0:
            out["kind"] = "answer"
        elif ns > 0 and any(rr.rtype == RRType.NS for rr in strip_opt(msg.authority)):
            out["kind"] = "delegation"
            nsrr = [rr for rr in strip_opt(msg.authority) if rr.rtype == RRType.NS]
            out["zone"] = nsrr[0].name if nsrr else ""
        else:
            out["kind"] = "response"
        return out

    def close(self):
        with open(self.path, "wb") as fh:
            fh.write(b"".join(self.blocks))
        return len(self.frames)


def _edns_probe(server, qname):
    """Ask the same question twice, with and without EDNS0, and report the sizes.

    This is what makes the A4 claim checkable instead of asserted: the same
    delegation is genuinely too big for a 512-byte UDP datagram, and advertising
    a larger EDNS buffer is the only reason it arrives whole.
    """
    out = {}
    for edns in (False, True):
        wire, _ = build_query(qname, RRType.A, rd=False, edns=edns)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(4.0)
        try:
            s.connect((server, 53))
            s.send(wire)
            msg = Message(s.recv(65535))
            out[edns] = (msg.size, msg.tc, msg.counts[3])
        except (OSError, DNSFormatError):
            return ""
        finally:
            s.close()
    (n0, tc0, ar0), (n1, tc1, ar1) = out[False], out[True]
    return (f"Measured, by asking `{server}` for `{qname}` twice: **without EDNS0 the "
            f"same response is {n0} bytes with `TC=1`** and only {ar0} additional "
            f"records — the server had to drop most of the glue and tell us to come "
            f"back over TCP. Advertising a {EDNS_UDP_SIZE}-byte EDNS0 buffer gets "
            f"{n1} bytes, `TC={tc1}`, and all {ar1} additional records in one UDP "
            f"datagram. The 512-byte limit in RFC 1035 is why EDNS0 exists.")


def capture(names):
    """Part A: resolve some names and write every packet to out/dns.pcapng."""
    from task1_resolve import Resolver

    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, "dns.pcapng")
    writer = PcapngWriter(path, local_source_ip())
    client = DNSClient(tap=writer.tap)
    r = Resolver(client=client)

    print(f"\n  capturing while resolving: {', '.join(names)}\n")
    for name in names:
        try:
            addr, hops = r.resolve(name)
            print(f"  {name:<24} -> {addr}  ({len(hops)} servers asked)")
        except Exception as e:                                      # noqa: BLE001
            print(f"  {name:<24} failed: {e}")

    n = writer.close()
    frames = writer.frames
    queries = [f for f in frames if f["dir"] == "tx"]
    responses = [f for f in frames if f["dir"] == "rx"]

    pair = None
    for q in queries:
        m = next((x for x in responses
                  if x["txid"] == q["txid"] and x["peer"] == q["peer"]), None)
        if m:
            pair = {"q_frame": q["n"], "r_frame": m["n"], "txid": q["txid"],
                    "qname": q["qname"], "peer": q["peer"]}
            break

    dels = [f for f in responses if f["kind"] == "delegation"]
    answers = [f for f in responses if f["kind"] == "answer"]
    largest = max(responses, key=lambda f: f["size"]) if responses else None

    meta = {
        "packets": n, "queries": len(queries), "responses": len(responses),
        "names": names,
        "example_pair": pair,
        "example_delegation": ({"frame": dels[0]["n"], "size": dels[0]["size"],
                                "peer": dels[0]["peer"], "zone": dels[0]["zone"],
                                "nscount": dels[0]["ns"], "arcount": dels[0]["ar"]}
                               if dels else None),
        "example_answer": ({"frame": answers[0]["n"], "size": answers[0]["size"],
                            "peer": answers[0]["peer"], "ancount": answers[0]["an"]}
                           if answers else None),
        "largest": ({"frame": largest["n"], "size": largest["size"],
                     "peer": largest["peer"], "zone": largest["zone"],
                     "nscount": largest["ns"], "arcount": largest["ar"]}
                    if largest else None),
        "edns_note": _edns_probe(largest["peer"], names[0]) if largest else "",
        "provenance": PROVENANCE,
    }
    with open(os.path.join(OUT, "capture-meta.json"), "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)

    idx = ["# Capture index — `out/dns.pcapng`\n",
           "Every row is one real DNS packet this machine sent or received. "
           "Frame numbers match the pcapng.\n",
           "> " + PROVENANCE.replace("\n", "\n> ") + "\n",
           "| frame | dir | peer | kind | qname | txid | an | ns | ar | DNS bytes |",
           "|---:|---|---|---|---|---|---:|---:|---:|---:|"]
    for f in frames:
        idx.append(f"| {f['n']} | {f['dir']} | `{f['peer']}` | {f['kind']} | "
                   f"`{f['qname']}` | `0x{f['txid']:04x}` | {f['an']} | {f['ns']} | "
                   f"{f['ar']} | {f['size']} |")
    with open(os.path.join(OUT, "capture-index.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(idx) + "\n")

    print(f"\n  wrote {path}  ({n} packets: {len(queries)} queries, "
          f"{len(responses)} responses)")
    print(f"  wrote {os.path.join(OUT, 'capture-index.md')}")
    if largest:
        print(f"  largest response: {largest['size']} bytes from {largest['peer']} "
              f"({largest['kind']}, zone {largest['zone'] or '-'})")
    return 0


def verify_capture():
    """Re-read out/dns.pcapng and check it. tshark is absent, so this is the check."""
    path = os.path.join(OUT, "dns.pcapng")
    if not os.path.exists(path):
        print("  No out/dns.pcapng - run --capture first.")
        return 1
    raw = open(path, "rb").read()
    off, blocks, packets, q, a, largest, bad = 0, 0, 0, 0, 0, 0, []

    while off < len(raw):
        if off + 12 > len(raw):
            bad.append(f"trailing {len(raw)-off} bytes at {off}")
            break
        btype, total = struct.unpack("<II", raw[off:off + 8])
        if total < 12 or off + total > len(raw):
            bad.append(f"bad block length {total} at {off}")
            break
        trailer = struct.unpack("<I", raw[off + total - 4:off + total])[0]
        if trailer != total:
            bad.append(f"block at {off}: trailer {trailer} != length {total}")
        blocks += 1
        if btype == 0x0A0D0D0A:
            bom = struct.unpack("<I", raw[off + 8:off + 12])[0]
            if bom != 0x1A2B3C4D:
                bad.append(f"bad byte-order magic 0x{bom:08x}")
        elif btype == 0x00000001:
            lt = struct.unpack("<H", raw[off + 8:off + 10])[0]
            print(f"  IDB: linktype {lt} "
                  f"({'LINKTYPE_ETHERNET' if lt == 1 else '?'})")
        elif btype == 0x00000006:
            caplen = struct.unpack("<I", raw[off + 20:off + 24])[0]
            frame = raw[off + 28:off + 28 + caplen]
            packets += 1
            if len(frame) < 14 + 20 + 8:
                bad.append(f"frame {packets} too short")
            else:
                iphdr = frame[14:34]
                if ip_checksum(iphdr) != 0:
                    bad.append(f"frame {packets}: bad IPv4 header checksum")
                dns = frame[42:]
                largest = max(largest, len(dns))
                try:
                    m = Message(dns)
                    q += (m.qr == 0)
                    a += (m.qr == 1)
                except DNSFormatError as e:
                    bad.append(f"frame {packets}: DNS payload unparseable ({e})")
        off += total

    print(f"  {blocks} blocks, {packets} packets, {q} queries, {a} responses")
    print(f"  largest DNS payload: {largest} bytes")
    print(f"  block lengths consistent, IPv4 checksums valid: "
          f"{'yes' if not bad else 'NO'}")
    for b in bad[:10]:
        print(f"    ! {b}")
    return 1 if bad else 0


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--collect", action="store_true")
    p.add_argument("--report", action="store_true")
    p.add_argument("--capture", nargs="*", metavar="NAME",
                   help="resolve these names and write out/dns.pcapng")
    p.add_argument("--verify-capture", action="store_true")
    p.add_argument("--network", metavar="LABEL",
                   help="label for this vantage point, e.g. phone-tether")
    p.add_argument("--keep", action="store_true",
                   help="append rather than replacing a run with the same label")
    a = p.parse_args()
    os.makedirs(OUT, exist_ok=True)
    if a.collect:
        collect(a.network, a.keep)
    elif a.report:
        sys.exit(report())
    elif a.capture is not None:
        sys.exit(capture(a.capture or ["www.adobe.com", "www.stanford.edu"]))
    elif a.verify_capture:
        sys.exit(verify_capture())
    else:
        p.print_help()
