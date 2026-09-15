#!/usr/bin/env python3
"""Week 3 · Task 1 — Build your own iterative resolver.

Textbook §2.4.2 - §2.4.3.

`dig +trace` walks root -> TLD -> authoritative for you. In this task you do
that walk yourself: start at a root server, read the delegation it returns,
ask the next server, and keep going until somebody answers authoritatively.

Transport is `dnsproto.py` in this folder - raw UDP and RFC 1035 message
parsing, because neither `dig` nor dnspython is installed on the machine this
was written on. Every query below goes out with **RD=0**, so no server ever
does the walk on our behalf.

    python3 task1_resolve.py www.korea.ac.kr
    python3 task1_resolve.py www.korea.ac.kr --trace     # show the walk
    python3 task1_resolve.py --verify                    # check against dig
    python3 task1_resolve.py www.korea.ac.kr --pcap out/dns.pcapng

Pass condition
--------------
`--verify` resolves five names with your resolver and with `dig`, and the
addresses must agree. A name behind a CDN may legitimately return a different
address each time; the harness compares the *set of authoritative nameservers*
you ended at for those, not the address.
"""
import argparse, shutil, subprocess, sys

import dnsproto
from dnsproto import DNSError, TYPE_A, TYPE_CNAME, TYPE_NS

# Root servers. Everything starts here; there is no earlier step.
ROOT_SERVERS = [
    "198.41.0.4",       # a.root-servers.net
    "199.9.14.201",     # b.root-servers.net
    "192.33.4.12",      # c.root-servers.net
]

# (name, kind).  "stable" names must match dig exactly.  "cdn" names are served
# from many replicas and may legitimately give you a different address than dig
# got a second earlier - for those we only require that you reached an answer.
VERIFY_NAMES = [
    ("www.korea.ac.kr", "stable"),
    ("dns.google", "stable"),
    ("en.wikipedia.org", "stable"),
    ("www.stanford.edu", "stable"),
    ("www.microsoft.com", "cdn"),
]


class Resolver:
    """An iterative resolver: root -> TLD -> authoritative, one hop at a time.

    The whole point is that we never ask a server to recurse for us. We ask a
    server, it says "not mine, ask over there", and we go there.

        resolve(name) -> (address, path)
            address : the A record we ended up with
            path    : every server we asked, in order - including the ones we
                      had to ask to find a nameserver's own address

    The four things that get in the way, and what this does about them:

    R3  A delegation hands over NS *names*. Glue (an A record for the
        nameserver, in the additional section) is only there when the
        nameserver lives inside the zone being delegated - `kr` gets glue for
        `c.dns.kr` because the address could not otherwise be found. When the
        nameserver lives somewhere else there is no glue and no need for it,
        and we have to resolve that name first, from the root, with this same
        walk. That sub-walk is where the "recursive" in recursive resolver
        comes from, and it is counted in `self.extra_lookups`.
    R4  A server that times out costs us nothing but the timeout: try the next
        one in the delegation. Only when every server in a delegation is dead
        does the walk fail.
    R5  A CNAME in the answer means the name we asked for is an alias. The
        address that comes back belongs to the target, so we restart the walk
        from the root with that target.
    R6  Depth caps on all three loops - delegations, CNAMEs, and nested
        nameserver lookups - so a malformed or malicious zone cannot hang us.
    """

    MAX_DEPTH = 16              # delegation hops in one walk
    MAX_CNAME = 8               # alias restarts
    MAX_NS_RECURSION = 3        # nested "resolve the nameserver's own name"
    MAX_QUERIES = 120           # total budget for one resolve()
    TIMEOUT = 3.0

    def __init__(self, log=None, trace=False, timeout=TIMEOUT):
        self.log = log                  # dnsproto.PacketLog, for Task 2 Part A
        self.trace = trace
        self.timeout = timeout
        self.reset()

    def reset(self):
        self.path = []                  # R1: servers asked, in order
        self.queries = 0
        self.glue_misses = 0            # delegations that arrived with no glue
        self.extra_lookups = 0          # queries spent resolving NS names
        self.cname_hops = []

    # ---------------------------------------------------------------- public
    def resolve(self, name):
        """Resolve `name` to an IPv4 address. Returns (address, path)."""
        self.reset()
        address = self._resolve(name.rstrip("."), cnames=0, ns_depth=0)
        return address, self.path

    # --------------------------------------------------------------- the walk
    def _resolve(self, name, cnames, ns_depth):
        if cnames > self.MAX_CNAME:
            raise DNSError(f"more than {self.MAX_CNAME} CNAMEs chasing {name}")

        servers = list(ROOT_SERVERS)
        zone = "."                      # the zone `servers` are authoritative for
        seen_zones = set()

        for depth in range(self.MAX_DEPTH):
            self._say(f"{'  ' * ns_depth}[{depth}] {name} ? ask {zone} "
                      f"({len(servers)} server(s))")
            reply = self._ask_any(servers, name)

            if reply.rcode == 3:                                  # NXDOMAIN
                raise DNSError(f"{name} does not exist (NXDOMAIN from {zone})")
            if reply.rcode != 0:
                raise DNSError(f"{zone} answered {reply.rcode_name} for {name}")

            if reply.is_answer():
                addrs = reply.records("answer", TYPE_A, name)
                if addrs:
                    self._say(f"{'  ' * ns_depth}      answer {addrs[0]['rdata']}"
                              f"{' (AA)' if reply.aa else ''}")
                    return addrs[0]["rdata"]

                cname = reply.records("answer", TYPE_CNAME, name)
                if cname:                                         # R5
                    target = cname[0]["rdata"]
                    self._say(f"{'  ' * ns_depth}      CNAME -> {target}, "
                              f"restarting at the root")
                    self.cname_hops.append((name, target))
                    # The answer often carries the target's A record already,
                    # but only a server authoritative for the *target* may say
                    # so. Restart the walk rather than trust the alias's zone.
                    return self._resolve(target, cnames + 1, ns_depth)

                # An A record for some other name, or an A we asked for under a
                # name we reached through a CNAME inside this same reply.
                any_a = reply.records("answer", TYPE_A)
                if any_a:
                    return any_a[-1]["rdata"]
                raise DNSError(f"{name}: answer section held nothing usable")

            if reply.is_delegation():
                next_zone = reply.records("authority", TYPE_NS)[0]["name"]
                if next_zone.lower() in seen_zones:               # R6
                    raise DNSError(f"delegation loop at {next_zone}")
                seen_zones.add(next_zone.lower())
                servers = self._servers_for(reply, next_zone, ns_depth)
                zone = next_zone or "."
                continue

            # NOERROR, no answer, no NS: the zone exists but has no A record
            # for this name (a bare SOA in the authority section).
            raise DNSError(f"{name}: no A record ({zone} answered with "
                           f"{len(reply.authority)} authority record(s))")

        raise DNSError(f"{name}: more than {self.MAX_DEPTH} delegations deep")

    def _servers_for(self, reply, zone, ns_depth):
        """Turn a delegation into a list of addresses we can ask.

        Glue first. When there is none, R3: resolve the nameservers' own names,
        which is another walk from the root.
        """
        ns_names = [r["rdata"] for r in reply.records("authority", TYPE_NS)]
        glue = [r["rdata"] for r in reply.additional
                if r["type"] == TYPE_A
                and r["name"].lower() in {n.lower() for n in ns_names}]
        if glue:
            self._say(f"{'  ' * ns_depth}      -> {zone}: {len(glue)} glue "
                      f"address(es) for {len(ns_names)} NS")
            return glue

        self.glue_misses += 1
        self._say(f"{'  ' * ns_depth}      -> {zone}: NO GLUE for "
                  f"{', '.join(ns_names[:3])} - resolving that name first")
        if ns_depth >= self.MAX_NS_RECURSION:                     # R6
            raise DNSError(f"nameserver lookups nested deeper than "
                           f"{self.MAX_NS_RECURSION} at {zone}")

        addresses = []
        for ns_name in ns_names:
            before = self.queries
            try:
                addresses.append(
                    self._resolve(ns_name, cnames=0, ns_depth=ns_depth + 1))
            except DNSError as e:
                self._say(f"{'  ' * ns_depth}         {ns_name}: {e}")
            finally:
                self.extra_lookups += self.queries - before
            if addresses:       # one reachable nameserver is enough to go on
                break
        if not addresses:
            raise DNSError(f"{zone}: no glue and no nameserver name resolved")
        return addresses

    def _ask_any(self, servers, name):
        """Ask each server in turn until one replies. R4."""
        errors = []
        for server in servers:
            if self.queries >= self.MAX_QUERIES:                  # R6
                raise DNSError(f"query budget ({self.MAX_QUERIES}) exhausted")
            self.queries += 1
            self.path.append(server)
            try:
                reply = dnsproto.ask(server, name, TYPE_A, rd=False,
                                     timeout=self.timeout, log=self.log)
            except DNSError as e:
                errors.append(str(e))
                self._say(f"        {server} did not answer, trying the next")
                continue
            if reply.tc:
                # Not a failure: the reply did not fit in a datagram. The
                # `.com` servers do this for microsoft.com - thirteen NS plus
                # glue. Ask again over TCP, which is what TC is for.
                self._say(f"        {server} set TC, asking again over TCP")
                try:
                    return dnsproto.ask_tcp(server, name, TYPE_A, rd=False,
                                            timeout=self.timeout + 2)
                except DNSError as e:
                    errors.append(f"{server} truncated, TCP failed: {e}")
                    continue
            return reply
        raise DNSError("no server answered: " + "; ".join(errors))

    def _say(self, line):
        if self.trace:
            print(line)


# ------------------------------------------------------------------- harness
def dig_answer(name):
    """What the system resolver says, for comparison.

    `dig` is the reference when it is installed. It is not installed here, so
    we fall back to asking a public recursive resolver the same question the
    same way dig would - RD=1, one query, let somebody else do the walk. The
    point of the comparison is unchanged: our answer against a recursive
    resolver's answer.
    """
    if shutil.which("dig"):
        out = subprocess.run(["dig", "+short", name, "A"],
                             capture_output=True, text=True).stdout
        return [l for l in out.split() if l and l[0].isdigit()]
    try:
        reply = dnsproto.ask("8.8.8.8", name, TYPE_A, rd=True, timeout=5.0)
    except DNSError:
        return []
    return [r["rdata"] for r in reply.answer if r["type"] == TYPE_A]


def verify():
    failures = 0
    if not shutil.which("dig"):
        print("\n  note: dig is not installed - comparing against 8.8.8.8 "
              "(RD=1) instead.\n")

    for name, kind in VERIFY_NAMES:
        r = Resolver()
        try:
            addr, path = r.resolve(name)
        except NotImplementedError:
            print("Nothing implemented yet - write Resolver.resolve first.")
            return 1
        except Exception as e:
            print(f"  FAIL  {name:<22} your resolver raised {e!r}")
            failures += 1
            continue

        expected = dig_answer(name)
        if addr in expected:
            mark, note = "ok  ", ""
        elif kind == "cdn":
            mark, note = "ok  ", "  <- differs, but this name is CDN-hosted. Explain it."
        else:
            mark, note = "FAIL", "  <- should have matched"
            failures += 1
        print(f"  {mark}  {name:<22} you={addr:<16} "
              f"dig={','.join(expected) or '-':<32} hops={len(path)}{note}")

    print(f"\n  {len(VERIFY_NAMES) - failures}/{len(VERIFY_NAMES)} ok")
    return 1 if failures else 0


def main():
    p = argparse.ArgumentParser(description="an iterative DNS resolver")
    p.add_argument("name", nargs="*", default=["www.korea.ac.kr"],
                   help="one or more names to resolve")
    p.add_argument("--verify", action="store_true",
                   help="resolve VERIFY_NAMES and compare against dig")
    p.add_argument("--trace", action="store_true",
                   help="print the walk as it happens")
    p.add_argument("--pcap", metavar="PATH",
                   help="write every datagram to a pcapng (Task 2 Part A)")
    a = p.parse_args()

    if a.verify:
        sys.exit(verify())

    log = dnsproto.PacketLog() if a.pcap else None
    names = a.name if isinstance(a.name, list) else [a.name]

    for name in names:
        r = Resolver(log=log, trace=a.trace)
        addr, path = r.resolve(name)
        for i, server in enumerate(path, 1):
            print(f"  {i}. asked {server}")
        print(f"\n  {name} -> {addr}")
        print(f"  {r.queries} queries, {r.glue_misses} delegation(s) without "
              f"glue, {r.extra_lookups} extra lookup(s) to find a "
              f"nameserver's address\n")

    if a.pcap:
        dnsproto.write_pcapng(a.pcap, log)
        print(f"  {len(log)} datagrams written to {a.pcap}")


if __name__ == "__main__":
    main()
