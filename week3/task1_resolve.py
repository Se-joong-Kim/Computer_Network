#!/usr/bin/env python3
"""Week 3 · Task 1 — Build your own iterative resolver.

Textbook §2.4.2 - §2.4.3.

`dig +trace` walks root -> TLD -> authoritative for you. In this task you do
that walk yourself: start at a root server, read the delegation it returns,
ask the next server, and keep going until somebody answers authoritatively.

    python task1_resolve.py www.korea.ac.kr
    python task1_resolve.py www.adobe.com --trace   # the glue-less case (R3)
    python task1_resolve.py --verify                # check yourself against dig

How this implementation differs from the suggested one
------------------------------------------------------
The task says "shell out to `dig` for the transport, or use `dnspython`".
Neither exists on this machine - it is Windows, `dig` ships with BIND and is
not installed, and there is no `dns` module - so the DNS wire format is
implemented here directly on `socket` and `struct`: query builder, response
parser, name-compression decoder, EDNS0, and a TCP fallback. That is strictly
more work than the assignment asked for, and it has one real benefit beyond
portability: because every byte on the wire passes through this file, Task 2
can tap it and write a capture (see `task2_steering.py --capture`).

`task2_steering.py` imports DNSClient/RRType/dig_one from this module, so the
measurement in Task 2 rides on the resolver built here.

Pass condition
--------------
`--verify` resolves five names with your resolver and with `dig`, and the
addresses must agree. A name behind a CDN may legitimately return a different
address each time; for those we only require that you reached an answer.
"""
import argparse, random, shutil, socket, struct, subprocess, sys, time

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

# --------------------------------------------------------------- depth caps (R6)
# One counter is not enough. A malformed zone can burn you four different ways:
# a CNAME ping-pong, a delegation loop, a glue-less NS whose own NS is also
# glue-less, or servers that simply answer very slowly. So there is a cap on
# each, plus a wall clock over the whole thing.
MAX_QUERIES        = 80     # total UDP/TCP queries for one resolve()
MAX_DELEGATIONS    = 16     # delegation steps within one walk
MAX_CNAME_RESTARTS = 8      # CNAME restarts within one resolve()
MAX_NS_DEPTH       = 4      # nested resolution of a glue-less nameserver name
WALL_CLOCK_LIMIT   = 30.0   # seconds for one resolve()
MAX_CNAME_IN_MSG   = 16     # CNAME hops followed inside a single response

EDNS_UDP_SIZE = 1232        # DNS flag-day recommendation: 1280-byte IPv6 MTU
                            # minus IPv6+UDP headers. Without EDNS the root's
                            # .edu delegation comes back truncated at 493 bytes
                            # with TC=1; with it, 840 bytes and TC=0.


# =============================================================== DNS wire format
class RRType:
    A     = 1
    NS    = 2
    CNAME = 5
    SOA   = 6
    PTR   = 12
    AAAA  = 28
    OPT   = 41          # not a record - EDNS0 pseudo-RR, see strip_opt()

    _NAMES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
              15: "MX", 16: "TXT", 28: "AAAA", 41: "OPT", 43: "DS",
              46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 50: "NSEC3"}

    @classmethod
    def name(cls, code):
        return cls._NAMES.get(code, f"TYPE{code}")


class RCODE:
    NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED = range(6)

    _NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
              4: "NOTIMP", 5: "REFUSED"}

    @classmethod
    def name(cls, code):
        return cls._NAMES.get(code, f"RCODE{code}")


class DNSFormatError(Exception):
    """The bytes we got back are not a DNS message we can read."""


class Unreachable(Exception):
    """This server will not answer us. R4: move on to the next one."""

    def __init__(self, server, reason):
        super().__init__(f"{server}: {reason}")
        self.server, self.reason = server, reason


class ResolveError(Exception):
    """The walk failed for this name."""


MAX_NAME_WIRE = 255         # RFC 1035 §2.3.4
MAX_JUMPS     = 64


def normalise(name):
    """Lowercase, no trailing dot. The root zone is the empty string."""
    return name.rstrip(".").lower()


def encode_name(name):
    """A domain name as length-prefixed labels, terminated by the root label."""
    out = b""
    if name:
        for label in name.split("."):
            raw = label.encode("idna") if any(ord(c) > 127 for c in label) \
                else label.encode("ascii")
            if not 1 <= len(raw) <= 63:
                raise DNSFormatError(f"bad label {label!r}")
            out += bytes([len(raw)]) + raw
    return out + b"\x00"


def read_name(msg, off):
    """Decode a (possibly compressed) domain name.

    Returns (name, next_off), where `next_off` is the offset just past the name
    *in the record stream* - that is, just past the FIRST pointer if one was
    taken, not past wherever the pointer chain finally ended up. Getting that
    latch wrong is the classic way to corrupt every record after this one.
    """
    labels, jumps, wire_len = [], 0, 0
    next_off = None
    seen = set()                        # offsets of every length byte consumed
    while True:
        if off >= len(msg):
            raise DNSFormatError(f"name runs off the end of the message at {off}")
        length = msg[off]
        tag = length & 0xC0

        if tag == 0x00:                                 # 00xxxxxx: a literal label
            if length == 0:                             # root label - the name ends
                off += 1
                if next_off is None:
                    next_off = off
                break
            if off in seen:
                raise DNSFormatError("compression loop (revisited label)")
            seen.add(off)
            end = off + 1 + length
            if end > len(msg):
                raise DNSFormatError("label runs off the end of the message")
            wire_len += 1 + length
            if wire_len > MAX_NAME_WIRE:                # guard 1: the 255-byte cap
                raise DNSFormatError("name exceeds 255 bytes")
            labels.append(msg[off + 1:end])
            off = end

        elif tag == 0xC0:                               # 11xxxxxx: a pointer
            if off + 1 >= len(msg):
                raise DNSFormatError("truncated compression pointer")
            target = ((length & 0x3F) << 8) | msg[off + 1]
            if next_off is None:
                next_off = off + 2                      # only the FIRST pointer
            jumps += 1
            if jumps > MAX_JUMPS:                       # guard 2: a jump budget
                raise DNSFormatError("too many compression jumps")
            if target >= off:                           # guard 3: strictly backwards
                raise DNSFormatError(f"forward/self pointer {target} >= {off}")
            if target in seen:
                raise DNSFormatError("compression loop (pointer into visited label)")
            off = target

        else:                                           # 0x40/0x80 are reserved
            raise DNSFormatError(f"reserved label type 0x{tag:02x}")

    name = ".".join(l.decode("ascii", "backslashreplace") for l in labels).lower()
    return name, next_off


class RR:
    """One resource record."""

    __slots__ = ("name", "rtype", "rclass", "ttl", "data", "raw")

    def __init__(self, name, rtype, rclass, ttl, data, raw):
        self.name, self.rtype, self.rclass = name, rtype, rclass
        self.ttl, self.data, self.raw = ttl, data, raw

    def __repr__(self):
        return f"<{self.name} {RRType.name(self.rtype)} {self.data!r} ttl={self.ttl}>"


class Message:
    """A parsed DNS message."""

    def __init__(self, raw):
        self.raw = raw
        self.size = len(raw)
        if len(raw) < 12:
            raise DNSFormatError(f"message is only {len(raw)} bytes")
        (self.id, flags, qdcount, ancount,
         nscount, arcount) = struct.unpack("!HHHHHH", raw[:12])

        self.flags  = flags
        self.qr     = (flags >> 15) & 1
        self.opcode = (flags >> 11) & 0xF
        self.aa     = (flags >> 10) & 1
        self.tc     = (flags >> 9) & 1
        self.rd     = (flags >> 8) & 1
        self.ra     = (flags >> 7) & 1
        self.rcode  = flags & 0xF
        self.counts = (qdcount, ancount, nscount, arcount)

        off = 12
        self.questions = []
        for _ in range(qdcount):
            qname, off = read_name(raw, off)
            if off + 4 > len(raw):
                raise DNSFormatError("question section truncated")
            qtype, qclass = struct.unpack("!HH", raw[off:off + 4])
            off += 4
            self.questions.append((qname, qtype, qclass))

        self.answers    = self._records(raw, off, ancount)
        off = self._off
        self.authority  = self._records(raw, off, nscount)
        off = self._off
        self.additional = self._records(raw, off, arcount)

    def _records(self, raw, off, count):
        out = []
        for _ in range(count):
            name, off = read_name(raw, off)
            if off + 10 > len(raw):
                raise DNSFormatError("record header truncated")
            rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", raw[off:off + 10])
            off += 10
            if off + rdlength > len(raw):
                raise DNSFormatError("rdata runs off the end of the message")
            rdata = raw[off:off + rdlength]
            out.append(RR(name, rtype, rclass, ttl,
                          self._rdata(raw, off, rtype, rdlength, rdata), rdata))
            # The one rule you cannot break: advance by RDLENGTH, never by
            # however far the name decoder walked. A compressed name inside
            # rdata points backwards, and following the decoder's cursor would
            # desynchronise every record after this one.
            off += rdlength
        self._off = off
        return out

    @staticmethod
    def _rdata(raw, off, rtype, rdlength, rdata):
        try:
            if rtype == RRType.A and rdlength == 4:
                return socket.inet_ntoa(rdata)
            if rtype == RRType.AAAA and rdlength == 16:
                return socket.inet_ntop(socket.AF_INET6, rdata)
            if rtype in (RRType.NS, RRType.CNAME, RRType.PTR):
                return read_name(raw, off)[0]
            if rtype == RRType.SOA:
                mname, o = read_name(raw, off)
                rname, o = read_name(raw, o)
                serial, refresh, retry, expire, minimum = struct.unpack(
                    "!IIIII", raw[o:o + 20])
                return {"mname": mname, "rname": rname, "serial": serial,
                        "refresh": refresh, "retry": retry, "expire": expire,
                        "minimum": minimum}
        except (DNSFormatError, struct.error, OSError):
            pass
        return rdata

    def __repr__(self):
        q = self.questions[0][0] if self.questions else "?"
        return (f"<Message {q} rcode={RCODE.name(self.rcode)} aa={self.aa} "
                f"tc={self.tc} an={self.counts[1]} ns={self.counts[2]} "
                f"ar={self.counts[3]} {self.size}B>")


def strip_opt(records):
    """Drop the EDNS0 pseudo-RR.

    OPT is not a resource record - its owner name must be root, its CLASS field
    is really the requestor's UDP payload size and its TTL field is really an
    extended rcode plus flags. Leaving it in the additional section would make a
    glue search trip over it.
    """
    return [rr for rr in records if rr.rtype != RRType.OPT]


def build_query(qname, qtype=RRType.A, rd=False, edns=True, txid=None):
    """One DNS query message. Returns (wire_bytes, transaction_id)."""
    if txid is None:
        txid = random.SystemRandom().randrange(1, 65536)
    flags = 0x0100 if rd else 0x0000            # RD is bit 8; R2 wants it clear
    arcount = 1 if edns else 0
    wire = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, arcount)
    wire += encode_name(qname) + struct.pack("!HH", qtype, 1)
    if edns:
        # name=root, TYPE=OPT, CLASS=our UDP buffer size, TTL=0, RDLENGTH=0
        wire += b"\x00" + struct.pack("!HHIH", RRType.OPT, EDNS_UDP_SIZE, 0, 0)
    return wire, txid


# ==================================================================== transport
class DNSClient:
    """Sends one question to one server. Never recurses, never decides anything.

    `tap`, if given, is called with every packet in both directions:

        tap(direction, peer_ip, peer_port, local_port, raw, t_unix, note)

    with direction "tx" or "rx". Task 2 hangs a pcapng writer off it.
    """

    def __init__(self, timeout=3.0, tries=2, tap=None):
        self.timeout, self.tries, self.tap = timeout, tries, tap
        self.stats = {"udp": 0, "tcp": 0, "timeouts": 0, "truncated": 0,
                      "refused": 0, "formerr": 0}

    # ---------------------------------------------------------------- internals
    def _tap(self, direction, peer, lport, raw, note):
        if self.tap:
            self.tap(direction, peer, 53, lport, raw, time.time(), note)

    def _udp(self, server, wire, txid, qname, qtype, note):
        """One UDP exchange. Returns a Message, or None if nothing came back."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(self.timeout)
        try:
            # connect() rather than sendto(): the kernel then drops replies that
            # did not come from this server, and on Windows an ICMP port
            # unreachable surfaces as ConnectionResetError on the next recv()
            # instead of costing us the full timeout.
            s.connect((server, 53))
            lport = s.getsockname()[1]
            deadline = time.monotonic() + self.timeout
            self.stats["udp"] += 1
            s.send(wire)
            self._tap("tx", server, lport, wire, note)
            while True:
                if time.monotonic() > deadline:
                    return None
                s.settimeout(max(0.05, deadline - time.monotonic()))
                data = s.recv(65535)
                self._tap("rx", server, lport, data, note)
                try:
                    msg = Message(data)
                except DNSFormatError:
                    continue                    # not parseable - keep listening
                if self._matches(msg, txid, qname, qtype):
                    return msg
                # Wrong transaction id or wrong question: someone else's packet
                # or an off-path spoof attempt. Ignore it and keep waiting.
        except socket.timeout:
            self.stats["timeouts"] += 1
            return None
        except (TimeoutError, ConnectionResetError, ConnectionRefusedError):
            return None
        except OSError:
            return None
        finally:
            s.close()

    def _tcp(self, server, wire, txid, qname, qtype, note):
        """Retry over TCP/53 - the backstop when a response does not fit in UDP."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect((server, 53))
            lport = s.getsockname()[1]
            self.stats["tcp"] += 1
            framed = struct.pack("!H", len(wire)) + wire
            s.sendall(framed)
            self._tap("tx", server, lport, wire, note + " [tcp]")
            head = self._recvn(s, 2)
            if head is None:
                return None
            (length,) = struct.unpack("!H", head)
            data = self._recvn(s, length)
            if data is None:
                return None
            self._tap("rx", server, lport, data, note + " [tcp]")
            msg = Message(data)
            return msg if self._matches(msg, txid, qname, qtype) else None
        except (socket.timeout, TimeoutError, ConnectionResetError,
                ConnectionRefusedError, OSError, DNSFormatError):
            return None
        finally:
            s.close()

    @staticmethod
    def _recvn(sock, n):
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    @staticmethod
    def _matches(msg, txid, qname, qtype):
        """Accept a response only if it answers the question we actually asked."""
        if msg.qr != 1 or msg.id != txid or len(msg.questions) != 1:
            return False
        rname, rtype, rclass = msg.questions[0]
        return rname == normalise(qname) and rtype == qtype and rclass == 1

    # ------------------------------------------------------------------- public
    def query(self, server, qname, qtype=RRType.A, rd=False, note=""):
        """Ask one server one question. Raises Unreachable if it will not answer.

        The ladder below is not defensive padding - every rung is a failure this
        machine actually saw while the resolver was being written:

          1. UDP with EDNS0(1232)              - the normal path
          2. no reply at all -> UDP without the OPT RR, in case a middlebox
             is dropping EDNS
          3. FORMERR -> UDP without the OPT RR, for servers that dislike EDNS
          4. TC=1 -> TCP/53, for a delegation that genuinely will not fit
        """
        qname = normalise(qname)
        for edns in (True, False):
            msg = None
            for _ in range(self.tries):
                wire, txid = build_query(qname, qtype, rd=rd, edns=edns)
                msg = self._udp(server, wire, txid, qname, qtype, note)
                if msg is not None:
                    break
            if msg is None:
                continue                        # rung 2: retry without EDNS
            if msg.rcode == RCODE.FORMERR and edns:
                self.stats["formerr"] += 1
                continue                        # rung 3: retry without EDNS
            if msg.tc:                          # rung 4: TCP
                self.stats["truncated"] += 1
                wire, txid = build_query(qname, qtype, rd=rd, edns=edns)
                tcp_msg = self._tcp(server, wire, txid, qname, qtype, note)
                if tcp_msg is not None:
                    return tcp_msg
            return msg
        raise Unreachable(server, "timeout")


# ===================================================================== the walk
_BOGON = [("0.0.0.0", 8), ("10.0.0.0", 8), ("127.0.0.0", 8), ("169.254.0.0", 16),
          ("172.16.0.0", 12), ("192.168.0.0", 16), ("224.0.0.0", 4),
          ("240.0.0.0", 4)]


def is_bogon(ip):
    """Reject glue pointing at private or reserved space.

    A misconfigured (or hostile) zone that hands out 192.168.x.x as a
    nameserver address would send our queries to whatever happens to sit at
    that address on the local network.
    """
    try:
        v = struct.unpack("!I", socket.inet_aton(ip))[0]
    except OSError:
        return True
    for net, bits in _BOGON:
        n = struct.unpack("!I", socket.inet_aton(net))[0]
        mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
        if v & mask == n & mask:
            return True
    return False


def in_zone(name, zone):
    """Is `name` inside `zone`? The root zone ("") contains everything."""
    return zone == "" or name == zone or name.endswith("." + zone)


def labels(name):
    return 0 if name == "" else name.count(".") + 1


class _CNAMERestart(Exception):
    def __init__(self, target):
        super().__init__(target)
        self.target = target


class Budget:
    """Shared by the top-level walk and every nested nameserver walk (R6).

    Sharing it is the point: a zone whose glue-less nameserver has a glue-less
    nameserver of its own cannot escape the cap by recursing, because each
    nested walk spends from the same pool.
    """

    def __init__(self):
        self.queries = MAX_QUERIES
        self.deadline = time.monotonic() + WALL_CLOCK_LIMIT

    def spend(self):
        self.queries -= 1
        if self.queries < 0:
            raise ResolveError("query budget exhausted")
        if time.monotonic() > self.deadline:
            raise ResolveError("wall-clock budget exhausted")


class Resolver:
    """An iterative resolver.

    The whole point is that we never ask a server to recurse for us (RD stays
    0). We ask one server, it says "not mine, ask over there", and we go there.

        resolve(name) -> (address, path)
            address : the A record we ended up with, as a string
            path    : the servers we asked, in order, so we can show our work

    Servers that did not answer are in `path` too, annotated - they were asked,
    and leaving them out would hide R4 doing its job. `self.last_trace` carries
    the structured version of the same walk (query name, response kind,
    delegated zone, byte count, transaction id) for observation.md.
    """

    def __init__(self, client=None, verbose=False):
        self.client = client or DNSClient()
        self.verbose = verbose
        self.last_trace = []

    # ------------------------------------------------------------------ public
    def resolve(self, name):
        name = normalise(name)
        budget, path = Budget(), []
        self.last_trace = []
        seen_cnames = {name}
        current, restarts = name, 0

        while True:
            try:
                addrs = self._walk(current, path, budget, depth=0)
                return addrs[0], path
            except _CNAMERestart as r:                       # R5
                restarts += 1
                if restarts > MAX_CNAME_RESTARTS:
                    raise ResolveError(f"CNAME chain too long at {r.target}")
                if r.target in seen_cnames:
                    raise ResolveError(f"CNAME loop at {r.target}")
                seen_cnames.add(r.target)
                self._note(kind="cname-restart", qname=current, target=r.target)
                current = r.target          # and start again from the roots

    # ----------------------------------------------------------------- the walk
    def _walk(self, qname, path, budget, depth):
        if depth > MAX_NS_DEPTH:
            raise ResolveError("nameserver-resolution depth cap hit")

        servers = list(ROOT_SERVERS)         # R2: every walk starts at a root
        zone = ""                            # ...which is authoritative for "."

        for _ in range(MAX_DELEGATIONS):
            msg, asked = self._ask_any(servers, qname, path, budget, zone)
            kind, payload = self._classify(msg, qname)
            self._note(kind=kind, qname=qname, server=asked, zone=zone,
                       size=msg.size, txid=msg.id, aa=msg.aa,
                       counts=msg.counts, depth=depth)

            if kind == "answer":
                return payload
            if kind == "cname":
                raise _CNAMERestart(payload)                 # R5
            if kind == "nxdomain":
                raise ResolveError(f"NXDOMAIN for {qname}")
            if kind == "nodata":
                raise ResolveError(f"{qname} exists but has no A record")
            if kind != "delegation":
                raise ResolveError(f"{asked} gave us nothing usable for {qname}")

            new_zone, ns_names, glue = payload
            if not self._is_progress(new_zone, zone, qname):
                raise ResolveError(
                    f"delegation went sideways: {zone or '.'!r} -> {new_zone!r}")
            zone = new_zone
            servers = self._servers_for(zone, ns_names, glue, path, budget, depth)

        raise ResolveError(f"delegation cap hit for {qname}")

    def _ask_any(self, servers, qname, path, budget, zone):
        """Try each server in turn until one answers. R4."""
        last = None
        for ip in servers:
            budget.spend()
            try:
                msg = self.client.query(ip, qname, RRType.A, rd=False,
                                        note=f"{qname} @ {zone or '.'}")
                path.append(ip)
                return msg, ip
            except Unreachable as e:
                path.append(f"{ip} ({e.reason})")   # we did ask it - record that
                self._note(kind="unreachable", qname=qname, server=ip,
                           zone=zone, detail=e.reason)
                last = e
        raise ResolveError(f"no server answered for {qname}"
                           + (f" (last: {last})" if last else ""))

    # ------------------------------------------------------------- the decision
    def _classify(self, msg, qname):
        """answer / cname / delegation / nodata / nxdomain.

        Order matters, and the trap is step 4: NSCOUNT > 0 does not mean
        "delegation". A NODATA reply also fills the authority section - with an
        SOA. Telling an SOA-only authority section from an NS one is the whole
        trick.
        """
        if msg.rcode == RCODE.NXDOMAIN:
            return "nxdomain", None
        if msg.rcode in (RCODE.SERVFAIL, RCODE.REFUSED, RCODE.NOTIMP):
            # Not a statement about the name - a statement about this server.
            # Raise so that R4 moves us to the next one.
            raise Unreachable("server", RCODE.name(msg.rcode).lower())
        if msg.rcode != RCODE.NOERROR:
            return "error", msg.rcode

        addrs, cname = self._follow_in_message(msg, qname)
        if addrs:
            return "answer", addrs
        if cname:
            return "cname", cname

        authority = strip_opt(msg.authority)
        if any(rr.rtype == RRType.SOA for rr in authority):
            return "nodata", None

        ns = [rr for rr in authority if rr.rtype == RRType.NS]
        if ns:
            zone = ns[0].name
            names = sorted({rr.data for rr in ns if isinstance(rr.data, str)})
            wanted = set(names)
            glue = {}
            for rr in strip_opt(msg.additional):
                if rr.rtype == RRType.A and rr.name in wanted:
                    if not is_bogon(rr.data):
                        glue.setdefault(rr.name, []).append(rr.data)
            return "delegation", (zone, names, glue)

        return "empty", None

    @staticmethod
    def _follow_in_message(msg, qname):
        """Walk any CNAME chain contained in this one response.

        Authoritative servers routinely return `CNAME` plus the target's `A` in
        the same answer section. Following that in-message saves a restart; only
        when the chain walks off the end of the message do we have to go back to
        the roots with the new name.

        Returns (addresses, cname_target_to_restart_with).
        """
        by_name = {}
        for rr in msg.answers:
            if rr.rclass == 1:
                by_name.setdefault(rr.name, []).append(rr)

        target, seen = normalise(qname), set()
        while target not in seen and len(seen) <= MAX_CNAME_IN_MSG:
            seen.add(target)
            rrs = by_name.get(target, [])
            addrs = [rr.data for rr in rrs
                     if rr.rtype == RRType.A and not is_bogon(rr.data)]
            if addrs:
                return addrs, None
            cnames = [rr.data for rr in rrs if rr.rtype == RRType.CNAME]
            if not cnames:
                break
            target = normalise(cnames[0])

        if target != normalise(qname):
            return [], target           # the chain left this message
        return [], None                 # nothing here for the name we asked

    @staticmethod
    def _is_progress(new_zone, cur_zone, qname):
        """Accept a delegation only if it moves us strictly down towards qname.

        Without this a broken - or hostile - server can bounce us back to the
        root, or sideways to an unrelated zone, forever.
        """
        return in_zone(qname, new_zone) and labels(new_zone) > labels(cur_zone)

    # ------------------------------------------------------------- R3: the glue
    def _servers_for(self, zone, ns_names, glue, path, budget, depth):
        """Turn a delegation's NS records into addresses we can actually ask."""
        # Glue the parent is authoritative for (in-bailiwick) first: it is the
        # only glue the parent had any business publishing.
        inb  = [ip for n in ns_names if in_zone(n, zone) for ip in glue.get(n, [])]
        outb = [ip for n in ns_names if not in_zone(n, zone) for ip in glue.get(n, [])]
        if inb or outb:
            return inb + outb

        # R3. No glue at all, so before we can ask this zone's nameservers
        # anything we have to resolve one of their names - which is another full
        # walk from the roots. This is where the recursion in "recursive
        # resolver" actually comes from.
        self._note(kind="glueless", qname=zone, zone=zone,
                   detail=",".join(ns_names), depth=depth)
        for ns in ns_names:
            # Skip a nameserver that lives inside the very zone being delegated:
            # finding its address would mean asking the servers we are trying to
            # find. Without glue that zone is simply broken - try the next name.
            if in_zone(ns, zone):
                self._note(kind="glueless-skip", qname=ns, zone=zone,
                           detail="in-bailiwick but no glue - circular")
                continue
            try:
                addrs = self._walk(ns, path, budget, depth + 1)
            except (ResolveError, _CNAMERestart) as e:
                self._note(kind="glueless-fail", qname=ns, zone=zone,
                           detail=str(e))
                continue
            if addrs:
                self._note(kind="glueless-ok", qname=ns, zone=zone,
                           detail=addrs[0], depth=depth)
                return addrs
        raise ResolveError(f"{zone}: no glue, and no nameserver name resolved")

    # ----------------------------------------------------------------- tracing
    def _note(self, **kw):
        self.last_trace.append(kw)
        if self.verbose:
            bits = " ".join(f"{k}={v}" for k, v in kw.items() if v not in (None, ""))
            print(f"    · {bits}", file=sys.stderr)


# ------------------------------------------------------------------- harness
def dig_answer(name):
    """What the system resolver says, for comparison.

    `dig +short` puts the question to the recursive resolver in resolv.conf.
    `dig` is not part of a Windows install, so when it is missing we fall back
    to socket.getaddrinfo(), which goes through the OS stub resolver and
    therefore asks *the same* recursive resolver dig would have asked. The
    comparison being made is unchanged - "my iterative walk" against "the
    system's recursive answer" - only the transport differs.

    Two caveats, both repeated in out/observation.md: getaddrinfo may be served
    out of the Windows DNS Client cache, and it gives us the A RRset without the
    TTL or the CNAME chain.
    """
    if shutil.which("dig"):
        out = subprocess.run(["dig", "+short", name, "A"],
                             capture_output=True, text=True).stdout
        return [l for l in out.split() if l and l[0].isdigit()]

    try:
        infos = socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    seen, addrs = set(), []
    for *_, sockaddr in infos:
        ip = sockaddr[0]
        if ip not in seen:
            seen.add(ip)
            addrs.append(ip)
    return addrs


def verify():
    r, failures = Resolver(), 0
    for name, kind in VERIFY_NAMES:
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
            note = ""
        elif kind == "cdn":
            note = "  <- differs, but this name is CDN-hosted. Explain it."
        else:
            note = "  <- should have matched"
            failures += 1
        print(f"  {'FAIL' if note.endswith('matched') else 'ok  '}  {name:<22} "
              f"you={addr:<16} dig={','.join(expected) or '-'}   "
              f"hops={len(path)}{note}")
    print(f"\n  {len(VERIFY_NAMES) - failures}/{len(VERIFY_NAMES)} ok")
    return 1 if failures else 0


def main():
    p = argparse.ArgumentParser()
    p.add_argument("name", nargs="?", default="www.korea.ac.kr")
    p.add_argument("--verify", action="store_true")
    p.add_argument("--trace", action="store_true",
                   help="show every delegation step, not just the servers asked")
    a = p.parse_args()

    if a.verify:
        sys.exit(verify())

    r = Resolver(verbose=a.trace)
    addr, path = r.resolve(a.name)
    for i, server in enumerate(path, 1):
        print(f"  {i}. asked {server}")
    print(f"\n  {a.name} -> {addr}")

    if a.trace:
        q = r.client.stats
        print(f"\n  {q['udp']} UDP queries, {q['tcp']} TCP retries, "
              f"{q['truncated']} truncated, {q['timeouts']} timeouts")


if __name__ == "__main__":
    main()
