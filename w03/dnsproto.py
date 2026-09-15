#!/usr/bin/env python3
"""Week 3 · a DNS message on the wire, in plain Python.

`dig` is not installed here and neither is dnspython, so the transport for
Tasks 1 and 2 is built from `socket` and `struct`. That turns out to be the
more honest version of the exercise anyway: nothing between the delegation and
the code that reads it.

What lives here:

    build_query / parse      RFC 1035 message format, including the 0xC0
                             compression pointers - without those you cannot
                             read a delegation, because the NS names in the
                             authority section are almost always compressed
    ask                      one UDP question to one server, no retry logic
                             beyond a timeout, returning the raw bytes too
    PacketLog / write_pcapng the raw bytes written out as a pcapng, for Task 2
                             Part A

A note on the pcapng, because it matters for how Task 2 is read: the DNS
payload in it is the real thing, byte for byte as it left and entered this
machine. The Ethernet/IP/UDP framing around it is *reconstructed* - a program
in userspace hands the kernel a payload and a destination and never sees the
headers the kernel builds. So this is a log of real DNS traffic, not a capture
taken off the interface. Task 2's report says so.
"""
import os
import random
import socket
import struct
import time

# ------------------------------------------------------------------ constants
TYPE_A, TYPE_NS, TYPE_CNAME, TYPE_SOA = 1, 2, 5, 6
TYPE_PTR, TYPE_MX, TYPE_TXT, TYPE_AAAA = 12, 15, 16, 28

TYPE_NAME = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
             15: "MX", 16: "TXT", 28: "AAAA", 41: "OPT", 43: "DS",
             46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 50: "NSEC3"}

RCODE_NAME = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
              4: "NOTIMP", 5: "REFUSED"}


class DNSError(Exception):
    """A server did not answer, or answered with something unusable."""


# -------------------------------------------------------------------- parsing
def encode_name(name):
    """A domain name as length-prefixed labels, terminated by a zero byte."""
    out = b""
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        raw = label.encode("idna") if any(ord(c) > 127 for c in label) \
            else label.encode("ascii")
        if len(raw) > 63:
            raise DNSError(f"label too long: {label}")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def decode_name(msg, offset):
    """Read a name at `offset`, following compression pointers.

    Returns (name, offset just past the name *in this position*) - which is
    not the same as where the name's bytes ended if we followed a pointer,
    hence the `jumped` bookkeeping.
    """
    labels, jumped, end, seen = [], False, offset, set()
    while True:
        if offset >= len(msg):
            raise DNSError("name runs past the end of the message")
        length = msg[offset]
        if length & 0xC0 == 0xC0:                       # compression pointer
            if offset + 1 >= len(msg):
                raise DNSError("truncated compression pointer")
            target = ((length & 0x3F) << 8) | msg[offset + 1]
            if target in seen:
                raise DNSError("compression pointer loop")
            seen.add(target)
            if not jumped:
                end = offset + 2
                jumped = True
            offset = target
            continue
        offset += 1
        if length == 0:
            if not jumped:
                end = offset
            break
        labels.append(msg[offset:offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels), end


def _parse_rdata(msg, rtype, offset, rdlength):
    """The part of a record whose shape depends on its type."""
    if rtype == TYPE_A and rdlength == 4:
        return socket.inet_ntoa(msg[offset:offset + 4])
    if rtype == TYPE_AAAA and rdlength == 16:
        return socket.inet_ntop(socket.AF_INET6, msg[offset:offset + 16])
    if rtype in (TYPE_NS, TYPE_CNAME, TYPE_PTR):
        return decode_name(msg, offset)[0]
    if rtype == TYPE_SOA:
        mname, o = decode_name(msg, offset)
        rname, o = decode_name(msg, o)
        serial, refresh, retry, expire, minimum = struct.unpack(
            "!IIIII", msg[o:o + 20])
        return {"mname": mname, "rname": rname, "serial": serial,
                "refresh": refresh, "retry": retry, "expire": expire,
                "minimum": minimum}
    if rtype == TYPE_MX:
        pref = struct.unpack("!H", msg[offset:offset + 2])[0]
        return {"preference": pref, "exchange": decode_name(msg, offset + 2)[0]}
    if rtype == TYPE_TXT:
        parts, o = [], offset
        while o < offset + rdlength:
            n = msg[o]
            parts.append(msg[o + 1:o + 1 + n].decode("utf-8", "replace"))
            o += 1 + n
        return "".join(parts)
    return msg[offset:offset + rdlength].hex()


class Message:
    """A parsed DNS message. The same object shape for a query and a reply."""

    def __init__(self, raw):
        self.raw = raw
        if len(raw) < 12:
            raise DNSError(f"message too short: {len(raw)} bytes")
        (self.id, flags, qdcount, ancount,
         nscount, arcount) = struct.unpack("!HHHHHH", raw[:12])

        self.qr = bool(flags >> 15 & 1)
        self.opcode = flags >> 11 & 0xF
        self.aa = bool(flags >> 10 & 1)       # authoritative answer
        self.tc = bool(flags >> 9 & 1)        # truncated - retry over TCP
        self.rd = bool(flags >> 8 & 1)        # recursion desired
        self.ra = bool(flags >> 7 & 1)        # recursion available
        self.rcode = flags & 0xF

        offset = 12
        self.question = []
        for _ in range(qdcount):
            qname, offset = decode_name(raw, offset)
            qtype, qclass = struct.unpack("!HH", raw[offset:offset + 4])
            offset += 4
            self.question.append({"name": qname, "type": qtype,
                                  "class": qclass})

        self.answer, self.authority, self.additional = [], [], []
        for section, count in ((self.answer, ancount),
                               (self.authority, nscount),
                               (self.additional, arcount)):
            for _ in range(count):
                rec, offset = self._read_record(raw, offset)
                section.append(rec)

    @staticmethod
    def _read_record(msg, offset):
        name, offset = decode_name(msg, offset)
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH",
                                                     msg[offset:offset + 10])
        offset += 10
        rdata = _parse_rdata(msg, rtype, offset, rdlength)
        return ({"name": name, "type": rtype,
                 "type_name": TYPE_NAME.get(rtype, str(rtype)),
                 "class": rclass, "ttl": ttl, "rdata": rdata}, offset + rdlength)

    # -- the questions the resolver actually asks of a reply ------------------
    @property
    def qname(self):
        return self.question[0]["name"] if self.question else ""

    @property
    def rcode_name(self):
        return RCODE_NAME.get(self.rcode, f"RCODE{self.rcode}")

    def records(self, section, rtype, name=None):
        """Records of one type from one section, optionally for one name."""
        return [r for r in getattr(self, section)
                if r["type"] == rtype
                and (name is None or r["name"].lower() == name.lower().rstrip("."))]

    def is_delegation(self):
        """No answer, but NS records pointing somewhere else. §2.4.2.

        This is the shape that makes the iterative walk possible: the server
        is saying "not mine, and here is who to ask next".
        """
        return not self.answer and bool(self.records("authority", TYPE_NS))

    def is_answer(self):
        return bool(self.answer)

    def __repr__(self):
        return (f"<Message id=0x{self.id:04x} {self.rcode_name} "
                f"{'AA ' if self.aa else ''}qname={self.qname!r} "
                f"an={len(self.answer)} ns={len(self.authority)} "
                f"ar={len(self.additional)}>")


def build_query(name, qtype=TYPE_A, rd=False, txid=None, udp_payload=4096):
    """A query message. `rd=False` is the whole point of Task 1.

    `udp_payload` adds an EDNS0 OPT record (RFC 6891) advertising how large a
    UDP reply we can take. Without it the limit is 512 bytes, and the `.com`
    servers cannot fit the microsoft.com delegation - thirteen nameservers plus
    their glue - into that, so they set TC and we would have to retry over TCP
    for every single com name. Pass 0 to ask the 512-byte way.
    """
    txid = random.randint(0, 0xFFFF) if txid is None else txid
    flags = 0x0100 if rd else 0x0000
    arcount = 1 if udp_payload else 0
    header = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, arcount)
    body = encode_name(name) + struct.pack("!HH", qtype, 1)
    if udp_payload:                      # OPT: root name, type 41, class=size
        body += b"\x00" + struct.pack("!HHIH", 41, udp_payload, 0, 0)
    return header + body, txid


# ------------------------------------------------------------------ transport
def ask(server, name, qtype=TYPE_A, rd=False, timeout=3.0, log=None,
        udp_payload=4096):
    """Send one question to one server over UDP and parse what comes back.

    Raises DNSError on timeout, on a reply that is not ours, or on a reply we
    cannot parse. The caller decides what to do about it - for the resolver
    that means trying the next server in the delegation (R4).
    """
    request, txid = build_query(name, qtype, rd, udp_payload=udp_payload)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.connect((server, 53))
        src_ip, src_port = sock.getsockname()
        sent_at = time.time()
        sock.send(request)
        if log is not None:
            log.add(sent_at, src_ip, src_port, server, 53, request)

        while True:                       # ignore replies with a stale txid
            reply = sock.recv(4096)
            got_at = time.time()
            if len(reply) >= 2 and struct.unpack("!H", reply[:2])[0] == txid:
                break
        if log is not None:
            log.add(got_at, server, 53, src_ip, src_port, reply)
    except socket.timeout:
        raise DNSError(f"{server} did not answer in {timeout}s")
    except OSError as e:
        raise DNSError(f"{server} unreachable: {e}")
    finally:
        sock.close()

    msg = Message(reply)
    msg.elapsed_ms = (got_at - sent_at) * 1000
    msg.server = server
    msg.transport = "udp"
    return msg


def ask_tcp(server, name, qtype=TYPE_A, rd=False, timeout=5.0):
    """The same question over TCP, for a reply that did not fit in a datagram.

    A truncated reply (TC=1) is not an error and not a dead server - it is the
    server saying "this does not fit, come back on TCP". DNS over TCP is the
    same message with a two-byte length in front of it.

    These do not go into the packet log: the log writes UDP datagrams, and
    inventing TCP segments and a handshake that this process never saw would
    make the pcapng a fiction rather than a record.
    """
    request, txid = build_query(name, qtype, rd, udp_payload=0)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((server, 53))
        sock.sendall(struct.pack("!H", len(request)) + request)

        header = _recv_exactly(sock, 2)
        reply = _recv_exactly(sock, struct.unpack("!H", header)[0])
    except (socket.timeout, OSError) as e:
        raise DNSError(f"{server} over TCP: {e}")
    finally:
        sock.close()

    msg = Message(reply)
    if msg.id != txid:
        raise DNSError(f"{server} over TCP replied to a different query")
    msg.server = server
    msg.transport = "tcp"
    return msg


def _recv_exactly(sock, count):
    chunks, got = [], 0
    while got < count:
        chunk = sock.recv(count - got)
        if not chunk:
            raise DNSError("connection closed mid-message")
        chunks.append(chunk)
        got += len(chunk)
    return b"".join(chunks)


# -------------------------------------------------------------------- pcapng
class PacketLog:
    """Every DNS datagram this process sent or received, with its timestamp.

    Task 2 Part A wants a file it can point at packet numbers in. The payloads
    here are the real bytes; see the module docstring for what is and is not
    reconstructed.
    """

    def __init__(self):
        self.packets = []      # (ts, src_ip, src_port, dst_ip, dst_port, data)

    def add(self, ts, src_ip, src_port, dst_ip, dst_port, data):
        self.packets.append((ts, src_ip, src_port, dst_ip, dst_port, data))

    def __len__(self):
        return len(self.packets)

    def summary(self):
        """(packet number, direction, parsed message) for each datagram.

        Packet numbers are 1-based so they line up with what Wireshark shows.
        """
        out = []
        for i, (ts, src, sport, dst, dport, data) in enumerate(self.packets, 1):
            try:
                msg = Message(data)
            except DNSError:
                msg = None
            out.append({"no": i, "ts": ts, "src": src, "dst": dst,
                        "sport": sport, "dport": dport,
                        "bytes": len(data), "msg": msg,
                        "dir": "query" if dport == 53 else "response"})
        return out


def _checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ipv4_udp_frame(src_ip, src_port, dst_ip, dst_port, payload, ident):
    """Rebuild the IPv4 + UDP headers a datagram this size would have carried."""
    udp_len = 8 + len(payload)
    src, dst = socket.inet_aton(src_ip), socket.inet_aton(dst_ip)

    udp = struct.pack("!HHHH", src_port, dst_port, udp_len, 0) + payload
    pseudo = src + dst + struct.pack("!BBH", 0, 17, udp_len)
    udp_ck = _checksum(pseudo + udp) or 0xFFFF
    udp = struct.pack("!HHHH", src_port, dst_port, udp_len, udp_ck) + payload

    total_len = 20 + udp_len
    ip = struct.pack("!BBHHHBBH", 0x45, 0, total_len, ident & 0xFFFF,
                     0x4000, 64, 17, 0) + src + dst
    ip = ip[:10] + struct.pack("!H", _checksum(ip)) + ip[12:]
    return ip + udp


def _block(block_type, body):
    """A pcapng block: type, length, body padded to 4 bytes, length again."""
    pad = (-len(body)) % 4
    total = 12 + len(body) + pad
    return (struct.pack("<II", block_type, total) + body + b"\x00" * pad
            + struct.pack("<I", total))


def write_pcapng(path, log, comment="DNS traffic logged by the resolver"):
    """Write the log as a pcapng of Raw-IP packets (linktype 101)."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    def option(code, value):
        if isinstance(value, str):
            value = value.encode("utf-8")
        return (struct.pack("<HH", code, len(value)) + value
                + b"\x00" * ((-len(value)) % 4))

    end = struct.pack("<HH", 0, 0)

    shb_body = (struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
                + option(1, comment)                    # opt_comment
                + option(4, "task1_resolve.py (dnsproto.PacketLog)")  # userappl
                + end)
    idb_body = (struct.pack("<HHI", 101, 0, 65535)      # LINKTYPE_RAW
                + option(2, "resolver") + option(9, b"\x06")   # microseconds
                + end)

    blocks = [_block(0x0A0D0D0A, shb_body), _block(0x00000001, idb_body)]
    for i, (ts, src, sport, dst, dport, data) in enumerate(log.packets):
        frame = _ipv4_udp_frame(src, sport, dst, dport, data, i + 1)
        us = int(round(ts * 1_000_000))
        epb = (struct.pack("<IIIII", 0, us >> 32, us & 0xFFFFFFFF,
                           len(frame), len(frame))
               + frame + b"\x00" * ((-len(frame)) % 4))
        blocks.append(_block(0x00000006, epb))

    with open(path, "wb") as fh:
        fh.write(b"".join(blocks))
    return path


def read_pcapng(path):
    """Read back a pcapng written by `write_pcapng`.

    Task 2 Part A asks for packet numbers and byte counts, and they should come
    out of the file rather than out of the program's memory - if the file does
    not parse, the answers built from it are worth nothing.

    Handles what we write: little-endian, one Raw-IP interface, EPBs.
    """
    with open(path, "rb") as fh:
        data = fh.read()

    packets, offset, number = [], 0, 0
    while offset + 12 <= len(data):
        block_type, total = struct.unpack("<II", data[offset:offset + 8])
        if total < 12 or offset + total > len(data):
            raise DNSError(f"bad block at offset {offset}")
        if block_type == 0x00000006:                              # EPB
            body = data[offset + 8:offset + total - 4]
            _, ts_hi, ts_lo, caplen, _ = struct.unpack("<IIIII", body[:20])
            frame = body[20:20 + caplen]
            ihl = (frame[0] & 0x0F) * 4
            src = socket.inet_ntoa(frame[12:16])
            dst = socket.inet_ntoa(frame[16:20])
            sport, dport = struct.unpack("!HH", frame[ihl:ihl + 4])
            payload = frame[ihl + 8:]
            number += 1
            packets.append({
                "no": number, "ts": ((ts_hi << 32) | ts_lo) / 1_000_000,
                "src": src, "dst": dst, "sport": sport, "dport": dport,
                "dns_bytes": len(payload), "frame_bytes": len(frame),
                "dir": "query" if dport == 53 else "response",
                "msg": Message(payload),
            })
        offset += total
    return packets
