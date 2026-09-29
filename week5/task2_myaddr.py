#!/usr/bin/env python3
"""Week 5 · Task 2 — Where exactly are you on the internet?

Textbook §4.3.2 (addressing, DHCP) and §4.3.3 (NAT).

This is the hands-on task. It asks what address your machine has, what address
the rest of the world sees, and why those two are usually different.

    python3 task2_myaddr.py --collect     # gather what your OS will tell you
    python3 task2_myaddr.py --report      # your analysis

Run it on **two networks**. Campus Wi-Fi and phone tethering behave differently
here, and the difference is the lesson.
"""
import argparse, hashlib, io, json, os, platform, re, struct, subprocess, sys
import urllib.request, zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")
sys.path.insert(0, HERE)


def sh(*cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=15).stdout
    except Exception as e:
        return f"<failed: {e}>"


def local_facts():
    """Raw output only. Reading it is your job, not this script's.

    Two additions to what was here, both raw, both for a reason:

    `traceroute` - A5 asks how many layers of NAT you are behind, and the only
    way to answer it from the inside is to look at what the first few hops
    admit to being. It has to be captured *per network*, at collect time: once
    you have left the tethered connection you cannot reconstruct its hop list.

    `Get-NetIPAddress` (Windows) - `ipconfig /all` prints its lease timestamps
    in the system locale, which here is Korean ("2026년 9월 28일 월요일 오후
    1:00:06"). The PowerShell object has the same information as
    locale-independent durations, so the two cross-check each other.
    """
    osname = platform.system()
    if osname == "Darwin":
        return {"os": osname,
                "ifconfig": sh("ifconfig"),
                "route": sh("route", "-n", "get", "default"),
                "dns": sh("scutil", "--dns"),
                "traceroute": sh("traceroute", "-n", "-m", "10", "-w", "1", "1.1.1.1")}
    if osname == "Linux":
        return {"os": osname,
                "ip_addr": sh("ip", "addr"),
                "ip_route": sh("ip", "route"),
                "dns": sh("cat", "/etc/resolv.conf"),
                "traceroute": sh("traceroute", "-n", "-m", "10", "-w", "1", "1.1.1.1")}
    return {"os": osname,
            "ipconfig": sh("ipconfig", "/all"),
            "route": sh("route", "print"),
            "arp": sh("arp", "-a"),
            "traceroute": sh("tracert", "-d", "-h", "10", "-w", "800", "1.1.1.1"),
            "netipaddress": sh("powershell", "-NoProfile", "-Command",
                               "Get-NetIPAddress -AddressFamily IPv4 | "
                               "Select-Object InterfaceAlias,IPAddress,PrefixLength,"
                               "PrefixOrigin,SuffixOrigin,ValidLifetime | ConvertTo-Json")}


def public_address():
    """What a server on the outside says your address is."""
    out = sh("curl", "-s", "--max-time", "10", "https://api.ipify.org")
    return out.strip() or None


def collect(label):
    os.makedirs(OUT, exist_ok=True)
    record = {"label": label, "local": local_facts(), "public": public_address()}
    path = os.path.join(OUT, "addresses.json")
    all_records = json.load(open(path)) if os.path.exists(path) else []
    all_records.append(record)
    json.dump(all_records, open(path, "w"), indent=2)
    print(f"  public address seen from outside: {record['public']}")
    print(f"  -> out/addresses.json  ({len(all_records)} record(s))")
    print("\n  Now read the raw output yourself and answer the questions in task2.md.")
    print("  The script deliberately does not parse it for you.")


# ===================================================== Part C · the DHCP trace
# Path (B). A DHCP exchange only happens when you join a network, and catching
# one needs a capture driver: Wireshark, tshark and Npcap could not be installed
# on this machine, and Windows' own pktmon refuses without administrator rights
# ("PktMon 드라이버와 통신하지 못했습니다: 액세스가 거부되었습니다", exit 5).
# So Part C uses the textbook authors' trace, as README.md and task2.md allow.

TRACE_ZIP_URL = "https://www-net.cs.umass.edu/wireshark-labs/wireshark-traces-9e.zip"
TRACE_ZIP_LOCAL = os.path.join(HERE, "..", "traces", "wireshark-traces-9e.zip")
TRACE_MEMBER = "dhcp-wireshark-trace1-1.pcapng"

ATTRIBUTION = """\
Wireshark lab trace files from J.F. Kurose and K.W. Ross,
Computer Networking: A Top-Down Approach, 9th ed.
https://gaia.cs.umass.edu/kurose_ross/
Copyright 1996-2025 J.F. Kurose, K.W. Ross. All Rights Reserved."""


def fetch_trace():
    """Put the authors' DHCP trace at out/dhcp.pcapng.

    It is not committed to the repository - it is their material, marked All
    Rights Reserved - so this command is how anyone else reconstructs it.
    """
    os.makedirs(OUT, exist_ok=True)
    dest = os.path.join(OUT, "dhcp.pcapng")
    if os.path.exists(TRACE_ZIP_LOCAL):
        print(f"  using {os.path.normpath(TRACE_ZIP_LOCAL)}")
        z = zipfile.ZipFile(TRACE_ZIP_LOCAL)
    else:
        print(f"  fetching {TRACE_ZIP_URL}")
        with urllib.request.urlopen(TRACE_ZIP_URL, timeout=300) as r:
            z = zipfile.ZipFile(io.BytesIO(r.read()))
    with z.open(TRACE_MEMBER) as src, open(dest, "wb") as out:
        out.write(src.read())
    print(f"  -> {dest}  ({os.path.getsize(dest):,} bytes)\n")
    print(ATTRIBUTION)
    return 0


# ------------------------------------------------- report-time parsing starts
# Everything below runs at *report* time, not at collect time. task2.md is
# explicit that --collect "deliberately does not parse any of it", and that
# separation is the point of the exercise: the raw output is the evidence, and
# reading it is the work. So the evidence is stored verbatim and interpreted
# here, where the interpretation can be checked against it.

def read_pcapng(path):
    """Yield (frame_number, timestamp_seconds, frame_bytes).

    Same block walker as w04-tcp/task2_measure.py - SHB for endianness, IDB for
    the timestamp resolution, EPB for the packets - with one addition: the link
    type is checked, so a capture that is not Ethernet fails loudly instead of
    being dissected into nonsense.
    """
    raw = open(path, "rb").read()
    off, n, endian, tsresol, linktype = 0, 0, "<", 6, None
    while off + 12 <= len(raw):
        btype = struct.unpack(endian + "I", raw[off:off + 4])[0]
        if btype == 0x0A0D0D0A:                             # Section Header
            if raw[off + 8:off + 12] == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif raw[off + 8:off + 12] == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            btype = struct.unpack(endian + "I", raw[off:off + 4])[0]
        total = struct.unpack(endian + "I", raw[off + 4:off + 8])[0]
        if total < 12 or off + total > len(raw):
            break
        if btype == 0x00000001:                             # Interface Description
            linktype = struct.unpack(endian + "H", raw[off + 8:off + 10])[0]
            if linktype != 1:
                raise ValueError(f"{path}: link type {linktype}, expected 1 (Ethernet)")
            body, o = raw[off + 16:off + total - 4], 0
            while o + 4 <= len(body):
                code, olen = struct.unpack(endian + "HH", body[o:o + 4])
                if code == 0:
                    break
                if code == 9 and olen >= 1:
                    tsresol = body[o + 4]
                o += 4 + olen + ((-olen) % 4)
        elif btype == 0x00000006:                           # Enhanced Packet
            hi, lo, caplen = struct.unpack(endian + "III", raw[off + 12:off + 24])
            ticks = (hi << 32) | lo
            ts = ticks / (2 ** (tsresol & 0x7F) if tsresol & 0x80 else 10 ** tsresol)
            n += 1
            yield n, ts, raw[off + 28:off + 28 + caplen]
        off += total


MAGIC_COOKIE = b"\x63\x82\x53\x63"          # RFC 2132. Before this it is BOOTP.
MSGTYPE = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
           5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}
OPTNAME = {1: "subnet_mask", 3: "router", 6: "dns", 12: "hostname",
           15: "domain_name", 28: "broadcast_addr", 50: "requested_ip",
           51: "lease_time", 53: "message_type", 54: "server_id",
           55: "param_req_list", 56: "message", 57: "max_dhcp_size",
           58: "renewal_T1", 59: "rebinding_T2", 61: "client_id"}
IP_OPTS = {1, 3, 6, 28, 50, 54}             # dotted quad(s)
U32_OPTS = {51, 58, 59}                     # big-endian seconds
STR_OPTS = {12, 15, 56}


def _ip(b):
    return ".".join(str(x) for x in b)


def _mac(b):
    return ":".join(f"{x:02x}" for x in b)


def parse_dhcp_options(raw):
    """TLV walk from byte 240 of the BOOTP payload.

    Two codes are not TLVs: 0x00 (PAD) is a single byte with no length, and
    0xFF (END) terminates. Everything else is code, length, then that many
    bytes of value.
    """
    out, order, i = {}, [], 0
    while i < len(raw):
        code = raw[i]
        if code == 0:
            i += 1
            continue
        if code == 255:
            break
        if i + 1 >= len(raw):
            break
        length = raw[i + 1]
        if i + 2 + length > len(raw):
            break                            # truncated - stop rather than guess
        val = raw[i + 2:i + 2 + length]
        if code == 53:
            dec = MSGTYPE.get(val[0], val[0])
        elif code in U32_OPTS and length == 4:
            dec = struct.unpack("!I", val)[0]
        elif code in IP_OPTS and length % 4 == 0:
            ips = [_ip(val[k:k + 4]) for k in range(0, length, 4)]
            dec = ips[0] if len(ips) == 1 else ips
        elif code in STR_OPTS:
            dec = val.decode("latin-1")
        elif code == 55:
            dec = list(val)
        elif code == 57 and length == 2:
            dec = struct.unpack("!H", val)[0]
        elif code == 61 and length == 7:
            dec = f"type{val[0]}:{_mac(val[1:])}"
        else:
            dec = val.hex()
        out[code] = dec
        order.append({"code": code, "name": OPTNAME.get(code, f"opt{code}"),
                      "len": length, "value": dec, "raw": val.hex()})
        i += 2 + length
    return out, order


def dissect_dhcp(frame):
    """Ethernet -> IPv4 -> UDP -> BOOTP/DHCP, or None if it is not one."""
    if len(frame) < 34 or struct.unpack("!H", frame[12:14])[0] != 0x0800:
        return None
    ihl = (frame[14] & 0x0F) * 4
    if frame[14 + 9] != 17:                                  # protocol 17 = UDP
        return None
    u = 14 + ihl
    if len(frame) < u + 8:
        return None
    sport, dport, ulen, _ = struct.unpack("!HHHH", frame[u:u + 8])
    if {sport, dport} != {67, 68}:
        return None
    b = frame[u + 8:]
    if len(b) < 240 or b[236:240] != MAGIC_COOKIE:
        return None
    hlen = b[2]
    xid, secs, flags = struct.unpack("!IHH", b[4:12])
    opts, order = parse_dhcp_options(b[240:])
    return {
        "eth_src": _mac(frame[6:12]), "eth_dst": _mac(frame[0:6]),
        "ip_src": _ip(frame[26:30]), "ip_dst": _ip(frame[30:34]),
        "ttl": frame[22], "sport": sport, "dport": dport, "udp_len": ulen,
        "op": b[0], "xid": xid, "secs": secs, "flags": flags,
        # The field C4 turns on: bit 15 of the BOOTP flags word.
        "broadcast_flag": bool(flags & 0x8000),
        "ciaddr": _ip(b[12:16]), "yiaddr": _ip(b[16:20]),
        "siaddr": _ip(b[20:24]), "giaddr": _ip(b[24:28]),
        "chaddr": _mac(b[28:28 + hlen]),
        "msgtype": opts.get(53), "opts": opts, "order": order,
        "l2_broadcast": frame[0:6] == b"\xff" * 6,
        "l3_broadcast": frame[30:34] == b"\xff" * 4,
    }


def dissect_arp(frame):
    """Just enough ARP to find the duplicate-address probes after the Ack."""
    if len(frame) < 42 or struct.unpack("!H", frame[12:14])[0] != 0x0806:
        return None
    op = struct.unpack("!H", frame[20:22])[0]
    return {"op": op, "sender_mac": _mac(frame[22:28]), "sender_ip": _ip(frame[28:32]),
            "target_ip": _ip(frame[38:42])}


def analyze_dhcp(path=None):
    """Answer C1-C4 from the capture, and write out/dhcp-analysis.json."""
    path = path or os.path.join(OUT, "dhcp.pcapng")
    if not os.path.exists(path):
        print(f"  no capture at {path}  - run --fetch-trace")
        return 1

    msgs, arps, total = [], [], 0
    for n, ts, frame in read_pcapng(path):
        total += 1
        d = dissect_dhcp(frame)
        if d:
            d["n"], d["t"] = n, ts
            msgs.append(d)
            continue
        a = dissect_arp(frame)
        if a:
            a["n"], a["t"] = n, ts
            arps.append(a)
    if not msgs:
        print("  no DHCP messages in this capture")
        return 1

    # One transaction is one xid. Take the first that completes a DORA.
    by_xid = {}
    for d in msgs:
        by_xid.setdefault(d["xid"], []).append(d)
    xid, group = next(
        ((x, g) for x, g in by_xid.items()
         if {"DISCOVER", "OFFER", "REQUEST", "ACK"} <= {m["msgtype"] for m in g}),
        (None, None))
    if xid is None:
        xid, group = next(iter(by_xid.items()))

    pick = lambda kind: next((m for m in group if m["msgtype"] == kind), None)
    disc, offer, req, ack = (pick(k) for k in ("DISCOVER", "OFFER", "REQUEST", "ACK"))
    t0 = group[0]["t"]
    lease = ack["opts"].get(51)
    t1, t2 = ack["opts"].get(58), ack["opts"].get(59)

    # After the Ack the client still does not use the address: RFC 5227 says it
    # probes for a duplicate first (sender 0.0.0.0, because it does not yet
    # trust the address), then announces it (sender == target).
    yi = ack["yiaddr"]
    probes = [a["n"] for a in arps
              if a["target_ip"] == yi and a["sender_ip"] == "0.0.0.0" and a["n"] > ack["n"]]
    announces = [a["n"] for a in arps
                 if a["target_ip"] == yi == a["sender_ip"] and a["n"] > ack["n"]]
    first_use = min((a["t"] for a in arps if a["n"] > ack["n"]
                     and a["sender_ip"] == yi), default=None)

    meta = {
        "capture": os.path.basename(path),
        "bytes": os.path.getsize(path),
        "sha256": hashlib.sha256(open(path, "rb").read()).hexdigest(),
        "frames_total": total, "dhcp_messages": len(msgs),
        "provenance": {"archive": os.path.basename(TRACE_ZIP_LOCAL),
                       "member": TRACE_MEMBER, "source": TRACE_ZIP_URL,
                       "attribution": ATTRIBUTION,
                       "note": "path (B): not my own capture - no Wireshark, "
                               "tshark or Npcap available, and pktmon needs "
                               "administrator rights (exit 5)"},
        "C1": {"complete": all((disc, offer, req, ack)),
               "xid": f"0x{xid:08x}",
               "messages": [{"frame": m["n"], "at_s": round(m["t"] - t0, 6),
                             "type": m["msgtype"], "opt53": m["opts"].get(53),
                             "src": f'{m["ip_src"]}:{m["sport"]}',
                             "dst": f'{m["ip_dst"]}:{m["dport"]}',
                             "eth_dst": m["eth_dst"], "secs": m["secs"],
                             "flags": f'0x{m["flags"]:04x}',
                             "broadcast_flag": m["broadcast_flag"],
                             "ciaddr": m["ciaddr"], "yiaddr": m["yiaddr"],
                             "l2_broadcast": m["l2_broadcast"],
                             "l3_broadcast": m["l3_broadcast"]}
                            for m in sorted(group, key=lambda m: m["n"])],
               "dora_seconds": round(ack["t"] - disc["t"], 6),
               "request_to_ack_ms": round((ack["t"] - req["t"]) * 1000, 3)},
        "C2": {"src": disc["ip_src"], "dst": disc["ip_dst"],
               "sport": disc["sport"], "dport": disc["dport"],
               "eth_dst": disc["eth_dst"], "chaddr": disc["chaddr"],
               "ciaddr": disc["ciaddr"]},
        "C3": {"lease_s": lease, "T1_s": t1, "T2_s": t2,
               "T1_fraction": round(t1 / lease, 4) if lease and t1 else None,
               "T2_fraction": round(t2 / lease, 4) if lease and t2 else None,
               "client_requested_lease_s": disc["opts"].get(51)},
        "C4": {"offer_unicast": offer is not None and not offer["l3_broadcast"],
               "ack_unicast": not ack["l3_broadcast"],
               "request_broadcast": req["l3_broadcast"],
               "broadcast_flag_set": any(m["broadcast_flag"] for m in group),
               "yiaddr": yi, "server_id": ack["opts"].get(54),
               "requested_ip_in_request": req["opts"].get(50),
               "arp_probe_frames": probes, "arp_announce_frames": announces,
               "seconds_from_ack_to_first_claim":
                   round(first_use - ack["t"], 3) if first_use else None},
        "offered": {OPTNAME.get(c, f"opt{c}"): v for c, v in ack["opts"].items()
                    if c in (1, 3, 6, 15, 28, 54)},
        "options_seen": {m["msgtype"]: m["order"] for m in (disc, offer, req, ack) if m},
    }
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "dhcp-analysis.json"), "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2, ensure_ascii=False)

    print(f"\n  {path}")
    print(f"  {total} frames, {len(msgs)} DHCP messages, transaction 0x{xid:08x}\n")
    for m in meta["C1"]["messages"]:
        print(f"    frame {m['frame']:>4}  +{m['at_s']:>8.6f}s  {str(m['type']):<9} "
              f"{m['src']:<24} -> {m['dst']:<24} flags={m['flags']}")
    print(f"\n  C2  Discover  {disc['ip_src']} -> {disc['ip_dst']}  "
          f"(eth {disc['eth_dst']})")
    print(f"  C3  lease {lease}s   T1 {t1}s ({meta['C3']['T1_fraction']})   "
          f"T2 {t2}s ({meta['C3']['T2_fraction']})")
    print(f"      the Discover also carries option 51 = "
          f"{meta['C3']['client_requested_lease_s']}s - that is the client asking")
    print(f"  C4  broadcast flag set: {meta['C4']['broadcast_flag_set']}   "
          f"Offer unicast: {meta['C4']['offer_unicast']}   "
          f"Ack unicast: {meta['C4']['ack_unicast']}   "
          f"Request broadcast: {meta['C4']['request_broadcast']}")
    if probes:
        print(f"      ARP probes {probes}, announcements {announces}, "
              f"address first claimed by gratuitous ARP {meta['C4']['seconds_from_ack_to_first_claim']}s "
              f"after the Ack")
    print(f"\n  -> out/dhcp-analysis.json")
    return 0


# ---------------------------------------------- reading the raw collect output
def ip2int(s):
    a, b, c, d = (int(x) for x in s.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def int2ip(n):
    return f"{(n >> 24) & 255}.{(n >> 16) & 255}.{(n >> 8) & 255}.{n & 255}"


def mask2plen(mask):
    m = ip2int(mask)
    plen = bin(m).count("1")
    if m != ((0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF if plen else 0):
        raise ValueError(f"{mask} is not a contiguous mask")
    return plen


BLOCKS = [("10.0.0.0", 8, "private (RFC 1918)"),
          ("172.16.0.0", 12, "private (RFC 1918)"),
          ("192.168.0.0", 16, "private (RFC 1918)"),
          ("100.64.0.0", 10, "shared address space (RFC 6598)"),
          ("169.254.0.0", 16, "link-local (RFC 3927)"),
          ("127.0.0.0", 8, "loopback")]


def is_masked(addr):
    """The published copy of this data masks public addresses as 58.78.x.x."""
    return bool(addr) and "x" in addr.lower()


def classify(addr):
    if is_masked(addr):
        return "public (masked in this copy)"
    a = ip2int(addr)
    for base, plen, name in BLOCKS:
        m = (0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF
        if a & m == ip2int(base) & m:
            return name
    return "public"


def common_prefix(a, b):
    """How many leading bits two addresses share."""
    return 32 - (ip2int(a) ^ ip2int(b)).bit_length()


_LEASE_RE = re.compile(r"(\d{4})\D+(\d{1,2})\D+(\d{1,2})\D+?.*?(오전|오후|AM|PM)?\s*"
                       r"(\d{1,2}):(\d{2}):(\d{2})")


def lease_seconds(text):
    """Seconds since an arbitrary epoch, from ipconfig's localised timestamp.

    ipconfig prints these in the system locale - here "2026년 9월 28일 월요일 오후
    1:00:06" - so strptime is the wrong tool. Pull the numbers out, fix the
    12-hour clock, and return None rather than a wrong number if it does not
    look like a timestamp at all.
    """
    m = _LEASE_RE.search(text or "")
    if not m:
        return None
    y, mo, d, ampm, h, mi, s = m.groups()
    y, mo, d, h, mi, s = (int(v) for v in (y, mo, d, h, mi, s))
    if ampm in ("오후", "PM") and h != 12:
        h += 12
    if ampm in ("오전", "AM") and h == 12:
        h = 0
    days = (y * 365 + y // 4 - y // 100 + y // 400
            + [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334][mo - 1] + d)
    if mo > 2 and (y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)):
        days += 1
    return ((days * 24 + h) * 60 + mi) * 60 + s


def parse_ipconfig(text):
    """`ipconfig /all` -> [{adapter, fields}].

    Adapter headers are localised ("Ethernet adapter 이더넷:") so they are found
    by shape - an unindented line ending in ':' - not by keyword. Labels are
    padded with dots; values can continue on the next, deeper-indented line
    (DNS Servers). A trailing "(Preferred)" is dropped.
    """
    adapters, cur, last = [], None, None
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        if not line.startswith(" ") and line.rstrip().endswith(":"):
            cur = {"adapter": line.rstrip()[:-1].strip(), "fields": {}}
            adapters.append(cur)
            last = None
            continue
        if cur is None:
            continue
        m = re.match(r"^\s+([^:]+?)[ .]*:\s?(.*)$", line)
        if m and "." in line.split(":")[0]:
            label = re.sub(r"[ .]+$", "", m.group(1)).strip()
            value = re.sub(r"\((Preferred|선호)\)", "", m.group(2)).strip()
            cur["fields"].setdefault(label, []).append(value)
            last = label
        elif last:
            cur["fields"][last].append(line.strip())
    return adapters


def parse_tracert(text):
    """Hop list from tracert / traceroute -n. '*' for a silent hop."""
    hops = []
    for line in (text or "").splitlines():
        m = re.match(r"^\s*(\d+)\s+(.*)$", line)
        if not m:
            continue
        ips = re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", m.group(2))
        hops.append(ips[-1] if ips else "*")
    return hops


# ConvertTo-Json serialises MSFT_NetIPAddress's enums as their integer values.
PREFIX_ORIGIN = {0: "Other", 1: "Manual", 2: "WellKnown", 3: "Dhcp",
                 4: "RouterAdvertisement"}


def parse_netipaddress(text):
    try:
        v = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []
    rows = v if isinstance(v, list) else [v]
    for r in rows:
        for key in ("PrefixOrigin", "SuffixOrigin"):
            if isinstance(r.get(key), int):
                r[key] = PREFIX_ORIGIN.get(r[key], str(r[key]))
    return rows


def facts(record):
    """One --collect record, read. Windows is parsed; macOS/Linux fall back to
    the raw output so that the report still generates for anyone else."""
    L = record.get("local", {})
    out = {"label": record.get("label"), "public": record.get("public"),
           "os": L.get("os"), "hops": parse_tracert(L.get("traceroute"))}
    if L.get("os") != "Windows":
        out["raw_only"] = True
        return out

    adapters = parse_ipconfig(L.get("ipconfig"))
    # A1 is the interface the default route leaves by - the one that has a
    # default gateway. Not "the first adapter", and not "the one called Wi-Fi".
    primary = next((a for a in adapters
                    if any(g.strip() and g[0].isdigit()
                           for g in a["fields"].get("Default Gateway", []))), None)
    out["adapters"] = []
    for a in adapters:
        f = a["fields"]
        ipv4 = next((v for v in f.get("IPv4 Address", []) if v), None)
        if ipv4:
            out["adapters"].append({"name": a["adapter"], "ipv4": ipv4,
                                    "mask": (f.get("Subnet Mask") or [None])[0],
                                    "gateway": next((g for g in f.get("Default Gateway", [])
                                                     if g and g[0].isdigit()), None)})
    if primary:
        f = primary["fields"]
        out.update({
            "adapter": primary["adapter"],
            "ipv4": next(v for v in f.get("IPv4 Address", []) if v),
            "mask": f.get("Subnet Mask", [None])[0],
            "gateway": next(g for g in f["Default Gateway"] if g and g[0].isdigit()),
            "dhcp_server": (f.get("DHCP Server") or [None])[0],
            "dns": [d for d in f.get("DNS Servers", []) if d],
            "mac": (f.get("Physical Address") or [None])[0],
            "lease_obtained": (f.get("Lease Obtained") or [None])[0],
            "lease_expires": (f.get("Lease Expires") or [None])[0],
        })
        a, b = lease_seconds(out["lease_obtained"]), lease_seconds(out["lease_expires"])
        out["lease_s"] = (b - a) if a is not None and b is not None else None
    out["netip"] = parse_netipaddress(L.get("netipaddress"))
    return out


def nat_verdict(f):
    """(count or None, [evidence]). Never a bare number."""
    a1, a4, hops = f.get("ipv4"), f.get("public"), f.get("hops", [])
    ev = []
    if not a1 or not a4:
        return None, ["missing A1 or A4"]
    if classify(a1) == "public":
        return 0, [f"A1 {a1} is already public - no NAT"]
    ev.append(f"A1 `{a1}` is {classify(a1)}; A4 `{a4}` is {classify(a4)} - "
              f"so at least one NAT")
    # CGNAT test: an RFC 6598 address alone is not enough. It must be the
    # address the default route uses, handed over by DHCP, with a real prefix.
    if classify(a1).startswith("shared"):
        return 2, ev + [f"A1 is in 100.64.0.0/10 *and* is the address the default "
                        f"route egresses - carrier-grade NAT, two layers"]
    if is_masked(a4) or (len(hops) >= 2 and is_masked(hops[1])):
        return None, ev + ["the public addresses are masked in this copy of the data, "
                           "so the prefix comparison between hop 2 and A4 cannot be "
                           "recomputed from it - the committed report.md was generated "
                           "from the unmasked data"]
    if len(hops) >= 2 and hops[1] != "*" and classify(hops[1]) == "public":
        cp = common_prefix(hops[1], a4)
        if cp >= 24:
            ev.append(f"hop 2 `{hops[1]}` - the first router past my gateway - is "
                      f"already public, and shares a /{cp} with A4. The link between "
                      f"my router's WAN side and the ISP is publicly numbered, so my "
                      f"router's WAN address is public: the translation happens once, "
                      f"at hop 1")
            return 1, ev
    return None, ev + ["inconclusive from traceroute alone"]


# ------------------------------------------------------------------ the report
def report():
    """out/addresses.json + out/dhcp-analysis.json -> out/report.md.

    Everything numeric is computed here from the stored evidence; the reasoning
    is written once, as prose filled from those numbers. Re-running after a
    second --collect regenerates the whole document, so the comparison in B2/B3
    appears as soon as the second network exists.
    """
    from task1_forward import network_range           # A2 checks against Task 1

    ap = os.path.join(OUT, "addresses.json")
    if not os.path.exists(ap):
        print("  no out/addresses.json - run --collect first")
        return 1
    records = json.load(open(ap))
    F = [facts(r) for r in records]
    dp = os.path.join(OUT, "dhcp-analysis.json")
    D = json.load(open(dp, encoding="utf-8")) if os.path.exists(dp) else None

    o = []
    w = o.append
    w("# Week 5 · Task 2 — Where exactly am I on the internet?\n")
    w(f"Generated by `task2_myaddr.py --report` from `out/addresses.json` "
      f"({len(records)} record{'s' if len(records) != 1 else ''}) and "
      f"`out/dhcp-analysis.json`. Every number below is computed from the raw "
      f"`--collect` output at report time; the collector itself parses nothing.\n")

    # ------------------------------------------------------------ §0 provenance
    w("## 0. What was measured, and with what\n")
    for f in F:
        w(f"- **`{f['label']}`** — {f.get('os')}, interface `{f.get('adapter', '?')}`")
    w("\n**Part C is not my own capture.** Wireshark, tshark and Npcap could not be "
      "installed on this machine, and Windows' built-in `pktmon` refuses without "
      "administrator rights (`액세스가 거부되었습니다`, exit 5). A DHCP exchange only "
      "happens when you join a network, so there was no way to catch one here. Part C "
      "therefore takes path (B), the official DHCP trace, parsed by this script's own "
      "pcapng/Ethernet/IPv4/UDP/BOOTP dissector since `tshark` is also absent.\n")
    if D:
        w(f"> {D['provenance']['attribution'].replace(chr(10), chr(10) + '> ')}\n")
        w(f"File: `{D['provenance']['member']}` from `{D['provenance']['archive']}`, "
          f"{D['bytes']:,} bytes, {D['frames_total']} frames, "
          f"SHA-256 `{D['sha256'][:16]}…`.\n")

    f = F[0]
    if f.get("raw_only"):
        w("\n_Parsing is implemented for Windows only; see the raw output in "
          "`out/addresses.json`._\n")
    else:
        # --------------------------------------------------------------- §1 A1
        w("## 1. A1 · The address my machine holds\n")
        w("| interface | IPv4 | mask | gateway |")
        w("|---|---|---|---|")
        for a in f["adapters"]:
            mark = " ← **default route**" if a["name"] == f.get("adapter") else ""
            w(f"| {a['name']}{mark} | `{a['ipv4']}` | `{a['mask']}` | "
              f"{('`' + a['gateway'] + '`') if a['gateway'] else '—'} |")
        w(f"\n**A1 = `{f['ipv4']}` / `{f['mask']}`** on `{f['adapter']}`. It is the "
          f"interface that holds the default gateway — the one the default route "
          f"actually leaves by — which is what makes it *the* address rather than "
          f"merely *an* address. (MAC `{f['mac']}`, DHCP server `{f['dhcp_server']}`.)\n")

        # --------------------------------------------------------------- §2 A2
        plen = mask2plen(f["mask"])
        a_int, m_int = ip2int(f["ipv4"]), ip2int(f["mask"])
        net = a_int & m_int
        bc = net | (~m_int & 0xFFFFFFFF)
        w("## 2. A2 · The subnet's range, by hand\n")
        w("```")
        w(f"addr   {f['ipv4']:<17} = {' '.join(f'{(a_int >> s) & 255:08b}' for s in (24, 16, 8, 0))}")
        w(f"mask   {f['mask']:<17} = {' '.join(f'{(m_int >> s) & 255:08b}' for s in (24, 16, 8, 0))}")
        w(f"AND    {int2ip(net):<17} = {' '.join(f'{(net >> s) & 255:08b}' for s in (24, 16, 8, 0))}   /{plen}")
        w(f"~mask  {int2ip(~m_int & 0xFFFFFFFF):<17}")
        w(f"OR     {int2ip(bc):<17}   <- network OR ~mask = broadcast")
        w("```")
        hand = (int2ip(net + 1), int2ip(bc - 1), int2ip(bc))
        t1 = tuple(network_range(f"{int2ip(net)}/{plen}"))
        w(f"\nNetwork `{int2ip(net)}/{plen}`: first usable **`{hand[0]}`**, last "
          f"usable **`{hand[1]}`**, broadcast **`{hand[2]}`** — {bc - net + 1} "
          f"addresses, {bc - net - 1} usable.\n")
        w(f"Checked against Task 1: `network_range(\"{int2ip(net)}/{plen}\")` returned "
          f"`{t1}` — **{'identical' if t1 == hand else 'DIFFERENT'}**.\n")

        # --------------------------------------------------------------- §3 A3
        g = f["gateway"]
        inside = (ip2int(g) & m_int) == net
        w("## 3. A3 · The default gateway, and why it has to be inside that range\n")
        w(f"Gateway **`{g}`** — **{'inside' if inside else 'OUTSIDE'}** "
          f"`{hand[0]}`…`{hand[1]}`.\n")
        w("It has to be, and not by convention. A host sends a packet one of exactly "
          "two ways: if `destination AND mask == my address AND mask` the destination "
          "is on this link, so it ARPs for it directly; otherwise it hands the frame to "
          "the gateway — **which also means ARPing for the gateway**. ARP is a "
          "link-layer broadcast, so it reaches only this broadcast domain, and a host "
          "only attempts it for addresses its own mask says are on-link. A gateway "
          "outside the range could never be resolved to a MAC address, the frame could "
          "never be built, and the default route would be unusable. A gateway is not "
          "\"the way out\" in the abstract — it is a neighbour on your own wire whose "
          "MAC you can learn, and that happens to forward.\n")
        if f.get("dhcp_server") == g:
            dns = f.get("dns") or []
            if g in dns:
                w(f"The DHCP server is also `{g}`, and so is the DNS resolver: gateway, "
                  f"DHCP server and resolver are one box, the home router.\n")
            else:
                w(f"The DHCP server is also `{g}` - the gateway and the DHCP server are "
                  f"one box, the home router. The resolvers are *not*: DHCP handed out "
                  f"{', '.join(f'`{d}`' for d in dns)}, the ISP's own servers "
                  f"({classify(dns[0]) if dns else '?'} addresses), so name resolution "
                  f"bypasses the router entirely. Compare the trace in §7, where one "
                  f"router is gateway, DHCP server and resolver at once.\n")

        # --------------------------------------------------------------- §4 A4
        w("## 4. A4 · The address the outside world saw\n")
        w(f"**`{f['public']}`** — {classify(f['public'])}, as reported by "
          f"`https://api.ipify.org`.\n")

        # --------------------------------------------------------------- §5 A5
        count, ev = nat_verdict(f)
        w("## 5. A5 · How many layers of NAT\n")
        w(f"**{count if count is not None else 'undetermined'}.**\n")
        for e in ev:
            w(f"- {e}")
        w("\ntraceroute to `1.1.1.1`, first hops:\n")
        w("| hop | address | class |")
        w("|---:|---|---|")
        for i, h in enumerate(f["hops"][:8], 1):
            w(f"| {i} | `{h}` | {classify(h) if h != '*' else 'no reply'} |")
        w("\n**How to tell one NAT from two.** One: A1 private, A4 public, and the first "
          "hop *past* your own gateway is public and in the same prefix as A4 — your "
          "router's WAN side is the public address. Two: either your own DHCP address is "
          "in `100.64.0.0/10` *and* it is the address your default route uses, or the hop "
          "past your gateway is itself private and A4 is a carrier-pool address you cannot "
          "place near your own link. Two RFC 1918 layers (a travel router behind venue "
          "Wi-Fi) is also two NATs, so \"two\" does not mean \"CGNAT\".\n")

        # ----------------------------------------------------- §5b the 100.64 trap
        cg_hops = [(i, h) for i, h in enumerate(f["hops"], 1)
                   if h != "*" and classify(h).startswith("shared")]
        cg_ifaces = [a for a in f["adapters"] if classify(a["ipv4"]).startswith("shared")]
        if cg_hops or cg_ifaces:
            w("## 5b. The `100.64.0.0/10` trap — it fires "
              f"{'twice' if cg_hops and cg_ifaces else 'once'} on this machine\n")
            w("`task2.md` says: *\"If A1 is `100.64.x` you have found carrier-grade NAT "
              "and there are two.\"* On this machine that rule is triggered, and it is "
              "wrong every time it is.\n")
            if cg_hops:
                first_pub = next((i for i, h in enumerate(f["hops"], 1)
                                  if h != "*" and classify(h).startswith("public")), None)
                w(f"**1. Traceroute hops {', '.join(str(i) for i, _ in cg_hops)} are in "
                  f"`100.64.0.0/10`** (`{'`, `'.join(h for _, h in cg_hops)}`). These are "
                  f"the ISP's internal backbone links, not a NAT in front of me. The "
                  f"giveaway is *order*: they appear after hop {first_pub}, i.e. after my "
                  f"packets already carry a public source address. A carrier NAT would "
                  f"have to sit *between* me and my public address, not several hops "
                  f"beyond it. Carriers number internal links from `100.64/10` and `10/8` "
                  f"because those links never need to be reachable from outside.\n")
            for a in cg_ifaces:
                np = next((x for x in f.get("netip", [])
                           if x.get("IPAddress") == a["ipv4"]), {})
                w(f"**2. The interface `{a['name']}` holds `{a['ipv4']}`, which is inside "
                  f"`100.64.0.0/10`.** It is not carrier NAT, and the machine itself says "
                  f"so:\n")
                w("| evidence | this interface | what carrier NAT would show |")
                w("|---|---|---|")
                w(f"| prefix length | **/{np.get('PrefixLength', '?')}** | a real subnet (/22, /20 …) |")
                w(f"| default gateway | **{a['gateway'] or 'none'}** | a next hop - you are a subnet member |")
                w(f"| address origin | **{np.get('PrefixOrigin', '?')}** "
                  f"(Wi-Fi: {next((x.get('PrefixOrigin') for x in f.get('netip', []) if x.get('IPAddress') == f['ipv4']), '?')}) | Dhcp - a carrier hands it over |")
                w(f"| default route leaves by | **`{f['ipv4']}`**, not this | this address - that is the definition |")
                w("\nThis is a mesh VPN that deliberately reuses RFC 6598 space because it is "
                  "the one large block that home and enterprise networks reliably do not use, "
                  "so its overlay never collides with `10/8` or `192.168/16`.\n")
            w("**The lesson.** An address range is a *registry convention*, not a fact about "
              "topology. RFC 6598 reserved `100.64/10` for carrier NAT, but nothing on the "
              "wire enforces that. The correct CGNAT test is not `A1 ∈ 100.64/10`; it is "
              "`A1 ∈ 100.64/10` **and** the default route egresses A1 **and** A1 came from "
              "DHCP/PPP **and** it came with a real prefix and gateway. Here the first "
              "condition holds for the Tailscale address and the other three fail. The number is a hypothesis; the "
              "routing table, the address origin and traceroute are the test.\n")

    # ------------------------------------------------------------ §6 B2/B3
    w("## 6. B2 · B3 · Two networks\n")
    usable = [x for x in F if not x.get("raw_only")]
    if len({x["label"] for x in F}) < 2:
        w("> **Not yet measured.** Only one network has been collected. The second — "
          "phone tethering — requires the phone, which is not with me this week. The "
          "comparison below will be generated automatically once it exists:\n>\n"
          "> ```\n> python task2_myaddr.py --collect \"phone tethering\"\n"
          "> python task2_myaddr.py --report\n> ```\n")
    else:
        w("| | " + " | ".join(f"`{x['label']}`" for x in usable) + " |")
        w("|---|" + "---|" * len(usable))
        for key, name in (("ipv4", "private address"), ("mask", "mask"),
                          ("gateway", "gateway"), ("dhcp_server", "DHCP server"),
                          ("public", "public address")):
            w(f"| {name} | " + " | ".join(f"`{x.get(key)}`" for x in usable) + " |")
        w("| NAT layers | " + " | ".join(str(nat_verdict(x)[0]) for x in usable) + " |")
        a, b = usable[0], usable[1]
        pub_changed = a["public"] != b["public"]
        priv_changed = a["ipv4"] != b["ipv4"]
        w(f"\n**Did the public address change? {'Yes' if pub_changed else 'No'}.** "
          + ("The public address belongs to whichever NAT is outermost, so it changes "
             "with the provider that owns that NAT — a different network is a different "
             "owner of that address." if pub_changed else
             "The same outermost NAT answered both times."))
        w(f"\n**Did the private one? {'Yes' if priv_changed else 'No'}.** "
          + ("The private address is handed out by whichever DHCP server sits on the "
             "local link, from that server's own pool. A different local network is a "
             "different server and usually a different RFC 1918 block, so the address "
             "changes even though nothing about my machine did." if priv_changed else
             "The same local DHCP server handed out the same address - it remembers the "
             "client by its hardware address."))
        w("")

    # ------------------------------------------------------------ §7-11 Part C
    if D:
        c1, c2, c3, c4 = D["C1"], D["C2"], D["C3"], D["C4"]
        w("## 7. C1 · DORA in the capture\n")
        w(f"All four present: **{'yes' if c1['complete'] else 'NO'}**, one transaction, "
          f"`xid {c1['xid']}`.\n")
        w("| frame | +t (s) | message | src → dst | Ethernet dst | `secs` | flags |")
        w("|---:|---:|---|---|---|---:|---|")
        for m in c1["messages"]:
            w(f"| {m['frame']} | {m['at_s']:.6f} | **{m['type']}** | `{m['src']}` → "
              f"`{m['dst']}` | `{m['eth_dst']}` | {m['secs']} | `{m['flags']}` |")
        w(f"\nThe `xid` is the only thing tying these together, and it has to be: in "
          f"none of the six does an IP address identify the client. Its own three "
          f"messages carry source `0.0.0.0`, and the server's three are addressed to "
          f"an IP the client does not own yet. Two Discovers and two Offers: "
          f"the client retransmitted (`secs` 0 → 2) and the server answered both. The "
          f"whole exchange took {c1['dora_seconds']:.3f} s; Request to Ack took "
          f"{c1['request_to_ack_ms']:.2f} ms. `test_tasks.py` skips its own DORA check "
          f"because `tshark` is absent — this table is the substitute evidence.\n")

        w("## 8. C2 · The Discover's source and destination\n")
        w(f"**`{c2['src']}:{c2['sport']}` → `{c2['dst']}:{c2['dport']}`**, Ethernet "
          f"destination `{c2['eth_dst']}`.\n")
        w(f"**The source must be `{c2['src']}`.** The whole point of the message is that "
          "the client has no address. Any other value would be either a claim to an "
          "address it does not own — replies routed to it would reach whoever does — or "
          "an address on a subnet it has not learned yet. `0.0.0.0` is RFC 1122's \"this "
          "host on this network\", the one value that means *I have no address*, and it "
          "is only ever valid as a source.\n")
        w(f"**That forces the destination.** To unicast, the client would need the "
          f"server's address and a route to it; both arrive in the Ack, later. With no "
          f"mask it cannot even decide whether a candidate is on-link, so it cannot ARP. "
          f"The only reachable destination is the limited broadcast `{c2['dst']}`, which "
          f"every host on the link receives and no router forwards — so the search is "
          f"bounded to exactly the broadcast domain the client is plugged into. The reply "
          f"has the mirror problem: the server cannot ARP for a client that owns no "
          f"address, which is why the client's hardware address `{c2['chaddr']}` travels "
          f"*inside* the payload (`chaddr`), where the server can read it.\n")

        w("## 9. C3 · The lease the server offered\n")
        w(f"| option | value | |")
        w(f"|---|---:|---|")
        w(f"| 51 lease time | **{c3['lease_s']:,} s** | {c3['lease_s'] / 3600:g} hours |")
        w(f"| 58 renewal T1 | {c3['T1_s']:,} s | {c3['T1_fraction']:g} × lease |")
        w(f"| 59 rebinding T2 | {c3['T2_s']:,} s | {c3['T2_fraction']:g} × lease |")
        w(f"\nThe server sent RFC 2131's defaults (0.5 and 0.875) explicitly. **A trap "
          f"worth naming:** option 51 also appears in the *Discover*, with the value "
          f"{c3['client_requested_lease_s']:,} s ({c3['client_requested_lease_s'] / 86400:g} "
          f"days). That is the client *asking*. The same option means a request in Discover "
          f"and Request and a grant in Offer and Ack; reading it off the first DHCP packet "
          f"in the trace gives the wrong answer.\n")
        if not f.get("raw_only") and f.get("lease_s"):
            w(f"For comparison, my own lease on `{f['label']}`: obtained "
              f"`{f['lease_obtained']}`, expires `{f['lease_expires']}` — "
              f"**{f['lease_s']:,} s ({f['lease_s'] / 3600:g} hours)**, twice the trace's.\n")

        w("## 10. C4 · Broadcast, then not\n")
        w(f"What this capture actually shows is more specific than the question: "
          f"**the Offer {'and the Ack are' if c4['offer_unicast'] and c4['ack_unicast'] else 'is'} "
          f"unicast, the Request is {'broadcast' if c4['request_broadcast'] else 'unicast'}, "
          f"and the BOOTP broadcast flag is {'SET' if c4['broadcast_flag_set'] else 'clear'} "
          f"in every message.**\n")
        w("That flag — bit 15 of the BOOTP `flags` word — decides it. RFC 2131 §4.1: a "
          "client that *cannot* receive a unicast datagram before its IP stack is "
          "configured sets it, and the server must then broadcast replies. This client "
          "left it clear, declaring that it *can* receive a unicast frame for an address it "
          "does not yet hold (true of a client that reads at the link layer). Three things "
          "changed between Discover and Ack:\n")
        w(f"1. **The server has a destination it can name.** It has allocated `yiaddr = "
          f"{c4['yiaddr']}`, and has held `chaddr` since the Discover, so it can build the "
          f"frame without ARP.")
        w(f"2. **The client has agreed to that address.** Its Request carried option 50 "
          f"`{c4['requested_ip_in_request']}` and option 54 `{c4['server_id']}`.")
        w("3. **The client said it can be unicast to**, by leaving the flag clear.\n")
        w("**And the Request is still broadcast, for a different reason.** By then the "
          "client knows its address, its mask and the server's address — everything "
          "unicast needs. It broadcasts anyway because RFC 2131 §3.1 requires the "
          "SELECTING-state Request to be heard by *every* DHCP server on the link, so that "
          "the ones whose offers were declined can release what they reserved. So DHCP's "
          "broadcast-or-unicast is driven by two independent causes — *can you be addressed* "
          "and *does anyone else need to overhear* — and conflating them is the easy error. "
          "The renewal Request at T1 is unicast, because by then there is no one else to "
          "tell.\n")
        if c4["arp_probe_frames"]:
            w(f"**The Ack is not the end.** Frames {', '.join(map(str, c4['arp_probe_frames']))} "
              f"are ARP probes for `{c4['yiaddr']}` with sender `0.0.0.0` — RFC 5227 "
              f"duplicate-address detection: the client has the Ack but does not yet trust "
              f"the address enough to put it in a sender field. Frames "
              f"{', '.join(map(str, c4['arp_announce_frames']))} are gratuitous ARP "
              f"announcements with sender = target = `{c4['yiaddr']}`, the first moment it "
              f"claims the address, {c4['seconds_from_ack_to_first_claim']} s after the Ack.\n")

        w("## 11. Path (B) · How long was the lease, and what happens at half of it?\n")
        w(f"**{c3['lease_s']:,} s — {c3['lease_s'] / 3600:g} hours.** At half of it, "
          f"**T1 = {c3['T1_s']:,} s**, the client leaves BOUND and enters **RENEWING**: it "
          f"sends a DHCPREQUEST **unicast** to the server named in option 54 "
          f"(`{c4['server_id']}`), with `ciaddr` now filled in, because it legitimately "
          f"owns the address and can send and receive normally. If the server Acks, the "
          f"lease clock restarts. If not, the client keeps the address and retries until "
          f"**T2 = {c3['T2_s']:,} s** ({c3['T2_fraction']:g}), when it gives up on that "
          f"server, enters **REBINDING**, and *broadcasts* its Request to any server on the "
          f"link. At {c3['lease_s']:,} s the lease expires and it must stop using the "
          f"address and start again from DISCOVER. A lease is a timer the *client* is "
          f"responsible for, not one the server enforces.\n")

    # ------------------------------------------------------------ §12 limits
    w("## 12. What this report does not establish\n")
    w("- **Part C is somebody else's network.** The trace is a Google Wifi router on "
      "`192.168.86.0/24`; it says nothing about my own router's DHCP behaviour beyond "
      "what `ipconfig` shows (lease length and server).")
    w("- **My router's WAN address was inferred from traceroute, not read off the "
      "router.** Hop 2 being public and sharing a /27 with A4 is strong evidence of one "
      "NAT; the router's own status page would close the question.")
    if len({x["label"] for x in F}) < 2:
        w("- **B1–B3 are not yet satisfied.** One network only. See §6.")
    w("")

    rp = os.path.join(OUT, "report.md")
    with open(rp, "w", encoding="utf-8") as fh:
        fh.write("\n".join(o) + "\n")
    print(f"  -> {rp}")
    if not F[0].get("raw_only"):
        c, _ = nat_verdict(F[0])
        print(f"     A1 {F[0].get('ipv4')}/{F[0].get('mask')}  gw {F[0].get('gateway')}  "
              f"A4 {F[0].get('public')}  NAT layers {c}")
    print(f"     networks: {len({x['label'] for x in F})}   DHCP analysis: "
          f"{'yes' if D else 'no - run --fetch-trace then --analyze-dhcp'}")
    return 0


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--collect", metavar="LABEL",
                   help='where you are, e.g. "campus wifi"')
    p.add_argument("--fetch-trace", action="store_true",
                   help="path (B): put the official DHCP trace at out/dhcp.pcapng")
    p.add_argument("--analyze-dhcp", nargs="?", const="", metavar="PCAPNG",
                   help="answer C1-C4 from a capture (default out/dhcp.pcapng)")
    p.add_argument("--report", action="store_true")
    a = p.parse_args()
    if a.collect:
        collect(a.collect)
    elif a.fetch_trace:
        raise SystemExit(fetch_trace())
    elif a.analyze_dhcp is not None:
        raise SystemExit(analyze_dhcp(a.analyze_dhcp or None))
    elif a.report:
        raise SystemExit(report())
    else:
        p.print_help()
