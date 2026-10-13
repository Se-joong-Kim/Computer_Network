#!/usr/bin/env python3
"""Week 7 · Task 2 — read the ARP capture and line it up with the clear.

    python task2_arp.py            # writes out/arp-analysis.json, prints the answers

task2_arp.ps1 does the measuring and needs administrator rights. This needs
none: it only reads what that script left in out/.

Why this exists rather than "open it in Wireshark"
--------------------------------------------------
pktmon on a Wi-Fi adapter records each frame as an 802.11 data frame - a
24-byte 802.11 header, 8 bytes of LLC/SNAP, then the 28-byte ARP message - but
`pktmon etl2pcap` labels the file Ethernet (linktype 1). Read as Ethernet,
every frame is garbage: the "destination MAC" begins with the 802.11
frame-control bytes 08 42, and no frame has type 0x0806, so a Wireshark filter
`arp` (and test_tasks.py's tshark check) finds nothing.

So the first run keeps pktmon's file untouched as out/arp-pktmon-raw.pcapng and
rewrites out/arp.pcapng in Ethernet II form, which is how Wireshark shows Wi-Fi
traffic on Windows anyway: the same destination and source MAC (taken from the
802.11 address fields according to ToDS/FromDS), type 0x0806, the same ARP
message byte for byte, the same timestamps. The analysis reads the raw file,
because it also says which way each frame went over the air.
"""
import ipaddress
import json
import os
import re
import socket
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")
CAPTURE = os.path.join(OUT, "arp.pcapng")
RAW = os.path.join(OUT, "arp-pktmon-raw.pcapng")

BROADCAST = "ff:ff:ff:ff:ff:ff"
SNAP_ARP = bytes.fromhex("aaaa030000000806")        # LLC/SNAP header, then ARP
CAMPUS = 1000          # machines on one campus segment for B4 - roughly a /22; assumed, not measured
WEB = "www.korea.ac.kr"


def mac(b):
    return b.hex(":")


# ----------------------------------------------------------------- pcapng in/out
def read_pcapng(path):
    """[(linktype, ts, units_per_second, data)] for every EPB, timestamps kept exact."""
    raw = open(path, "rb").read()
    ifaces, frames, off = [], [], 0
    while off + 12 <= len(raw):
        btype, blen = struct.unpack("<II", raw[off:off + 8])
        body = raw[off + 8:off + blen - 4]
        if btype == 0x0A0D0D0A:                            # section header
            if body[:4] != b"\x4d\x3c\x2b\x1a":
                raise SystemExit(f"{path}: big-endian pcapng is not handled")
            ifaces = []
        elif btype == 1:                                   # interface description
            linktype = struct.unpack("<H", body[:2])[0]
            units, o = 10 ** 6, 8                          # default if_tsresol
            while o + 4 <= len(body):
                code, olen = struct.unpack("<HH", body[o:o + 4])
                if code == 0:
                    break
                if code == 9:                              # if_tsresol
                    r = body[o + 4]
                    units = 2 ** (r & 0x7F) if r & 0x80 else 10 ** r
                o += 4 + (olen + 3) // 4 * 4
            ifaces.append((linktype, units))
        elif btype == 6:                                   # enhanced packet
            iface, hi, lo, cap = struct.unpack("<IIII", body[:16])
            linktype, units = ifaces[iface]
            frames.append((linktype, (hi << 32) | lo, units, body[20:20 + cap]))
        off += blen
    return frames


def _block(btype, body):
    body += b"\0" * (-len(body) % 4)
    n = len(body) + 12
    return struct.pack("<II", btype, n) + body + struct.pack("<I", n)


def _option(code, value):
    return struct.pack("<HH", code, len(value)) + value + b"\0" * (-len(value) % 4)


def write_ethernet_pcapng(path, frames, comment):
    """frames: [(ts in microseconds, ethernet bytes)]. One Ethernet interface."""
    shb = (struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
           + _option(1, comment.encode()) + _option(4, b"task2_arp.py") + _option(0, b""))
    idb = struct.pack("<HHI", 1, 0, 0) + _option(2, b"Wi-Fi") + _option(0, b"")
    out = _block(0x0A0D0D0A, shb) + _block(1, idb)
    for ts, data in frames:
        out += _block(6, struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(data), len(data)) + data)
    open(path, "wb").write(out)


# ------------------------------------------------------------------ dissection
def dissect(linktype, data):
    """{'link', 'da', 'sa', 'ra', 'arp'} or None if this is not an ARP frame."""
    if linktype == 1 and data[12:14] == b"\x08\x06":
        return {"link": "ethernet", "da": mac(data[0:6]), "sa": mac(data[6:12]),
                "ra": mac(data[0:6]), "arp": data[14:42]}
    if linktype not in (1, 105) or len(data) < 24 or (data[0] >> 2) & 3 != 2:
        return None                                        # not an 802.11 data frame
    tods, fromds = data[1] & 1, (data[1] >> 1) & 1
    a1, a2, a3 = data[4:10], data[10:16], data[16:22]
    hdr = 24 + (6 if tods and fromds else 0) + (2 if data[0] & 0x80 else 0)   # 4th address, QoS
    if data[hdr:hdr + 8] != SNAP_ARP:
        return None
    if tods and not fromds:                                # station -> AP
        da, sa = a3, a2
    elif fromds and not tods:                              # AP -> station
        da, sa = a1, a3
    elif tods and fromds:
        da, sa = a3, data[24:30]
    else:
        da, sa = a1, a2
    return {"link": "802.11", "da": mac(da), "sa": mac(sa), "ra": mac(a1),
            "dir": "to AP" if tods else "from AP", "arp": data[hdr + 8:hdr + 36]}


def arp_fields(b):
    op = struct.unpack("!H", b[6:8])[0]
    return {"op": {1: "request", 2: "reply"}.get(op, str(op)),
            "sender_mac": mac(b[8:14]), "sender_ip": str(ipaddress.IPv4Address(b[14:18])),
            "target_mac": mac(b[18:24]), "target_ip": str(ipaddress.IPv4Address(b[24:28]))}


def as_ethernet(f):
    eth = bytes.fromhex(f["da"].replace(":", "") + f["sa"].replace(":", "")) + b"\x08\x06" + f["arp"]
    return eth + b"\0" * (60 - len(eth))                   # Ethernet minimum, no FCS


# ------------------------------------------------------------- what the run left
def read_log():
    """arp-run.log -> ({event: unix ms}, {'me', 'mac', 'gateway'})."""
    marks, who = {}, {}
    for line in open(os.path.join(OUT, "arp-run.log"), encoding="ascii", errors="replace"):
        m = re.match(r"(\d{13})\s+\S+\s+(.*)", line)
        if not m:
            continue
        ms, what = int(m.group(1)), m.group(2).strip()
        marks.setdefault(what, ms)
        i = re.search(r"me (\S+) mac (\S+) gateway (\S+)", what)
        if i:
            who = {"me": i.group(1), "mac": i.group(2).lower().replace("-", ":"), "gateway": i.group(3)}
    return marks, who


def read_table(name):
    """`arp -a` text -> {interface ip: [{'ip', 'mac', 'type'}]}"""
    tables, cur = {}, None
    for line in open(os.path.join(OUT, name), encoding="ascii", errors="replace"):
        m = re.match(r"Interface: (\S+)", line)
        if m:
            cur = tables.setdefault(m.group(1), [])
            continue
        m = re.match(r"\s+(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})?\s*(dynamic|static)", line)
        if m and cur is not None:
            cur.append({"ip": m.group(1), "mac": m.group(2) or "", "type": m.group(3)})
    return tables


def refill_first(me):
    """The first `arp -a -N me` snapshot after the clear: (seconds after clear, dynamic entries)."""
    path = os.path.join(OUT, "arp-refill-log.txt")
    if not os.path.exists(path):
        return None
    text = open(path, encoding="ascii", errors="replace").read()
    for block in re.split(r"=====\s*", text)[1:]:
        t = float(re.match(r"\+([\d.]+)", block).group(1))
        dyn = re.findall(r"(\d+\.\d+\.\d+\.\d+)\s+\S+\s+dynamic", block)
        return t, dyn
    return None


# --------------------------------------------------------------------- analysis
def main():
    if not os.path.exists(CAPTURE) and not os.path.exists(RAW):
        raise SystemExit("no out/arp.pcapng - run task2_arp.ps1 first (as Administrator)")
    source = RAW if os.path.exists(RAW) else CAPTURE
    frames = []
    for n, (lt, ts, units, data) in enumerate(read_pcapng(source), 1):
        f = dissect(lt, data)
        if f:
            f.update(n=n, ts_us=ts * 10 ** 6 // units, **arp_fields(f["arp"]))
            frames.append(f)
    if not frames:
        raise SystemExit(f"{source}: no ARP frames found")

    # pktmon's 802.11-labelled-as-Ethernet file -> keep it, write an Ethernet II one
    if source == CAPTURE and any(f["link"] == "802.11" for f in frames):
        os.replace(CAPTURE, RAW)
        write_ethernet_pcapng(CAPTURE, [(f["ts_us"], as_ethernet(f)) for f in frames],
                              "ARP frames captured by pktmon on Wi-Fi as 802.11 data frames, "
                              "rewritten as Ethernet II by task2_arp.py; original in "
                              "arp-pktmon-raw.pcapng")
        print("  out/arp.pcapng held 802.11 frames labelled Ethernet: kept as "
              "out/arp-pktmon-raw.pcapng, rewrote out/arp.pcapng as Ethernet II\n")

    marks, who = read_log()
    clear = marks["CLEAR"]
    my_mac = who["mac"]
    for f in frames:
        f["ms_after_clear"] = round(f["ts_us"] / 1000 - clear, 1)
        f["mine"] = f["sa"] == my_mac

    print(f"  {'#':>2} {'vs clear':>9}  {'destination MAC':<18} {'source MAC':<18} ARP")
    for f in frames:
        say = (f"who has {f['target_ip']}? tell {f['sender_ip']}" if f["op"] == "request"
               else f"{f['sender_ip']} is at {f['sender_mac']}")
        print(f"  {f['n']:>2} {f['ms_after_clear']:>+8.0f}ms  {f['da']:<18} {f['sa']:<18} {say}")

    # B1: my first request after the clear, and the reply to it
    after = [f for f in frames if f["ms_after_clear"] >= 0]
    req = next(f for f in after if f["mine"] and f["op"] == "request")
    rep = next(f for f in after if f["op"] == "reply" and f["ts_us"] >= req["ts_us"]
               and f["sender_ip"] == req["target_ip"] and f["da"] == my_mac)

    # The same question asked before and after the clear: was it broadcast?
    asked = {}
    for f in frames:
        if f["mine"] and f["op"] == "request":
            asked.setdefault(f["target_ip"], []).append(
                {"frame": f["n"], "ms_after_clear": f["ms_after_clear"],
                 "broadcast": f["da"] == BROADCAST})

    # Other machines' questions that reached me, and whether their answers did
    overheard = [f for f in frames if not f["mine"] and f["op"] == "request" and f["da"] == BROADCAST]
    for f in overheard:
        f["answer_seen"] = any(g["op"] == "reply" and g["sender_ip"] == f["target_ip"]
                               and g["da"] == f["sa"] for g in frames)

    # B4: one minute of capture
    start = marks.get("capture started", clear) * 1000
    minute = [f for f in frames if start <= f["ts_us"] < start + 60_000_000]
    bcast = [f for f in minute if f["da"] == BROADCAST]
    bcast_unforced = [f for f in bcast if f["ms_after_clear"] < 0 or f["ms_after_clear"] > 5000]

    # Part A from the text files
    before, after_t = read_table("arp-before.txt"), read_table("arp-after.txt")
    me = who["me"]
    count = lambda rows, kind=None: sum(1 for r in rows if kind is None or r["type"] == kind)
    first_back = refill_first(me)
    try:
        web = sorted({a[4][0] for a in socket.getaddrinfo(WEB, 443, socket.AF_INET)})
    except OSError:
        web = []
    after_ips = {r["ip"] for rows in after_t.values() for r in rows}
    wifi_net = ipaddress.ip_network(f"{me}/24", strict=False)

    result = {
        "capture": {"file": "out/arp.pcapng (Ethernet II)", "raw": "out/arp-pktmon-raw.pcapng",
                    "frames": len(frames), "link_as_captured": frames[0]["link"],
                    "seconds": round((frames[-1]["ts_us"] - frames[0]["ts_us"]) / 1e6, 1),
                    "my_ip": me, "my_mac": my_mac, "gateway": who["gateway"]},
        "A2": {"first_request_after_clear": {"frame": req["n"], "for": req["target_ip"],
                                             "ms_after_clear": req["ms_after_clear"]},
               "ms_before_my_ping": round(marks["ping gateway"] - clear - req["ms_after_clear"]),
               "first_refill_snapshot": {"s_after_clear": first_back[0], "dynamic": first_back[1]}
               if first_back else None},
        "A3": {iface: {"before": count(before.get(iface, [])),
                       "before_dynamic": count(before.get(iface, []), "dynamic"),
                       "after": count(after_t.get(iface, [])),
                       "after_dynamic": count(after_t.get(iface, []), "dynamic")}
               for iface in before},
        "A4": {"server": WEB, "addresses": web,
               "in_arp_after": sorted(set(web) & after_ips),
               "wifi_entries_outside_my_subnet": sorted(
                   r["ip"] for r in after_t.get(me, [])
                   if r["type"] == "dynamic" and ipaddress.ip_address(r["ip"]) not in wifi_net)},
        "B1": {"request": {k: req[k] for k in ("n", "ms_after_clear", "da", "sa", "op", "sender_ip",
                                               "target_ip", "target_mac")},
               "reply": {k: rep[k] for k in ("n", "ms_after_clear", "da", "sa", "op", "sender_ip",
                                             "sender_mac")},
               "reply_after_ms": round((rep["ts_us"] - req["ts_us"]) / 1000, 1)},
        "B2": {"request_destination": req["da"], "reply_destination": rep["da"],
               "reply_destination_is_me": rep["da"] == my_mac},
        "B3": {"my_requests_by_target": asked,
               "overheard_broadcasts": [{"frame": f["n"], "from": f["sender_ip"],
                                         "for": f["target_ip"], "answer_seen": f["answer_seen"]}
                                        for f in overheard]},
        "B4": {"frames_in_60s": len(minute), "broadcast": len(bcast),
               "broadcast_not_caused_by_clear": len(bcast_unforced),
               "unicast": len(minute) - len(bcast),
               "campus_machines_assumed": CAMPUS,
               "campus_frames_per_min": len(minute) * CAMPUS,
               "campus_broadcasts_per_s_each_machine_hears": round(len(bcast) * CAMPUS / 60, 1),
               "campus_broadcasts_per_s_steady": round(len(bcast_unforced) * CAMPUS / 60, 1)},
    }
    json.dump(result, open(os.path.join(OUT, "arp-analysis.json"), "w"), indent=2)

    b4 = result["B4"]
    print(f"""
  A2  first back: {req['target_ip']} - my request {req['ms_after_clear']:+.0f} ms after the clear,
      {result['A2']['ms_before_my_ping'] / 1000:.1f} s before I pinged anything
  A3  entries per interface, before -> after: """
          + ", ".join(f"{i} {v['before']}->{v['after']}" for i, v in result["A3"].items()) + f"""
  A4  {WEB} {', '.join(web) or '(could not resolve)'}: in the table? {bool(result['A4']['in_arp_after'])}
  B1  request frame {req['n']}, reply frame {rep['n']}, {result['B1']['reply_after_ms']} ms apart
  B2  request to {req['da']}, reply to {rep['da']} (me: {rep['da'] == my_mac})
  B3  broadcasts from others that reached me: {len(overheard)}, their answers seen: \
{sum(f['answer_seen'] for f in overheard)}
  B4  {b4['frames_in_60s']} ARP frames in 60 s ({b4['broadcast']} broadcast); x {CAMPUS:,} machines = \
{b4['campus_frames_per_min']:,}/min,
      {b4['campus_broadcasts_per_s_each_machine_hears']} broadcasts/s reaching every machine \
({b4['campus_broadcasts_per_s_steady']}/s without a clear)

  -> out/arp-analysis.json""")


if __name__ == "__main__":
    sys.exit(main())
