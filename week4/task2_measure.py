#!/usr/bin/env python3
"""Week 4 · Task 2 — Measure your own link, more than once.

Textbook §3.5 (handshake, sequence numbers) and §3.7 (what limits throughput).

This is the hands-on task. The number it produces is about *your* connection at
*this* moment, and it will not be the same as anybody else's, or as your own an
hour from now. That is the finding, not a problem with the measurement.

    python3 task2_measure.py --label "campus wifi"
    python3 task2_measure.py --label "tethering"

Each run appends to out/throughput.json so you can compare them later.
"""
import argparse, json, os, statistics, struct, subprocess, time

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")

# A few hundred KB from a host that is not next door. Change it if it dies -
# and if you do, say so in observation.md, because the distance is part of
# what you are measuring.
TARGET = "https://speed.cloudflare.com/__down?bytes=5000000"
REPEATS = 5


def one_run():
    """One transfer. Returns (seconds, bytes, curl's own timing breakdown)."""
    fmt = "%{time_namelookup} %{time_connect} %{time_starttransfer} %{time_total} %{size_download}"
    r = subprocess.run(
        ["curl", "-s", "-o", os.devnull, "-w", fmt, TARGET],
        capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout.strip():
        raise RuntimeError(f"curl failed: {r.stderr.strip() or r.returncode}")
    dns, conn, first, total, size = (float(x) for x in r.stdout.split())
    return {
        "dns_s": dns,
        "connect_s": conn - dns,        # this is your TCP handshake
        "ttfb_s": first - conn,
        "total_s": total,
        "bytes": int(size),
        "mbps": int(size) * 8 / total / 1e6 if total else 0,
    }


# ============================================================ Part A · analysis
# Wireshark, tshark and Npcap could not be installed on this machine, and
# Windows' built-in pktmon needs administrator rights we do not have. So this
# reads the capture directly: pcapng blocks, Ethernet, IPv4, TCP and the TCP
# option list, in about 150 lines of struct.unpack.
#
#     python task2_measure.py --analyze out/tcp.pcapng

TCP_FLAGS = [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"),
             (0x10, "ACK"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR")]


def parse_tcp_options(raw):
    """The SYN's option list. This is where MSS, window scale and SACK live."""
    opts, i = [], 0
    while i < len(raw):
        kind = raw[i]
        if kind == 0:                                   # End of option list
            opts.append(("EOL", None)); break
        if kind == 1:                                   # No-op, used as padding
            opts.append(("NOP", None)); i += 1; continue
        if i + 1 >= len(raw):
            break
        length = raw[i + 1]
        if length < 2 or i + length > len(raw):
            break
        body = raw[i + 2:i + length]
        if kind == 2 and len(body) == 2:
            opts.append(("MSS", struct.unpack("!H", body)[0]))
        elif kind == 3 and len(body) == 1:
            opts.append(("WindowScale", body[0]))
        elif kind == 4:
            opts.append(("SACKPermitted", True))
        elif kind == 5:
            opts.append(("SACK", len(body) // 8))
        elif kind == 8 and len(body) == 8:
            opts.append(("Timestamps", struct.unpack("!II", body)))
        else:
            opts.append((f"kind{kind}", body.hex()))
        i += length
    return opts


def read_pcapng(path):
    """Yield (frame_number, timestamp_seconds, frame_bytes). Pure stdlib."""
    raw = open(path, "rb").read()
    off, n, endian, tsresol = 0, 0, "<", 6
    while off + 12 <= len(raw):
        btype = struct.unpack(endian + "I", raw[off:off + 4])[0]
        if btype == 0x0A0D0D0A:                         # Section Header Block
            if raw[off + 8:off + 12] == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif raw[off + 8:off + 12] == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            btype = struct.unpack(endian + "I", raw[off:off + 4])[0]
        total = struct.unpack(endian + "I", raw[off + 4:off + 8])[0]
        if total < 12 or off + total > len(raw):
            break
        if btype == 0x00000001:                         # Interface Description
            body, o = raw[off + 16:off + total - 4], 0  # skip linktype/reserved/snaplen
            while o + 4 <= len(body):                   # option list: if_tsresol is 9
                code, olen = struct.unpack(endian + "HH", body[o:o + 4])
                if code == 0:
                    break
                if code == 9 and olen >= 1:
                    tsresol = body[o + 4]
                o += 4 + olen + ((-olen) % 4)
        elif btype == 0x00000006:                       # Enhanced Packet Block
            hi, lo, caplen = struct.unpack(endian + "III", raw[off + 12:off + 24])
            ticks = (hi << 32) | lo
            ts = ticks / (2 ** (tsresol & 0x7F) if tsresol & 0x80 else 10 ** tsresol)
            n += 1
            yield n, ts, raw[off + 28:off + 28 + caplen]
        off += total


def dissect(frame):
    """Ethernet -> IPv4 -> TCP. Returns a dict, or None if it is not TCP/IPv4."""
    if len(frame) < 34 or struct.unpack("!H", frame[12:14])[0] != 0x0800:
        return None
    ihl = (frame[14] & 0x0F) * 4
    if frame[14 + 9] != 6:                              # protocol 6 = TCP
        return None
    ip_total = struct.unpack("!H", frame[16:18])[0]
    src = ".".join(str(b) for b in frame[26:30])
    dst = ".".join(str(b) for b in frame[30:34])
    t = 14 + ihl
    if len(frame) < t + 20:
        return None
    sport, dport, seq, ack = struct.unpack("!HHII", frame[t:t + 12])
    off_flags, window = struct.unpack("!HH", frame[t + 12:t + 16])
    doff = (off_flags >> 12) * 4
    flags = off_flags & 0x1FF
    options = parse_tcp_options(frame[t + 20:t + doff]) if doff > 20 else []
    payload_len = max(0, ip_total - ihl - doff)
    return {"src": src, "dst": dst, "sport": sport, "dport": dport,
            "seq": seq, "ack": ack, "window": window, "doff": doff,
            "flags": flags, "options": dict(options), "payload": payload_len,
            "flagstr": "".join(n for b, n in TCP_FLAGS if flags & b) or "-",
            "data": frame[t + doff:t + doff + payload_len]}


def analyze(path):
    """Answer A2-A5 from a capture, without tshark."""
    if not os.path.exists(path):
        print(f"  no capture at {path}")
        return 1

    packets = []
    for n, ts, frame in read_pcapng(path):
        d = dissect(frame)
        if d:
            d["n"], d["t"] = n, ts
            packets.append(d)
    if not packets:
        print("  no TCP/IPv4 packets found")
        return 1

    # --- find a connection whose three-way handshake is fully captured
    syns = [p for p in packets if p["flags"] & 0x02 and not p["flags"] & 0x10]
    chosen = None
    for syn in syns:
        key = (syn["src"], syn["sport"], syn["dst"], syn["dport"])
        synack = next((p for p in packets
                       if p["n"] > syn["n"] and p["flags"] & 0x12 == 0x12
                       and p["src"] == key[2] and p["sport"] == key[3]
                       and p["dst"] == key[0] and p["dport"] == key[1]), None)
        if not synack:
            continue
        ack = next((p for p in packets
                    if p["n"] > synack["n"] and p["flags"] & 0x10
                    and not p["flags"] & 0x02
                    and p["src"] == key[0] and p["sport"] == key[1]
                    and p["dst"] == key[2] and p["dport"] == key[3]), None)
        if ack:
            chosen = (syn, synack, ack, key)
            break
    if not chosen:
        print("  no complete three-way handshake in this capture")
        return 1
    syn, synack, ack, key = chosen
    client = (key[0], key[1])
    server = (key[2], key[3])

    flow = [p for p in packets
            if {(p["src"], p["sport"]), (p["dst"], p["dport"])} == {client, server}]
    c2s = [p for p in flow if (p["src"], p["sport"]) == client]
    s2c = [p for p in flow if (p["src"], p["sport"]) == server]

    # --- A5: what the receiver advertised, against what was ever in flight
    cscale = 2 ** syn["options"].get("WindowScale", 0)
    sscale = 2 ** synack["options"].get("WindowScale", 0)
    scaled_server = [p["window"] * sscale for p in s2c if not p["flags"] & 0x02]
    scaled_client = [p["window"] * cscale for p in c2s if not p["flags"] & 0x02]

    # bytes the client had outstanding: highest byte sent minus highest acked
    highest_ack, inflight_peak, at_frame = syn["seq"] + 1, 0, None
    acks = {p["n"]: p["ack"] for p in s2c if p["flags"] & 0x10}
    seen_ack = syn["seq"] + 1
    for p in flow:
        if (p["src"], p["sport"]) == server and p["flags"] & 0x10:
            seen_ack = max(seen_ack, p["ack"])
        elif (p["src"], p["sport"]) == client and p["payload"]:
            outstanding = (p["seq"] + p["payload"]) - seen_ack
            if outstanding > inflight_peak:
                inflight_peak, at_frame = outstanding, p["n"]

    bytes_c2s = sum(p["payload"] for p in c2s)
    bytes_s2c = sum(p["payload"] for p in s2c)
    duration = flow[-1]["t"] - flow[0]["t"]

    print(f"\n  capture   {os.path.basename(path)}   "
          f"{len(packets)} TCP packets, {len(syns)} SYNs")
    print(f"  flow      {client[0]}:{client[1]}  <->  {server[0]}:{server[1]}")
    print(f"            {len(flow)} packets, {duration:.2f} s, "
          f"{bytes_c2s:,} bytes up / {bytes_s2c:,} bytes down\n")

    print("  A2 · the three-way handshake")
    for label, p in (("SYN", syn), ("SYN-ACK", synack), ("ACK", ack)):
        print(f"     frame {p['n']:>4}  {label:<8} {p['src']}:{p['sport']} -> "
              f"{p['dst']}:{p['dport']}  [{p['flagstr']}]  "
              f"seq={p['seq']} ack={p['ack']}  t={p['t'] - syn['t']:+.6f}s")
    print(f"     handshake took {ack['t'] - syn['t']:.6f} s "
          f"({(ack['t'] - syn['t']) * 1000:.2f} ms)")

    print("\n  A3 · initial sequence numbers (raw, as they appear on the wire)")
    print(f"     client ISN   {syn['seq']:>12}   (0x{syn['seq']:08x})")
    print(f"     server ISN   {synack['seq']:>12}   (0x{synack['seq']:08x})")
    print(f"     difference   {abs(syn['seq'] - synack['seq']):>12}")
    print(f"     the SYN-ACK acknowledges {synack['ack']} = client ISN + 1 "
          f"({'correct' if synack['ack'] == syn['seq'] + 1 else 'MISMATCH'})")

    print("\n  A4 · options carried on the SYN")
    for who, p, scale in (("client SYN    ", syn, cscale),
                          ("server SYN-ACK", synack, sscale)):
        o = p["options"]
        print(f"     {who}  MSS={o.get('MSS', '-')}  "
              f"WindowScale={o.get('WindowScale', 'absent')} (x{scale})  "
              f"SACKPermitted={'yes' if o.get('SACKPermitted') else 'no'}  "
              f"Timestamps={'yes' if 'Timestamps' in o else 'no'}")
        print(f"                      raw window field = {p['window']}")

    print("\n  A5 · advertised window vs bytes actually in flight")
    if scaled_server:
        print(f"     server advertised (scaled x{sscale}):  "
              f"min {min(scaled_server):,}  median "
              f"{int(statistics.median(scaled_server)):,}  max {max(scaled_server):,} bytes")
    if scaled_client:
        print(f"     client advertised (scaled x{cscale}):  "
              f"min {min(scaled_client):,}  median "
              f"{int(statistics.median(scaled_client)):,}  max {max(scaled_client):,} bytes")
    print(f"     client's peak bytes unacknowledged: {inflight_peak:,} bytes "
          f"(frame {at_frame})")
    if scaled_server:
        pct = inflight_peak / max(scaled_server) * 100
        print(f"     -> the sender filled {pct:.1f}% of the window the receiver offered")
        print(f"     -> so the receive window was NOT the limit; "
              f"something else was (see observation.md)")

    print("\n  path (B) · whose transfer is this, from the capture alone")
    payloads = b"".join(p["data"] for p in c2s[:6])
    head = payloads[:400].decode("latin-1", "replace").split("\r\n")
    for line in head[:8]:
        if line.strip():
            print(f"     | {line[:100]}")
    mss = syn["options"].get("MSS")
    print(f"     client {client[0]} is an RFC1918 private address behind NAT"
          if client[0].startswith(("192.168.", "10.", "172.")) else
          f"     client {client[0]} is a public address")
    print(f"     client MSS {mss} -> MTU {mss + 40 if mss else '?'} "
          f"({'standard Ethernet' if mss == 1460 else 'not plain Ethernet'})")

    meta = {
        "capture": os.path.basename(path),
        "flow": {"client": f"{client[0]}:{client[1]}",
                 "server": f"{server[0]}:{server[1]}",
                 "packets": len(flow), "duration_s": round(duration, 3),
                 "bytes_up": bytes_c2s, "bytes_down": bytes_s2c},
        "A2": {"syn_frame": syn["n"], "synack_frame": synack["n"],
               "ack_frame": ack["n"],
               "handshake_ms": round((ack["t"] - syn["t"]) * 1000, 3)},
        "A3": {"client_isn": syn["seq"], "server_isn": synack["seq"],
               "synack_acks": synack["ack"]},
        "A4": {"client": {k: v for k, v in syn["options"].items() if k != "Timestamps"},
               "server": {k: v for k, v in synack["options"].items() if k != "Timestamps"},
               "client_window_raw": syn["window"], "server_window_raw": synack["window"]},
        "A5": {"client_scale": cscale, "server_scale": sscale,
               "server_advertised_max": max(scaled_server) if scaled_server else None,
               "server_advertised_median": int(statistics.median(scaled_server))
               if scaled_server else None,
               "peak_bytes_inflight": inflight_peak, "peak_at_frame": at_frame},
    }
    with open(os.path.join(OUT, "capture-analysis.json"), "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)
    print(f"\n  -> out/capture-analysis.json")
    return 0


TRACE_ZIP = "https://www-net.cs.umass.edu/wireshark-labs/wireshark-traces-9e.zip"
TRACE_NAME = "tcp-wireshark-trace1-1.pcapng"
ATTRIBUTION = """\
Wireshark lab trace files from J.F. Kurose and K.W. Ross,
Computer Networking: A Top-Down Approach, 9th ed.
https://gaia.cs.umass.edu/kurose_ross/
Copyright 1996-2025 J.F. Kurose, K.W. Ross. All Rights Reserved."""


def fetch_trace():
    """Restore out/tcp.pcapng from the authors' site.

    The trace is not committed to this repository: it is the textbook authors'
    material, marked All Rights Reserved, and their site is the origin. One
    command puts it back.
    """
    import io, urllib.request, zipfile
    dest = os.path.join(OUT, "tcp.pcapng")
    os.makedirs(OUT, exist_ok=True)
    print(f"  fetching {TRACE_ZIP}")
    with urllib.request.urlopen(TRACE_ZIP, timeout=300) as r:
        blob = r.read()
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        with z.open(TRACE_NAME) as src, open(dest, "wb") as out:
            out.write(src.read())
    print(f"  -> {dest}  ({os.path.getsize(dest):,} bytes)\n")
    print(ATTRIBUTION)
    return 0


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--label",
                   help='where you are, e.g. "campus wifi" or "tethering"')
    p.add_argument("--fetch-trace", action="store_true",
                   help="download the official lab trace to out/tcp.pcapng")
    p.add_argument("--repeats", type=int, default=REPEATS)
    p.add_argument("--analyze", nargs="?", const=os.path.join(OUT, "tcp.pcapng"),
                   metavar="PCAPNG",
                   help="answer A2-A5 from a capture (default out/tcp.pcapng)")
    a = p.parse_args()
    os.makedirs(OUT, exist_ok=True)
    if a.fetch_trace:
        raise SystemExit(fetch_trace())
    if a.analyze:
        raise SystemExit(analyze(a.analyze))
    if not a.label:
        p.error("--label is required when measuring")

    runs = []
    for i in range(a.repeats):
        r = one_run()
        runs.append(r)
        print(f"  {i + 1}/{a.repeats}  {r['mbps']:7.2f} Mbps   "
              f"handshake {r['connect_s'] * 1000:6.1f} ms   "
              f"ttfb {r['ttfb_s'] * 1000:6.1f} ms")
        time.sleep(1)

    mbps = [r["mbps"] for r in runs]
    record = {
        "label": a.label,
        "when": time.strftime("%Y-%m-%d %H:%M:%S"),
        "target": TARGET,
        "runs": runs,
        "mbps_median": statistics.median(mbps),
        "mbps_min": min(mbps),
        "mbps_max": max(mbps),
        "handshake_ms_median": statistics.median(
            r["connect_s"] * 1000 for r in runs),
    }

    path = os.path.join(OUT, "throughput.json")
    all_records = json.load(open(path)) if os.path.exists(path) else []
    all_records.append(record)
    json.dump(all_records, open(path, "w"), indent=2)

    spread = (max(mbps) - min(mbps)) / statistics.median(mbps) if mbps else 0
    print(f"\n  {a.label}:  median {record['mbps_median']:.2f} Mbps, "
          f"spread {spread:.0%} across {a.repeats} runs")
    print(f"  handshake median {record['handshake_ms_median']:.1f} ms")
    print(f"  -> out/throughput.json  ({len(all_records)} record(s) so far)")


if __name__ == "__main__":
    main()
