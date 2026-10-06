#!/usr/bin/env python3
"""Week 6 · Task 2 Parts B and C — time OSPF reconvergence properly.

Runs on the Docker host (here: WSL Ubuntu, as root), against the three FRR
routers that `compose.yml --profile routing` brings up.

    python3 task2_ospf.py --out ../w06-routing/out

Why not just `scenario.sh cut`: that script decides "reconverged" the moment
r1's `show ip route ospf` text differs from what it was before the cut. That
text carries a per-route uptime counter ("..., weight 1, 00:01:23"), which
changes every second whether or not any route moved - so the script reports a
reconvergence of about one second no matter what the network does. This
measurement compares only the *structure* of each table - prefix, metric and
the set of next hops - and ignores the clock. It also watches all three
routers, not just r1, and times the repair as well as the break.

Events, in order:
  1  interface down   r1's net_b interface `ip link set down` (as scenario.sh)
  2  interface up     the same interface back up
  3  silent cut       r1's net_b link detached from its bridge on the host, so
                      both ends stay UP and the frames just stop arriving -
                      the failure only a hello timeout can reveal
  4  silent repair    re-attached
  5  cost change      r1's net_a cost 10 -> 100: a path moves, nothing fails
  6  cost restore     100 -> 10
"""
import argparse, json, os, re, subprocess, sys, threading, time

ROUTERS = ("r1", "r2", "r3")


# ------------------------------------------------------------------ plumbing
def run(*cmd, check=False):
    r = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True)
    if check and r.returncode:
        raise RuntimeError(f"{' '.join(cmd)}: {r.stderr.strip()}")
    return r.stdout


def container(service):
    name = run("docker", "ps", "--filter", f"label=com.docker.compose.service={service}",
               "--format", "{{.Names}}").strip().splitlines()
    if not name:
        raise SystemExit(f"no running container for {service} - is the lab up?")
    return name[0]


C = {}


def vtysh(r, *commands):
    args = ["docker", "exec", C[r], "vtysh"]
    for c in commands:
        args += ["-c", c]
    return run(*args)          # stdout only: vtysh's config-file warnings go to stderr


def rexec(r, *cmd):
    return run("docker", "exec", C[r], *cmd, check=True)


def addrs(r):
    """{iface: (addr, prefix_len)} inside a router."""
    out = {}
    for line in rexec(r, "ip", "-4", "-o", "addr").splitlines():
        m = re.search(r"\d+:\s+(\S+)\s+inet\s+([\d.]+)/(\d+)", line)
        if m and m.group(1) != "lo":
            out[m.group(1)] = (m.group(2), int(m.group(3)))
    return out


def net_of(addr, plen):
    a = sum(int(x) << (24 - 8 * i) for i, x in enumerate(addr.split(".")))
    m = (0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF
    n = a & m
    return f"{n >> 24}.{(n >> 16) & 255}.{(n >> 8) & 255}.{n & 255}/{plen}"


def structure(r):
    """What the table *says*, without when it said it: prefix -> (metric, next hops)."""
    try:
        data = json.loads(vtysh(r, "show ip route ospf json") or "{}")
    except json.JSONDecodeError:
        return None
    out = {}
    for prefix, routes in data.items():
        for rt in routes:
            hops = frozenset((nh.get("ip", "connected"), nh.get("interfaceName"))
                             for nh in rt.get("nexthops", []) if nh.get("active"))
            out[prefix] = (rt.get("metric"), hops)
    return out


def show(s):
    """A structure as readable text."""
    if s is None:
        return "?"
    parts = []
    for p in sorted(s):
        metric, hops = s[p]
        hop = " | ".join(sorted(f"{ip} {ifc}" if ip != "connected" else f"connected {ifc}"
                                for ip, ifc in hops)) or "-"
        parts.append(f"{p} [{metric}] {hop}")
    return "; ".join(parts)


# --------------------------------------------------------------- measurement
def watch(trigger, label, before, min_wait, settle=12.0, max_wait=150.0):
    """Fire `trigger`, then poll all three routers in parallel until every one
    has been unchanged for `settle` s (and at least `min_wait` s have passed).

    Returns per router: first time its structure left `before`, and the time it
    first reached the structure it ended on (and stayed). Times are seconds
    from just before the trigger command was issued.
    """
    samples = {r: [] for r in ROUTERS}
    stop = threading.Event()

    def poll(r):
        while not stop.is_set():
            s = structure(r)
            samples[r].append((time.monotonic() - t0, s))

    # "first change" is measured against the tables as they are at the trigger,
    # which after a cut is the cut state - not the original `before`.
    pre = {r: structure(r) for r in ROUTERS}
    t0 = time.monotonic()
    trigger()
    threads = [threading.Thread(target=poll, args=(r,), daemon=True) for r in ROUTERS]
    for t in threads:
        t.start()
    while True:
        time.sleep(0.5)
        now = time.monotonic() - t0
        if now > max_wait:
            break
        if now < min_wait:
            continue
        quiet = True
        for r in ROUTERS:
            seq = [s for _, s in samples[r] if s is not None]
            last = seq[-1] if seq else None
            changed_at = max((t for t, s in samples[r] if s != last), default=0.0)
            if now - changed_at < settle:
                quiet = False
        if quiet:
            break
    stop.set()
    for t in threads:
        t.join()

    result = {"event": label, "observed_s": round(time.monotonic() - t0, 1), "routers": {}}
    for r in ROUTERS:
        seq = [(t, s) for t, s in samples[r] if s is not None]
        final = seq[-1][1]
        first_change = next((t for t, s in seq if s != pre[r]), None)
        settled = next((t for i, (t, s) in enumerate(seq)
                        if all(s2 == final for _, s2 in seq[i:])), None)
        changes, prev = [], pre[r]
        for t, s in seq:
            if s != prev:
                changes.append({"t": round(t, 2), "table": show(s)})
                prev = s
        gaps = [b - a for (a, _), (b, _) in zip(seq, seq[1:])]
        result["routers"][r] = {
            "first_change_s": round(first_change, 2) if first_change is not None else None,
            "converged_s": round(settled, 2) if first_change is not None else None,
            "back_to_before": final == before[r],
            "samples": len(seq),
            "poll_interval_s": round(sum(gaps) / len(gaps), 2) if gaps else None,
            "final": show(final),
            "changes": changes,
        }
    return result


def snapshot(title):
    lines = [f"# {title}", f"# taken {time.strftime('%Y-%m-%d %H:%M:%S')}", ""]
    for r in ROUTERS:
        lines += [f"===== {r} : show ip route ospf =====",
                  vtysh(r, "show ip route ospf").rstrip(), ""]
    return "\n".join(lines) + "\n"


def wait_converged(reference=None, timeout=180):
    """Until every router has two FULL neighbours and (optionally) matches `reference`."""
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        full = all(vtysh(r, "show ip ospf neighbor").count("Full") >= 2 for r in ROUTERS)
        if full and (reference is None or all(structure(r) == reference[r] for r in ROUTERS)):
            return round(time.monotonic() - t0, 1)
        time.sleep(1)
    raise SystemExit("routers did not return to a converged state")


def host_veth(r, iface):
    """The host-side end of a container interface, and the bridge it is on."""
    peer = rexec(r, "cat", f"/sys/class/net/{iface}/iflink").strip()
    for line in run("ip", "-o", "link").splitlines():
        m = re.match(rf"^{peer}:\s+([^@:]+)", line)
        if m:
            veth = m.group(1)
            master = re.search(r"master (\S+)", line)
            return veth, master.group(1) if master else None
    raise SystemExit(f"host end of {r} {iface} not found")


# ----------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    if os.geteuid() != 0:
        raise SystemExit("run as root - the silent cut detaches a veth on the host")
    for r in ROUTERS:
        C[r] = container(r)

    # Name the three networks by what they connect, not by eth number:
    # Docker does not promise that eth0/eth1 follow compose.yml's order.
    ifs = {r: addrs(r) for r in ROUTERS}
    nets = {r: {net_of(*v): k for k, v in ifs[r].items()} for r in ROUTERS}
    def shared(x, y):
        return (set(nets[x]) & set(nets[y])).pop()
    NET = {"net_a": shared("r1", "r3"), "net_b": shared("r1", "r2"), "net_c": shared("r2", "r3")}
    r1_b, r1_a = nets["r1"][NET["net_b"]], nets["r1"][NET["net_a"]]
    veth, bridge = host_veth("r1", r1_b)

    print("  converging ...", flush=True)
    wait_converged()
    time.sleep(15)                                   # let DR/BDR and SPF timers settle
    before = {r: structure(r) for r in ROUTERS}
    timers = vtysh("r1", "show ip ospf interface")
    hello = re.search(r"Hello (\d+)s, Dead (\d+)s, Wait (\d+)s", timers).groups()

    # ---- the uptime column: why a text diff is not a reconvergence test
    t1 = vtysh("r1", "show ip route ospf")
    time.sleep(2.2)
    t2 = vtysh("r1", "show ip route ospf")
    uptime_diff = [(x, y) for x, y in zip(t1.splitlines(), t2.splitlines()) if x != y]
    same_structure = structure("r1") == before["r1"]

    with open(os.path.join(a.out, "route-before.txt"), "w") as fh:
        fh.write(snapshot("B1 - all three tables, converged, before any change"))
        fh.write("===== r1 : show ip ospf neighbor =====\n" + vtysh("r1", "show ip ospf neighbor"))
        fh.write("\n===== r1 : OSPF timers (FRR defaults - frr.conf does not set them) =====\n")
        fh.write("\n".join(l for l in timers.splitlines()
                           if re.search(r"^\S+ is |Timer intervals|Cost|Designated", l)) + "\n")
        fh.write("\n===== networks =====\n" + "\n".join(
            f"{n:<6} {p:<16} r1:{nets['r1'].get(p, '-'):<5} r2:{nets['r2'].get(p, '-'):<5} "
            f"r3:{nets['r3'].get(p, '-')}" for n, p in NET.items()) + "\n")

    events = []

    print(f"  1 interface down: r1 {r1_b} (net_b)", flush=True)
    e = watch(lambda: rexec("r1", "ip", "link", "set", r1_b, "down"),
              f"interface down - r1 {r1_b} (net_b) set down", before, min_wait=20)
    events.append(e)
    with open(os.path.join(a.out, "route-after.txt"), "w") as fh:
        fh.write(snapshot(f"B3 - all three tables after r1 {r1_b} (net_b) went down"))

    print("  2 interface up", flush=True)
    events.append(watch(lambda: rexec("r1", "ip", "link", "set", r1_b, "up"),
                        f"interface up - r1 {r1_b} (net_b) set up", before, min_wait=30))
    wait_converged(before)

    print(f"  3 silent cut: host {veth} off {bridge}", flush=True)
    events.append(watch(lambda: run("ip", "link", "set", veth, "nomaster", check=True),
                        f"silent cut - r1's net_b link detached from {bridge} on the host; "
                        f"both interfaces stay UP", before, min_wait=60))
    print("  4 silent repair", flush=True)
    events.append(watch(lambda: run("ip", "link", "set", veth, "master", bridge, check=True),
                        f"silent repair - re-attached to {bridge}", before, min_wait=60))
    wait_converged(before)

    print(f"  5 cost: r1 {r1_a} (net_a) 10 -> 100", flush=True)
    cost_before = snapshot("C2 - before r1 net_a cost 10 -> 100")
    e = watch(lambda: vtysh("r1", "configure terminal", f"interface {r1_a}", "ip ospf cost 100"),
              f"cost change - r1 {r1_a} (net_a) cost 10 -> 100, no link goes down",
              before, min_wait=20)
    events.append(e)
    cost_after = snapshot("C2 - after r1 net_a cost 10 -> 100")
    print("  6 cost restore", flush=True)
    events.append(watch(lambda: vtysh("r1", "configure terminal", f"interface {r1_a}",
                                      "ip ospf cost 10"),
                        f"cost restore - r1 {r1_a} (net_a) cost 100 -> 10", before, min_wait=20))
    with open(os.path.join(a.out, "cost-change.txt"), "w") as fh:
        fh.write(cost_before + "\n" + cost_after)

    # ---- reconverge.txt
    L = ["# Week 6 Task 2 - measured OSPF reconvergence (FRR 9.1.0, three routers)",
         f"# measured {time.strftime('%Y-%m-%d %H:%M:%S')} by task2_ospf.py",
         "",
         f"OSPF timers on every interface: Hello {hello[0]} s, Dead {hello[1]} s, "
         f"Wait {hello[2]} s (FRR defaults; frr.conf does not set them).",
         "Each router polled continuously in its own thread; 'converged' = first moment its "
         "table reached the state it then kept.",
         "Times are seconds from just before the trigger command; resolution is one poll "
         "(see interval per router).",
         "Only the table's structure is compared - prefix, metric, next hops - never the "
         "uptime column.",
         ""]
    L.append(f"{'event':<62} {'router':<6} {'first change':>13} {'converged':>10} {'poll':>6}")
    L.append("-" * 101)
    for e in events:
        for i, r in enumerate(ROUTERS):
            d = e["routers"][r]
            fc = "-" if d["first_change_s"] is None else f"{d['first_change_s']:.2f} s"
            cv = "unchanged" if d["converged_s"] is None else f"{d['converged_s']:.2f} s"
            L.append(f"{(e['event'] if i == 0 else ''):<62} {r:<6} {fc:>13} {cv:>10} "
                     f"{d['poll_interval_s']:>5}s")
        L.append("")
    L += ["Why scenario.sh's own timing cannot be trusted:",
          f"  two snapshots of r1's 'show ip route ospf' 2.2 s apart, with nothing changed "
          f"(structure identical: {same_structure}),",
          f"  differ in {len(uptime_diff)} line(s) - only the uptime counter:"]
    L += [f"    {x.strip()}\n    {y.strip()}" for x, y in uptime_diff[:2]]
    L.append("  scenario.sh compares exactly that text, so it reports 'reconverged' about a "
             "second after any cut.")
    with open(os.path.join(a.out, "reconverge.txt"), "w") as fh:
        fh.write("\n".join(L) + "\n")
    with open(os.path.join(a.out, "ospf-timeline.json"), "w") as fh:
        json.dump({"networks": NET, "r1_net_b": r1_b, "r1_net_a": r1_a,
                   "host_veth": veth, "bridge": bridge, "timers": hello,
                   "before": {r: show(before[r]) for r in ROUTERS},
                   "uptime_only_diff": uptime_diff, "events": events}, fh, indent=2)
    print("\n".join(L))


if __name__ == "__main__":
    main()
