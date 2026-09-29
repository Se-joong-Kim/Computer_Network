#!/usr/bin/env python3
"""Week 5 · Task 1 — Subnets and longest-prefix match.

Textbook §4.3.2 (IPv4 addressing, CIDR) and §4.3.3 (forwarding).

Two things a router does with every packet: work out which prefixes the
destination falls inside, and pick the longest one. The second is the whole
of "longest prefix match", and it is the reason the internet's routing table
can hold a million entries and still be answerable.

You build both, from integers up. No `ipaddress` module - that library is
exactly the thing you are supposed to understand this week.

    python3 task1_forward.py --verify
"""
import argparse


# An address is 32 bits. Everything below is shifts and masks on that integer -
# no `ipaddress`, no `socket.inet_aton` (R6). The dotted quad is a display
# format; it is not what an address is.

def ip_to_int(address):
    """'192.168.0.1' -> 3232235521. Strict about what it accepts."""
    parts = address.strip().split(".")
    if len(parts) != 4:
        raise ValueError(f"not a dotted quad: {address!r}")
    value = 0
    for octet in parts:
        if not octet.isdigit():
            raise ValueError(f"octet {octet!r} is not a number in {address!r}")
        # '010' is 10 here but 8 in C and in some resolvers. Refuse it rather
        # than pick a side.
        if len(octet) > 1 and octet[0] == "0":
            raise ValueError(f"octet {octet!r} has a leading zero in {address!r}")
        n = int(octet)
        if n > 255:
            raise ValueError(f"octet {n} is above 255 in {address!r}")
        value = (value << 8) | n
    return value


def int_to_ip(value):
    """3232235521 -> '192.168.0.1'."""
    return (f"{(value >> 24) & 0xFF}.{(value >> 16) & 0xFF}."
            f"{(value >> 8) & 0xFF}.{value & 0xFF}")


def mask_for(prefix_len):
    """/24 -> 0xFFFFFF00. The special case is /0: shifting a 32-bit word by 32
    is undefined in C and merely surprising in Python, so it gets its own line."""
    if prefix_len == 0:
        return 0
    return (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF


def parse_cidr(cidr):
    """'163.152.6.0/24' -> (network as int, prefix length)."""
    if "/" not in cidr:
        raise ValueError(f"no prefix length in {cidr!r} - a CIDR block needs one")
    address, _, length = cidr.partition("/")

    # R1: the prefix length must be 0-32. `.isdigit()` also rejects '-1' and
    # '2.5' before int() would raise something less informative.
    if not length.strip().isdigit():
        raise ValueError(f"prefix length {length!r} is not a number in {cidr!r}")
    prefix_len = int(length)
    if prefix_len > 32:
        raise ValueError(f"prefix length {prefix_len} is outside 0-32 in {cidr!r}")

    value = ip_to_int(address)
    network = value & mask_for(prefix_len)

    # R2: 163.152.6.5/24 is how people write "this host, on that subnet". It is
    # a perfectly meaningful thing to say, but it is not a network, and letting
    # it through would mean a forwarding table whose entries do not mean what
    # they appear to. Name the network they probably meant.
    if value != network:
        raise ValueError(f"{cidr} has host bits set - "
                         f"the network is {int_to_ip(network)}/{prefix_len}")
    return network, prefix_len


def network_range(cidr):
    """'163.152.6.0/24' -> (first usable, last usable, broadcast).

    The textbook's "first usable and last usable" quietly assumes a prefix short
    enough to have a middle: one address at the bottom names the network, one at
    the top is the broadcast, and the hosts live between them. Two prefixes are
    too small for that, and they are handled explicitly rather than allowed to
    produce nonsense arithmetic:

      /32  a host route. One address, which is the host. No network address to
           reserve and nothing to broadcast to, so the third value is None.
      /31  RFC 3021. Point-to-point links wasted half of a /30 on a network and
           a broadcast address that two routers on a wire have no use for, so
           the RFC removed both: on a /31 *both* addresses are usable hosts and
           there is no broadcast. Hence (net, net+1, None).

    Returning None rather than inventing an address is the point - "there isn't
    one" is the true answer, and a plausible-looking address would be a lie.
    See out/observation.md.
    """
    network, prefix_len = parse_cidr(cidr)
    broadcast = network | (~mask_for(prefix_len) & 0xFFFFFFFF)

    if prefix_len == 32:
        return (int_to_ip(network), int_to_ip(network), None)
    if prefix_len == 31:
        return (int_to_ip(network), int_to_ip(network + 1), None)
    return (int_to_ip(network + 1), int_to_ip(broadcast - 1), int_to_ip(broadcast))


class ForwardingTable:
    """Longest-prefix-match forwarding.

    add(cidr, next_hop)  ·  lookup(address) -> next_hop or None

    Entries live in a dict keyed by (network, prefix_len). That is not for
    speed - with six entries a list would do, and Task 3 is where speed gets
    taken seriously - it is so that a duplicate prefix is detected for free.
    """

    def __init__(self):
        self.entries = {}                   # (network, prefix_len) -> next_hop

    def add(self, cidr, next_hop):
        network, prefix_len = parse_cidr(cidr)
        key = (network, prefix_len)
        # Two entries with the same prefix and different next hops is not a
        # tie to be broken - it is a malformed table, and silently keeping one
        # of them would hide the error at exactly the moment it matters. A real
        # router resolves this earlier, in the routing protocol, by preferring
        # the route with the better administrative distance or metric; by the
        # time a prefix reaches the forwarding table it is already unique.
        if key in self.entries and self.entries[key] != next_hop:
            raise ValueError(f"{cidr} is already in the table -> "
                             f"{self.entries[key]!r}, cannot also be {next_hop!r}")
        self.entries[key] = next_hop

    def lookup(self, address):
        """The next hop of the longest prefix that contains `address`."""
        value = ip_to_int(address)
        best_len, best_hop = -1, None
        for (network, prefix_len), next_hop in self.entries.items():
            if value & mask_for(prefix_len) == network and prefix_len > best_len:
                best_len, best_hop = prefix_len, next_hop
        # R5 needs no special case. 0.0.0.0/0 has prefix_len 0, which is the
        # smallest length there is, so any other match beats it by the ordinary
        # rule. The default route is not "the fallback" by fiat - it is the
        # entry that always matches and always loses.
        return best_hop


# ------------------------------------------------------------------- harness
RANGE_CASES = [
    ("192.168.0.0/24",  "192.168.0.1",   "192.168.0.254",  "192.168.0.255"),
    ("10.0.0.0/8",      "10.0.0.1",      "10.255.255.254", "10.255.255.255"),
    ("172.16.32.0/20",  "172.16.32.1",   "172.16.47.254",  "172.16.47.255"),
    ("203.0.113.64/26", "203.0.113.65",  "203.0.113.126",  "203.0.113.127"),
]

TABLE = [
    ("0.0.0.0/0",       "default-gw"),
    ("10.0.0.0/8",      "campus"),
    ("10.20.0.0/16",    "eng-building"),
    ("10.20.30.0/24",   "lab-floor"),
    ("10.20.30.64/26",  "lab-rack-2"),
    ("192.168.1.0/24",  "home"),
]

LOOKUP_CASES = [
    ("10.20.30.70",   "lab-rack-2"),     # inside all four 10.x entries
    ("10.20.30.10",   "lab-floor"),
    ("10.20.99.1",    "eng-building"),
    ("10.99.0.1",     "campus"),
    ("8.8.8.8",       "default-gw"),
    ("192.168.1.77",  "home"),
]


def verify():
    fails = 0
    for cidr, first, last, bcast in RANGE_CASES:
        try:
            got = network_range(cidr)
        except NotImplementedError:
            print("  network_range is still a stub"); return 1
        except Exception as e:
            print(f"  FAIL  {cidr:<18} raised {e!r}"); fails += 1; continue
        ok = tuple(got) == (first, last, bcast)
        print(f"  {'ok  ' if ok else 'FAIL'}  {cidr:<18} {got}")
        fails += not ok

    t = ForwardingTable()
    try:
        for cidr, hop in TABLE:
            t.add(cidr, hop)
    except NotImplementedError:
        print("  ForwardingTable is still a stub"); return 1

    for addr, expect in LOOKUP_CASES:
        got = t.lookup(addr)
        ok = got == expect
        print(f"  {'ok  ' if ok else 'FAIL'}  {addr:<16} -> {got}  (want {expect})")
        fails += not ok

    print(f"\n  {len(RANGE_CASES) + len(LOOKUP_CASES) - fails}"
          f"/{len(RANGE_CASES) + len(LOOKUP_CASES)} ok")
    return 1 if fails else 0


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--verify", action="store_true")
    a = p.parse_args()
    raise SystemExit(verify() if a.verify else p.print_help())
