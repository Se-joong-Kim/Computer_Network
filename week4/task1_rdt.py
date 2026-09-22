#!/usr/bin/env python3
"""Week 4 · Task 1 — Build reliable delivery on top of an unreliable channel.

Textbook §3.4 (reliable data transfer) and §3.5 (TCP's sequence numbers).

`UnreliableChannel` below loses packets, reorders them, duplicates them, and
delays them. It is the network as §3.4 models it. Your job is to move a file
across it and have the bytes arrive intact and in order.

That is the whole of TCP's reliability story with the congestion control taken
out, and it is worth building once by hand before you ever trust a socket again.

    python3 task1_rdt.py --verify
"""
import argparse, hashlib, random

PAYLOAD = 8            # bytes per packet - small, so you see the sequencing


class UnreliableChannel:
    """Loses 10%, duplicates 3%, reorders, and delays. Deterministic by seed.

    You may not make it nicer. You may not read its internals. It is the only
    way your sender can reach your receiver.
    """

    def __init__(self, seed=246, loss=0.10, dup=0.03, reorder=0.10):
        self.rng = random.Random(seed)
        self.loss, self.dup, self.reorder = loss, dup, reorder
        self.wire = []          # packets in flight, in no particular order
        self.stats = {"sent": 0, "lost": 0, "duplicated": 0, "delivered": 0}

    def send(self, packet):
        """Hand a packet to the network. It may never come out."""
        self.stats["sent"] += 1
        if self.rng.random() < self.loss:
            self.stats["lost"] += 1
            return
        copies = 2 if self.rng.random() < self.dup else 1
        self.stats["duplicated"] += copies - 1
        for _ in range(copies):
            if self.rng.random() < self.reorder and self.wire:
                self.wire.insert(self.rng.randrange(len(self.wire)), packet)
            else:
                self.wire.append(packet)

    def receive(self):
        """Take the next packet out, or None if the network has nothing."""
        if not self.wire:
            return None
        self.stats["delivered"] += 1
        return self.wire.pop(0)


# --------------------------------------------------------------- packet format
# Packets go on the wire as bytes, the way they would on a real one, rather than
# as Python objects the two ends could accidentally share. Both kinds carry a
# sequence number, because every single thing that goes wrong on this channel is
# only detectable by looking at that number.
#
#   data packet   b"D" + seq(4, big-endian) + payload
#   ack packet    b"A" + seq(4, big-endian)
#
# There is no checksum: `UnreliableChannel` loses, duplicates, reorders and
# delays, but it never flips a bit, so a checksum here would be decoration that
# never fires. On a real link it would not be optional.

WINDOW = 16            # packets in flight - see observation.md for why 16
TIMEOUT = 24           # steps without an ACK before we assume it is gone


def pack_data(seq, payload):
    return b"D" + seq.to_bytes(4, "big") + payload


def pack_ack(seq):
    return b"A" + seq.to_bytes(4, "big")


def unpack(packet):
    """(kind, seq, payload), or None if this is not something we sent."""
    if not isinstance(packet, (bytes, bytearray)) or len(packet) < 5:
        return None
    kind = packet[:1]
    if kind not in (b"D", b"A"):
        return None
    return kind, int.from_bytes(packet[1:5], "big"), bytes(packet[5:])


class Sender:
    """A selective-repeat sliding-window sender.

    Why selective repeat rather than stop-and-wait or Go-Back-N: see
    observation.md. The short version is that this channel reorders, and
    reordering is exactly the case that punishes a cumulative-ACK protocol -
    Go-Back-N would discard correctly-arrived packets and resend them.

    State:
      unacked   seq -> the step number we last sent it on (for the timeout)
      acked     seqs the receiver has confirmed. A seq leaves `unacked` and
                enters `acked` exactly once; a second ACK for it is ignored,
                which is half of R3.
    """

    def __init__(self, data_channel, ack_channel, data):
        self.data_channel = data_channel
        self.ack_channel = ack_channel
        # R1: split into PAYLOAD-sized pieces and number them. The numbers are
        # packet indices rather than byte offsets; TCP counts bytes so that it
        # can re-segment, which we never need to do.
        self.packets = [data[i:i + PAYLOAD] for i in range(0, len(data), PAYLOAD)]
        self.total = len(self.packets)
        self.base = 0                  # lowest seq not yet acknowledged
        self.next_seq = 0              # lowest seq never yet sent
        self.unacked = {}              # seq -> step it was last (re)sent
        self.acked = set()
        self.t = 0                     # our clock: one tick per step()
        self.transmissions = 0         # every send, retransmissions included

    def step(self):
        """Do one unit of work. Return False when everything has been acked."""
        self.t += 1

        # 1. Collect whatever ACKs the network is willing to give us.
        while True:
            packet = self.ack_channel.receive()
            if packet is None:
                break
            parsed = unpack(packet)
            if parsed is None or parsed[0] != b"A":
                continue               # not an ACK - it is not ours to act on
            seq = parsed[1]
            if seq in self.unacked:
                del self.unacked[seq]
                self.acked.add(seq)
            # R3, half one: an ACK for a seq we already retired, or for a seq we
            # never sent, is simply dropped. Duplicates are common here (the
            # channel duplicates 3%) and a sender that advanced a counter per
            # ACK rather than per *distinct* seq would slide its window past
            # data that never arrived.

        # Slide the window over everything acknowledged so far.
        while self.base < self.total and self.base in self.acked:
            self.base += 1

        if self.base >= self.total:
            return False               # every packet is acknowledged - done

        # 2. Retransmit anything that has been silent too long (R4).
        for seq, sent_at in list(self.unacked.items()):
            if self.t - sent_at >= TIMEOUT:
                self._send(seq)

        # 3. Fill the window with new packets.
        while (self.next_seq < self.total
               and self.next_seq < self.base + WINDOW):
            if self.next_seq not in self.acked:
                self._send(self.next_seq)
            self.next_seq += 1

        return True

    def _send(self, seq):
        self.data_channel.send(pack_data(seq, self.packets[seq]))
        self.unacked[seq] = self.t
        self.transmissions += 1


class Receiver:
    """The matching selective-repeat receiver.

    It buffers out-of-order packets instead of dropping them, and it ACKs
    *every* data packet it sees - including ones it already has.

    That second point is the one that matters. If the receiver only ACKed
    packets that were new to it, a lost ACK would deadlock the transfer: the
    sender would retransmit forever and the receiver would silently discard
    each copy as a duplicate. Re-ACKing a duplicate is what lets a lost ACK
    recover.
    """

    def __init__(self, data_channel, ack_channel):
        self.data_channel = data_channel
        self.ack_channel = ack_channel
        self.buffer = {}               # seq -> payload, in whatever order
        self.delivered = bytearray()   # reassembled, in order
        self.expected = 0              # lowest seq not yet delivered
        self.received = 0              # data packets seen, duplicates included
        self.duplicates = 0

    def step(self):
        while True:
            packet = self.data_channel.receive()
            if packet is None:
                break
            parsed = unpack(packet)
            if parsed is None or parsed[0] != b"D":
                continue
            _, seq, payload = parsed
            self.received += 1

            # R3, half two: a data packet arriving twice must not corrupt the
            # output. Writing it into a dict keyed by seq is idempotent - the
            # second copy overwrites the first with identical bytes. Appending
            # to a list instead is the version that breaks, and it breaks
            # silently, producing a file that is too long rather than wrong.
            if seq in self.buffer or seq < self.expected:
                self.duplicates += 1
            else:
                self.buffer[seq] = payload

            # ACK it regardless of whether it was new (see the class docstring).
            self.ack_channel.send(pack_ack(seq))

        # R2: deliver in order, however scrambled the arrivals were.
        while self.expected in self.buffer:
            self.delivered += self.buffer.pop(self.expected)
            self.expected += 1

    def data(self):
        """The bytes reassembled so far."""
        return bytes(self.delivered)


# ------------------------------------------------------------------- harness
def verify(seed=246, size=2000, max_steps=200_000):
    original = bytes(random.Random(seed).getrandbits(8) for _ in range(size))
    up, down = UnreliableChannel(seed), UnreliableChannel(seed + 1)

    # Data goes out over `up`, ACKs come back over `down`. Both are unreliable.
    sender = Sender(up, down, original)
    receiver = Receiver(up, down)

    for _ in range(max_steps):
        alive = sender.step()
        receiver.step()
        if not alive and len(receiver.data() or b"") >= size:
            break

    got = receiver.data() or b""
    ok = hashlib.sha256(got).hexdigest() == hashlib.sha256(original).hexdigest()
    print(f"  bytes    sent {size}   received {len(got)}")
    print(f"  channel  {up.stats}")
    print(f"  result   {'IDENTICAL' if ok else 'CORRUPTED OR INCOMPLETE'}")
    return 0 if ok else 1


def selftest(size=2000, max_steps=200_000):
    """A stricter check than `verify`, for a reason worth knowing about.

    `verify` above builds its test data with

        bytes(random.Random(seed).getrandbits(8) for _ in range(size))

    which constructs a *new* Random(seed) on every iteration, so every byte
    comes out the same: for seed 246 the payload is 2000 copies of 0xed. SHA-256
    of that is invariant under permutation, so `verify` cannot tell a receiver
    that reassembles in order from one that appends whatever arrives. I confirmed
    that: a receiver that just appends passes the reordering case there.

    I have deliberately not patched `verify` - it is the stated pass condition
    and test_tasks.py calls it - so this runs the same transfer against data
    that is actually random, and against each impairment on its own so that a
    failure names its own cause.

        python task1_rdt.py --selftest
    """
    cases = [("loss only",      dict(loss=0.10, dup=0.00, reorder=0.00)),
             ("reordering only", dict(loss=0.00, dup=0.00, reorder=0.10)),
             ("duplication only", dict(loss=0.00, dup=0.03, reorder=0.00)),
             ("all three",      dict(loss=0.10, dup=0.03, reorder=0.10)),
             ("brutal (30% loss)", dict(loss=0.30, dup=0.10, reorder=0.30))]
    seeds = (246, 999, 1, 12345, 2026)
    print(f"\n  payload: {size} bytes of genuinely random data "
          f"(not verify()'s repeated byte)\n")
    print(f"  {'channel':<20}{'seeds ok':>10}{'sent':>8}{'min':>6}{'ratio':>8}")
    failures = 0
    for label, ch in cases:
        ok_count, sent_total, steps_total = 0, 0, 0
        for seed in seeds:
            rng = random.Random(seed)                   # one generator, reused
            original = bytes(rng.getrandbits(8) for _ in range(size))
            up, down = UnreliableChannel(seed, **ch), UnreliableChannel(seed + 1, **ch)
            sender, receiver = Sender(up, down, original), Receiver(up, down)
            for step in range(max_steps):
                alive = sender.step()
                receiver.step()
                if not alive and len(receiver.data() or b"") >= size:
                    break
            got = receiver.data() or b""
            ok_count += got == original
            sent_total += up.stats["sent"]
            steps_total += step
        minimum = -(-size // PAYLOAD)
        failures += len(seeds) - ok_count
        print(f"  {label:<20}{ok_count}/{len(seeds):<9}{sent_total // len(seeds):>8}"
              f"{minimum:>6}{sent_total / len(seeds) / minimum:>8.2f}x")
    print(f"\n  result   {'ALL IDENTICAL' if not failures else f'{failures} FAILURES'}\n")
    return 1 if failures else 0


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--verify", action="store_true")
    p.add_argument("--selftest", action="store_true",
                   help="stricter: real random data, one impairment at a time")
    p.add_argument("--seed", type=int, default=246)
    a = p.parse_args()
    if a.selftest:
        raise SystemExit(selftest())
    raise SystemExit(verify(a.seed) if a.verify else p.print_help())
