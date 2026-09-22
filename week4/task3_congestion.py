#!/usr/bin/env python3
"""Week 4 · Task 3 — Beat the fixed window.

Textbook §3.7.

`FixedWindow` is a sender that never adapts. It picks a window and keeps it,
forever, no matter what the network says back. It is not a strawman: it is what
you get if you skip congestion control entirely, and it was the internet's
actual failure mode in October 1986.

Write `YourControl` and beat it on the harness:

    python3 bench.py
    python3 bench.py --yours

The interface is two events and one number:

    .window        how many packets you are willing to have in flight
    .on_ack()      one packet made it there and back
    .on_loss()     a packet was dropped, or timed out waiting for its ACK

That is all the information a real TCP sender has. It cannot see the queue,
it cannot see the link rate, and neither can you. You infer them from these
two events, which is the entire idea of §3.7.
"""


class FixedWindow:
    """Send 64 packets at a time and never listen."""

    def __init__(self):
        self.window = 64

    def on_ack(self):
        pass

    def on_loss(self):
        pass


class YourControl:
    """Slow start, then AIMD with a deliberately gentle decrease.

    Three decisions, in the order they matter.

    **1. Where the window has to end up.**  The link drains 1 packet per slot
    and the round trip is 20 slots, so the pipe holds BDP = 1 x 20 = 20 packets.
    Below 20 in flight the link literally runs dry and goodput falls in
    proportion. Above 20 the surplus is not speed, it is queue: at a window of
    W the standing queue is W - 20, which is delay handed to every other flow
    on the link. So the window wants to sit *just above* 20 - high enough never
    to starve the link, low enough that the queue stays short. That target, not
    the backoff rule, is what decides the score.

    **2. Therefore the decrease factor is not 1/2.**  Loss here only appears
    when in-flight exceeds 20 + 10 = 30, so the window peaks around 32. Textbook
    Reno halves: 32 -> 16, which is *below* BDP, so after every loss the link
    idles while the window climbs back. That is precisely why plain AIMD scores
    ~87% here. The constraint is

        beta * W_peak  >=  BDP        ->   beta >= 20/32 = 0.625

    Anything gentler than that and the sender never stops filling the pipe.
    Pushing beta the other way is limited by the average queue: mean window is
    roughly (1 + beta)/2 * W_peak, and the requirement mean queue <= 5 caps it
    near beta = 0.72. I measured the whole curve (it is in observation.md);
    0.70 sits inside both bounds with margin on each, and scores 97% of the
    baseline's goodput at an average queue of 4.6.

    **3. A burst of timeouts is one congestion event, not twenty.**  When the
    queue overflows it usually drops several packets at once, and this harness
    calls on_loss() once per timed-out packet - sometimes several in the same
    slot. Reducing on each of them would divide the window by beta^n and
    collapse it. Real TCP reduces at most once per RTT; with no clock here, the
    stand-in for "an RTT has passed" is "a window's worth of ACKs has arrived
    since the last reduction".
    """

    BETA = 0.70               # multiplicative decrease - see (2) above
    INITIAL_SSTHRESH = 24.0   # leave slow start a little above BDP
    MIN_WINDOW = 2.0

    def __init__(self):
        self.window = 1.0
        self.ssthresh = self.INITIAL_SSTHRESH
        self.acks_since_cut = 0
        # Bookkeeping, for observation.md rather than for the algorithm.
        self.cuts = 0
        self.ignored_losses = 0

    def on_ack(self):
        self.acks_since_cut += 1
        if self.window < self.ssthresh:
            # Slow start: one extra packet per ACK, so the window doubles every
            # round trip. This is the "grow differently before your first loss"
            # phase - it is about finding the pipe quickly, not about fairness.
            self.window += 1.0
        else:
            # Congestion avoidance: +1 packet per round trip. Additive increase
            # is the half of AIMD that makes competing flows converge to a fair
            # share; probing any faster would just refill the queue.
            self.window += 1.0 / self.window

    def on_loss(self):
        # One reduction per congestion event (3). Until a full window of ACKs
        # has come back, further timeouts are the same overflow still draining.
        if self.acks_since_cut < self.window:
            self.ignored_losses += 1
            return

        self.ssthresh = max(self.MIN_WINDOW, self.window * self.BETA)
        self.window = self.ssthresh          # no slow start after a loss;
                                             # we already know roughly where
                                             # the pipe is, so re-probing from
                                             # 1 would only starve the link
        self.acks_since_cut = 0
        self.cuts += 1
