#!/usr/bin/env python3
"""Week 3 · Task 3 — Beat the baseline cache.

Textbook §2.4.2 (caching) and §2.4.3 (TTL).

`BaselineCache` below works. It is also bad, in more than one way, and one of
its problems is worse than being slow. Find them, write `YourCache`, and prove
the improvement with the harness:

    python3 bench.py                 # baseline only
    python3 bench.py --yours         # baseline vs. yours, side by side

Rules
-----
* Do not change `bench.py`. If you need to change it to win, you are not
  winning. Say so in observation.md instead.
* `YourCache` must expose the same two methods as `BaselineCache`.
* Speed is not the only score. The harness also counts **stale answers** -
  times you served a record whose TTL had already run out. A cache that keeps
  everything forever is very fast and completely wrong.

Targets
-------
The baseline scores **325 upstream queries, 67.5% hit rate, 266 stale answers**.

  pass  : zero stale answers
  good  : zero stale, and no more upstream queries than the baseline
  strong: the above, plus you can say in observation.md **how few upstream
          queries a correct cache could possibly make on this workload, and
          why you cannot go below that number**

That last one is the real question. Read it before you start optimising -
it will tell you where to stop.
"""
import time


class BaselineCache:
    """A DNS cache that somebody wrote in a hurry.

    It caches. It is not correct, and it is not fast. Both are your problem.
    """

    FIXED_LIFETIME = 60          # seconds we keep anything, regardless of TTL

    def __init__(self, upstream):
        self.upstream = upstream  # upstream(name) -> (address, ttl)
        self.entries = []         # list of [name, address, stored_at]

    def lookup(self, name, now):
        """Return an address for `name`, asking upstream only if we have to."""
        for entry in self.entries:                      # linear scan
            if entry[0] == name:
                if now - entry[2] < self.FIXED_LIFETIME:
                    return entry[1]
                self.entries.remove(entry)
                break
        address, ttl = self.upstream(name)
        self.entries.append([name, address, now])
        return address

    def stats(self):
        return {"entries": len(self.entries)}


class YourCache:
    """A cache that keeps each record for exactly as long as it is allowed to.

    The baseline has two faults and they share one root cause: it throws the
    TTL away and substitutes FIXED_LIFETIME = 60 s for every record.

      * correctness - any record whose TTL is under 60 s is served after it
        expired.  www.microsoft.com (TTL 20) is the worst of them: for 40 of
        every 60 seconds the baseline hands out a record it no longer has the
        right to hold.  That is where the 266 stale answers come from.
      * performance - any record whose TTL is over 60 s is thrown away early.
        dns.google (TTL 86400) needs exactly one fetch in a one-hour workload;
        the baseline refetches it every minute it is asked for.

    The linear scan over self.entries is a third fault, but it is the cheap
    one: it costs CPU, not correctness and not round trips.

    So: store the expiry the authority actually gave us, and index by name.

        name -> (address, expires_at)

    Freshness test is `now < expires_at`, strictly.  A record whose TTL runs
    out exactly now is expired, not fresh - the TTL counts the seconds the
    answer may be *used*, and at t = expires_at that budget is spent.
    """

    def __init__(self, upstream):
        self.upstream = upstream
        self.entries = {}         # name -> (address, expires_at)
        self.hits = 0
        self.misses = 0           # first time we ever saw the name
        self.refetches = 0        # we had it, its TTL had run out

    def lookup(self, name, now):
        entry = self.entries.get(name)
        if entry is not None:
            address, expires_at = entry
            if now < expires_at:
                self.hits += 1
                return address
            self.refetches += 1
        else:
            self.misses += 1
        address, ttl = self.upstream(name)
        self.entries[name] = (address, now + ttl)
        return address

    def stats(self):
        return {"entries": len(self.entries), "hits": self.hits,
                "misses": self.misses, "refetches": self.refetches}


# --------------------------------------------------------------------- floor
# Task 3 R5.  How few upstream queries could *any* correct cache make here?
#
# An answer fetched at time t is valid on [t, t + ttl) and nowhere else.  A
# cache that never serves an expired record must therefore cover every query
# time for a name with intervals of length ttl.  Covering a set of points with
# fixed-length intervals takes fewest intervals when each interval is placed as
# far left as it may go while still covering the leftmost uncovered point -
# and "fetch only when nothing valid is held" places them exactly there.
# Fetching earlier only slides the window left and loses coverage on the right,
# so no cache does better, not even one that knows the whole future workload.
#
# Which is the point: the floor is set by the TTLs, not by the data structure.
# There is nothing to be clever about.  Run this to reproduce the number:
#
#     python3 task3_cache.py --floor
#
# It imports bench.py read-only for the fixture and the workload; it does not
# modify the harness.

def floor():
    """The fewest upstream queries any correct cache could make."""
    from bench import FIXTURE, QUERIES, RTT_MS, workload

    expires, fetches = {}, {}
    queries = {}
    for t, name in workload():
        queries[name] = queries.get(name, 0) + 1
        if t >= expires.get(name, -1):                  # nothing valid held
            fetches[name] = fetches.get(name, 0) + 1
            expires[name] = t + FIXTURE[name][1]

    total = sum(fetches.values())
    print(f"\n  floor {total} upstream queries   "
          f"hit rate {(QUERIES - total) / QUERIES:.1%}   "
          f"sim time {total * RTT_MS / 1000:.1f}s\n")
    print(f"  {'name':<21}{'ttl':>7}{'queries':>9}{'fetches':>9}   "
          f"{'why':<28}")
    for name, (_, ttl) in FIXTURE.items():
        n = fetches.get(name, 0)
        why = ("asked more often than its TTL lives" if n > 20 else
               "TTL outlives the whole workload" if ttl >= 3600 else
               "")
        print(f"  {name:<21}{ttl:>7}{queries.get(name, 0):>9}{n:>9}   {why}")
    print(f"\n  No correct cache goes below {total}: each fetch buys exactly "
          f"ttl seconds of\n  validity, and these are the fewest such windows "
          f"that cover every query.\n")
    return total


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--floor", action="store_true",
                   help="the lower bound any correct cache is held to")
    if p.parse_args().floor:
        floor()
    else:
        p.print_help()
