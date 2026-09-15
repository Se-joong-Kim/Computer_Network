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
    """A cache that respects the TTL it was given.

    Same interface: __init__(upstream), lookup(name, now) -> address, stats().

    What the baseline got wrong, in one sentence: it reads
    `address, ttl = self.upstream(name)` and then throws `ttl` away, keeping
    every record for a hard-coded 60 seconds instead. That single discarded
    variable is wrong in *both* directions - it serves the short-TTL names long
    after they died (the correctness bug: all 266 stale answers come from the
    two names whose TTL is under 60 s) and it discards the long-TTL names while
    they are still perfectly valid (the performance bug: 145 wasted round trips,
    including a 86400-second record refetched 20 times in one hour).

    So: one dict entry per name, holding the answer and the instant it dies.

        entries[name] = (address, expires_at)

    Expiry predicate is `now >= expires_at`, i.e. a record is served only on the
    half-open interval [fetched_at, fetched_at + ttl). Three reasons for the
    strict comparison:

    * It is what RFC 1035 means by "may be cached for TTL seconds" - at exactly
      fetched_at + ttl the record is dead, not dying.
    * The harness measures staleness externally with a non-strict test
      (`elif t > fresh_until[name]`), so it would tolerate the closed interval
      [f, f+ttl]. Serving only the half-open interval is a strict subset of what
      it tolerates, which makes zero stale answers true by construction rather
      than true by one character.
    * A TTL of 0 then means "do not cache" for free, which is what it is
      supposed to mean.

    On this workload it scores 275 upstream / 0 stale, and 275 is also the floor
    - no correct cache can do better. The argument is in out/observation.md.
    """

    def __init__(self, upstream):
        self.upstream = upstream      # upstream(name) -> (address, ttl)
        self.entries = {}             # name -> (address, expires_at)
        self.hits = 0
        self.misses = 0
        self.evictions = 0

    def lookup(self, name, now):
        """Return an address for `name`, asking upstream only if we have to."""
        entry = self.entries.get(name)                  # O(1), not a linear scan
        if entry is not None:
            address, expires_at = entry
            if now < expires_at:                        # still inside its own TTL
                self.hits += 1
                return address
            del self.entries[name]                      # dead: drop it, never serve it
            self.evictions += 1

        self.misses += 1
        address, ttl = self.upstream(name)
        if ttl > 0:                                     # TTL 0 means "do not cache"
            self.entries[name] = (address, now + ttl)
        return address

    def stats(self):
        total = self.hits + self.misses
        return {
            "hits": self.hits,
            "misses": self.misses,          # == upstream round trips made
            "evictions": self.evictions,    # records that died and were dropped
            "entries": len(self.entries),   # live records only, unlike the baseline's
            "hit_rate": self.hits / total if total else 0.0,
        }
