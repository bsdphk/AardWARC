# Architectural notes about AardWARC

Some of the architectural decisions in AardWARC are very
counter-intuitive, and therefore worthy of an explanation.

## Permanence

Because AardWARC is written for digital collections in museums,
permanence is the topmost priority.

The WARC/ISO-28500 file format goes a long way in this respect,
both in terms of documentation and built in integrity checks.

What AardWARC brings to the table in this respect is mostly auditing
and index rebuild facilities, so that the WARC files alone define
the storage, with the index just being an adjunct access speed-up.

## Scaling

Museums never throw anything out and therefore AardWARC stores
are unbounded in size, both in terms of items and bytes.

As far as storing objects go, WARC/ISO-28500 has that down pat,
but retrieving objects is a different matter.

One can, as a last resort, read all the WARC files sequentially
to find something, but in day to day usage, an index is required.

I decided against SQLite3 as index-engine because it is 273KLOC
where AardWARC is barely 8KLOC, it would truly be the tail wagging
the dog.

Berkeley DB is a more reasonable 13KLOC, but Oracle owns the project
which means that relying on it in the long term is not indicated.

Technically even Berkeley DB would be overkill because each indexed
object is born with a well behaved, and well distributed, long
random(-ish) unique key, and we never delete anything.

The implemented AardWARC index consists of two parts, a sorted list
of 16 byte entries, and an unsorted "appendix" containing the most
recently written items.

Because the keys are well distriuted, lookups in the sorted index
can go almost directly to the entry from the WARC-ID (see comments
at the top of index.c for the "almost" part) and if not found there,
the "appendix" is small enough to read sequentially.

When adding new items only an atomic and robust append write to
the "index.appendix" file is required.

Periodically, a "housekeeping" operation sorts the appendix and
merges it with the sorted index to a new sorted index.

At some point, the sorted index file will grow too big, at which time
it will be split into multiple files, based on a prefix of the
WARC-ID bits but this is not yet implemented.

*phk*
