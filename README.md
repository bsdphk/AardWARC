# AardWARC

## Museum-quality bit-archive storage management

This is a small, high-quality storage engine for saving files into,
and retrieving files out of permanent ISO 28500 compliant WARC silos.

This is only an storage engine, it supports little more than the
two operations "store this" and "get that", all the other aspects
of a proper bit-archive, access control, user interfaces,
data validation and so on must be provided elsewhere.

Each stored file gets assigned a WARC-Record-ID.  WARC records of
type "resource" uses the SHA256 sum of the stored file, and WARC
"metadata" records uses the SHA256 of the "WARC-Refers-To:" header
and the metadata file content.

An auxillary rebuildable index facilitates rapid access to individual
stored objects keyed by the WARC-Record-ID.

Almost the entire focus during development has been on correctness and
robustness, and presently FreeBSD is the only supported platform,
but porting it to other UNIX-like operating systems is expected to
require a trivial effort.  (Patches/Pulls are welcome).

One "test-application" called "stow" is built in, it makes very
neat deduplicated permanent personal archive.  In compliance with
the "dogfood" principle, I have all 217 Gigabytes of my personal
archive stored with "stow".

*phk*
