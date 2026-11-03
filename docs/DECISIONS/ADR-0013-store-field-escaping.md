# ADR-0013 — The store log escapes user text at the write choke point

- **Status**: accepted, 2026-11-03
- **Context**: `Store` is an append-only log of tab-separated, newline-terminated
  records (`U`, `D`, `P`, `S`, `G`, `X`, `T`, `R`). Replay rebuilds all state from it.
  Several fields originate as API input.
- **Decision**: user-controlled text is percent-escaped on write and unescaped per
  field on read, in one place — `append_line`/`replay` in `server/src/api/store.cpp`.
  `%`→`%25`, LF→`%0A`, CR→`%0D`; TAB stays structural. Input is additionally validated
  at the API boundary (printable, bounded length) so mistakes get a `400` rather than a
  silently transformed value.
- **Why escaping is not optional**: a device `name` containing `\nU\t…\tadmin` used to
  write a *forged account* into the log, which replay then honoured — an authenticated
  user could become an administrator, permanently. Verified end to end, then fixed;
  `scripts/verify-log-injection.ps1` keeps it fixed.
- **Why at the choke point**: escaping at call sites would be forgotten by the next
  record kind. One encoder on the way out, one decoder on the way in, and every current
  and future field is covered by construction.
- **Why percent-encoding**: it is reversible, human-inspectable in a tail, costs O(1)
  per byte, and unknown `%` sequences decode to themselves — so a log written before
  this ADR replays byte-identically.
- **Alternatives considered**: (a) JSON-lines — better, but rewrites the format, every
  reader and the compaction path, and loses the cheap `field[5]` parsing the hot replay
  loop relies on; (b) rejecting only at the boundary — leaves `Store` unsafe for any
  other caller, including future admin tooling; (c) length-prefixed fields — unreadable
  in a log and needs a parser on read.
- **Consequences**: the log stays greppable, records stay one line each, and `Store` is
  now safe for any caller. Cost: a field containing `%` grows by 2 bytes per literal.
