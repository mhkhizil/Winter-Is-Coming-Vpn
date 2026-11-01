# ADR-0001 — Record architecture decisions

* Status: accepted
* Date: 2026-11-01
* Deciders: server team

## Context
This project has properties that are expensive to change later: the wire format,
the tenancy model, and where private keys live. Verbal decisions rot.

## Decision
Every structural decision is recorded as an ADR in this directory, using
`ADR-NNNN-short-title.md`, with: context, decision, consequences, rejected
alternatives. A PR that changes a constant in `vpn/wire/constants.hpp`, a table in
`server/migrations/`, or a dependency must add or amend an ADR in the same PR.
ADRs are immutable once accepted; a reversal is a new ADR that supersedes the old
one (and marks it `superseded by ADR-NNNN`).

## Consequences
* Slower for small changes, much faster for the expensive ones.
* New engineers can reconstruct *why* without archaeology in git history.
* Reviewers can refuse a change by pointing at an ADR instead of arguing.

## Alternatives rejected
* Commit messages only — not discoverable, get lost on squash-merge.
* A wiki — drifts from the code and has no review.
