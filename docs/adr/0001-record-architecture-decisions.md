# 0001 — Record architecture decisions

Status: Accepted
Date: 2026-10-29

## Context

`SPEC.md` §2 lists the decisions the project is built on. Each was taken for a reason that is easy to
lose once the code exists, and several more will be forced on us by kernel interfaces and protocol
behaviour that only show up in the QEMU harness. A project with one small team and long gaps between
sessions needs those reasons written down where the code lives.

## Decision

A decision in SPEC §2 is changed only through an Architecture Decision Record in this directory, written
before the code that depends on the change. Discoveries about kernel interfaces and protocol quirks
(unsupported attributes, renamed options, workarounds) are recorded here as well.

Each record is `NNNN-title.md` with `Status`, `Date`, and the sections Context, Decision, Consequences.
Numbers are never reused; a superseded record keeps its file and gains `Status: Superseded by NNNN`.

## Consequences

Every reader of the code can find out why it is the way it is. The cost is a short document per
decision, which is the point.
