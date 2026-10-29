# 0005 — Copyright holder

Status: Accepted
Date: 2026-10-29

## Context

Under a pure GPL licence with DCO sign-off (ADR-0002) the copyright notice is only a notice, but it
has to be consistent across every file, and the candidates were a person and two companies.

## Decision

Every source file carries `Copyright (C) 2026 Andrew Newton`. The year is the year the file was
created; later edits do not change it.

## Consequences

One string, checked for by eye in review and easy to grep for. Contributors keep their own copyright
in the files they author, as the DCO implies.
