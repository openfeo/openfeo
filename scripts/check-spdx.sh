#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Andrew Newton
#
# Every tracked source file must carry the SPDX licence line within its
# first three lines, and every package.json under web/ must name the licence
# (JSON has no comments). Prints the offenders and exits 1 if there are any.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
status=0
# A git pathspec's `*` crosses directories, so `web/*.ts` is every .ts file under web/.
while IFS= read -r f; do
  [ -f "$f" ] || continue
  if ! head -n 3 "$f" | grep -q 'SPDX-License-Identifier: GPL-2.0-or-later'; then
    echo "missing SPDX header: $f"
    status=1
  fi
done < <(git ls-files -- '*.rs' '*.sh' '*.c' '*.h' 'Makefile' '**/Makefile' '*.proto' \
  'web/*.ts' 'web/*.vue' 'web/*.css' 'web/*.mjs' 'web/*.js' 'web/*.html' 'web/*.yaml')
while IFS= read -r f; do
  [ -f "$f" ] || continue
  if ! grep -q '"license": "GPL-2.0-or-later"' "$f"; then
    echo "missing licence field: $f"
    status=1
  fi
done < <(git ls-files -- 'web/package.json' 'web/*/package.json')
exit "$status"
