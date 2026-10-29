#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Andrew Newton
#
# Every tracked source file must carry the SPDX licence line within its
# first three lines. Prints the offenders and exits 1 if there are any.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
status=0
while IFS= read -r f; do
  [ -f "$f" ] || continue
  if ! head -n 3 "$f" | grep -q 'SPDX-License-Identifier: GPL-2.0-or-later'; then
    echo "missing SPDX header: $f"
    status=1
  fi
done < <(git ls-files -- '*.rs' '*.sh' '*.c' '*.h' 'Makefile' '**/Makefile')
exit "$status"
