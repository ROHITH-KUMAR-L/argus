#!/usr/bin/env bash
# Regenerate the x86_64 syscall table from the host kernel headers.
set -euo pipefail
hdr=${1:-/usr/include/asm/unistd_64.h}
out=crates/policy-model/src/syscalls_x86_64.rs
{
  echo "//! x86_64 syscall name/number table generated from Linux $(uname -r | cut -d. -f1-2) \`asm/unistd_64.h\`."
  echo '//! Regenerate with `scripts/gen_syscalls.sh` when changing the supported kernel baseline.'
  echo
  echo 'pub const SYSCALLS_X86_64: &[(&str, u32)] = &['
  grep '#define __NR_' "$hdr" | awk '{sub("__NR_","",$2); printf "    (\"%s\", %s),\n", $2, $3}'
  echo '];'
} > "$out"
echo "wrote $out"
