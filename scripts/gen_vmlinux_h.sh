#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail

OUT="${1:-build/vmlinux.h}"

mkdir -p "$(dirname "$OUT")"

if [[ ! -e /sys/kernel/btf/vmlinux ]]; then
  echo "ERROR: /sys/kernel/btf/vmlinux not found. Your kernel may lack BTF."
  echo "       Enable CONFIG_DEBUG_INFO_BTF=y or install a kernel with BTF."
  exit 1
fi

bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$OUT"
echo "Wrote $OUT"
