#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
export PATH="$HOME/.cargo/bin:$PATH"
out=${1:?provide a new directory under native/results}
out=$(realpath -m -- "$out")
[[ $out == "$root/results/"* ]] || { echo 'Output must be under native/results' >&2; exit 2; }
mkdir "$out"
exec > >(tee "$out/command.log") 2>&1
rustc +nightly-2025-05-20 --version --verbose
rustc +nightly-2025-05-20 --test --edition=2024 "$root/src/transport_probe.rs" -o "$out/probe-tests"
"$out/probe-tests" --nocapture
sha256sum "$root/src/transport_probe.rs" "$root/scripts/test_transport_probe.sh" "$out/probe-tests" > "$out/SHA256SUMS"
