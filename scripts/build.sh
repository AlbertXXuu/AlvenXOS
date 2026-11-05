#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
export PATH="$HOME/.cargo/bin:$PATH"
export RUSTUP_TOOLCHAIN=nightly-2025-05-20
build_id=${ALVENX_BUILD_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}
[[ $build_id =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || { echo 'Invalid build ID' >&2; exit 2; }
mkdir -p "$root/build"
build="$root/build/$build_id"
mkdir "$build"
mkdir "$build/user"
exec > >(tee "$build/build.log") 2>&1
for app in workers bad_pointer protection_fault write_rx execute_stack yield_bench disk_a disk_b fd_read seek_read; do
    riscv64-linux-gnu-as -march=rv64gc -mabi=lp64d -o "$build/user/$app.o" "$root/user/$app.S"
    riscv64-linux-gnu-ld --no-relax --build-id=none -z max-page-size=4096 \
        -T "$root/user/linker.ld" -o "$build/user/$app.elf" "$build/user/$app.o"
done
python3 "$root/scripts/make_block_inputs.py" "$build/images"
python3 "$root/scripts/make_disk_inputs.py" "$build"
python3 "$root/scripts/make_fd_inputs.py" "$build"
python3 "$root/scripts/make_seek_inputs.py" "$build"
cd "$root"
python3 "$root/scripts/provenance.py" "$build"
export ALVENX_USER_DIR="$build/user"
export CARGO_TARGET_DIR="${ALVENX_TARGET_DIR:-$HOME/.cache/alvenx-native-target}"
export RUSTFLAGS="-C link-arg=-T$root/linker.ld -C relocation-model=static -C link-arg=--no-relax"
cargo build --locked --offline --release --target riscv64gc-unknown-none-elf
cp "$CARGO_TARGET_DIR/riscv64gc-unknown-none-elf/release/alvenx-core" "$build/alvenx.elf"
sha256sum "$build/alvenx.elf" "$build/inputs.json" "$build"/user/*.elf "$build"/images/* "$build"/blob/* "$build"/fd/* "$build"/seek/* > "$build/SHA256SUMS"
riscv64-linux-gnu-readelf -h -l "$build/alvenx.elf" > "$build/kernel-elf.txt"
printf '%s\n' "$build" > "$root/build/LAST_BUILD"
printf 'Build retained at %s\n' "$build"
