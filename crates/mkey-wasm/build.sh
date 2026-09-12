#!/usr/bin/env sh
# Build the wasm package.
#
#   ./build.sh [target] [out-dir]      target: web (default), nodejs, bundler
#
# cargo, wasm-bindgen and wasm-opt spelled out rather than left to wasm-pack:
# the size profile this crate needs is not one wasm-pack knows, and it then
# runs wasm-opt with its own flags, which do not validate this module.
set -eu

target=${1:-web}
out=${2:-pkg}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

# Panic messages carry the source path of whatever panicked, and those paths
# are data, not debug info — `strip` does not touch them. Unremapped they put
# the build machine's home directory, and the name of whatever crate registry
# it uses, inside an artifact that is committed and shipped.
cargo_home=${CARGO_HOME:-$HOME/.cargo}
rustup_home=${RUSTUP_HOME:-$HOME/.rustup}

# The registry source directories are named after the registry itself, which
# is below $CARGO_HOME and so not covered by remapping that — and the name of
# a private mirror has no business in a published artifact. Each one is
# mapped to the same generic path. No prefix here overlaps another: mapping
# $CARGO_HOME as a whole as well would be ambiguous, and every cargo path that
# reaches a panic message comes from a registry checkout anyway.
remap=""
for registry in "$cargo_home"/registry/src/*/; do
  [ -d "$registry" ] && remap="$remap --remap-path-prefix=$registry=/cargo/registry/"
done

# shellcheck disable=SC2086 -- $remap is a list of flags, word splitting is wanted
RUSTFLAGS="${RUSTFLAGS:-} $remap \
  --remap-path-prefix=$rustup_home=/rustup \
  --remap-path-prefix=$root=/build" \
cargo build -p mkey-wasm --target wasm32-unknown-unknown --profile wasm-release

wasm-bindgen \
  --target "$target" \
  --out-dir "$out" \
  --out-name mkey_wasm \
  "$root/target/wasm32-unknown-unknown/wasm-release/mkey_wasm.wasm"

wasm-opt -Oz \
  --enable-bulk-memory \
  --enable-bulk-memory-opt \
  --enable-nontrapping-float-to-int \
  "$out/mkey_wasm_bg.wasm" \
  -o "$out/mkey_wasm_bg.opt.wasm"
mv "$out/mkey_wasm_bg.opt.wasm" "$out/mkey_wasm_bg.wasm"

printf '%s\n' "----"
printf 'raw     %s bytes\n' "$(wc -c < "$out/mkey_wasm_bg.wasm" | tr -d ' ')"
printf 'gzip    %s bytes\n' "$(gzip -9 -c "$out/mkey_wasm_bg.wasm" | wc -c | tr -d ' ')"
if command -v brotli >/dev/null 2>&1; then
  printf 'brotli  %s bytes\n' "$(brotli -c -q 11 "$out/mkey_wasm_bg.wasm" | wc -c | tr -d ' ')"
fi
