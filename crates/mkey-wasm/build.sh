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
