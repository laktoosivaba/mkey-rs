# Vendored Virgil foundation

`libfoundation.wasm` is a WebAssembly build of
[virgil-crypto-c](https://github.com/VirgilSecurity/virgil-crypto-c)'s
`foundation` library, embedded in the crate with `include_bytes!` and driven
through wasmtime. It is what opens the Virgil container a SALTO mobile key
arrives in, and what generates the EC key pair a device registration needs —
that key has to come from Virgil's own implementation, because its key
provider rejects anything but the SEC1 shape it emits.

`wasm-map.txt` is the exported-symbol map that goes with it.

**Licence.** virgil-crypto-c is BSD-3-Clause, as declared by the upstream
distribution of the same library (`@virgilsecurity/core-foundation`, 2.1.0).

**Provenance.** This is a local emscripten build rather than the upstream
npm artifact — it is 457 841 bytes against that package's 592 456 — and the
source revision it was built from was not recorded. Treat it as
unreproducible: a rebuild will not be byte-identical, and there is nothing
here to diff it against.

**One deliberate edit.** The build embedded absolute paths from the machine
it was made on, as `__FILE__` strings in assertion messages — 175 of them,
carrying a home directory name. The 34-byte prefix was replaced in place with
`/build/vendor/virgil-crypto-c-src/`, which is the same length, so every
offset in the data section is unchanged. The file size is identical and the
six tests in this crate — which generate, wrap, import and export real keys
through this module — pass either way.
