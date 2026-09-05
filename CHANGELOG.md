# Changelog

## [1.0.0] - 2026-09-05

WasmFence now ships as a capability-manifest gate for WebAssembly modules. The release adds normalized JSON manifest input, forbidden import namespaces, public export allowlists, schema v2 reports, SARIF 2.1.0 output, and stable fingerprints. The implementation remains offline and never instantiates or executes Wasm.

CI now covers Python 3.10, 3.11, and 3.12, WAT and manifest inputs, linting, compile checks, and exit-code/report-schema semantics.

## [0.1.0]

Initial deterministic WAT import/export capability-policy auditor.
