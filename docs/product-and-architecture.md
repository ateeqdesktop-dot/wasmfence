# WasmFence Product and Architecture

WasmFence turns explicit WebAssembly imports and exports into a reviewable capability contract. A bounded text loader extracts declarations, a pure policy engine compares them with allowed imports and required exports, and deterministic reporters produce CI-friendly output.

The MVP is offline, does not instantiate modules, and has no runtime authority. Future adapters can inspect binary modules with wasm-tools, support WASI/component imports, generate SARIF, and compare capability diffs between releases.
