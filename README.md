# WasmFence

Deterministic offline WebAssembly capability-policy auditor. Parses WAT import/export declarations and rejects forbidden host capabilities, missing required exports, or excessive import surface without executing the module.

```bash
python -m pip install .
wasmfence --format json --policy fixtures/policy.json fixtures/module.wat
```
Exit 0 is clean, 1 means findings, and 2 means invalid or oversized input. WasmFence complements wasm-tools: it is a repository-owned policy gate, not a runtime or vulnerability scanner.
