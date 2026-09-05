# WasmFence — Product and Architecture

## Product vision

WasmFence is a local admission gate for WebAssembly capability declarations. It helps platform teams review the host surface promised to a module before packaging or execution, while keeping policy evaluation deterministic and offline.

## Problem and users

A WebAssembly module is isolated only within the capabilities exposed by its host. Imports therefore become a security and operability contract. Platform engineers, security reviewers, and maintainers need that contract in version control rather than relying on runtime defaults or manual review.

## Functional contract

| Area | v1.0 behavior |
|---|---|
| Input | WAT import/export declarations or normalized JSON manifest |
| Imports | Exact allowlist and forbidden namespace denylist |
| Exports | Required exports and optional public-interface allowlist |
| Surface | Maximum import count |
| Output | Markdown, JSON schema v2, SARIF 2.1.0 |
| Exit codes | 0 clean, 1 findings, 2 invalid or oversized input |

## Component architecture

```text
WAT / normalized manifest + repository policy
                    |
             bounded local parser
                    |
             capability declaration
                    |
           deterministic policy engine
           /          |             \
      import ACL   export ACL    surface bound
                    |
          stable findings + fingerprints
                    |
       Markdown / JSON / SARIF serializers
                    |
                 CI exit code
```

The parser reads declarations only. WasmFence never instantiates a module, resolves imports, invokes an export, or loads a runtime. A deployment platform remains responsible for Wasmtime or another runtime, resource limits, signature verification, and supply-chain controls.

## Data and error flow

Unreadable paths, malformed JSON, missing manifest arrays, invalid policy values, and oversized input return exit code 2. A valid declaration with policy findings returns the complete report and exit code 1. Stable finding fingerprints make the same policy violation comparable across CI runs.

## Security model

Inputs are untrusted. The implementation uses a bounded local read and a narrow WAT declaration grammar. It performs no network, DNS, subprocess, dynamic module loading, or Wasm execution. A clean report only means the declared import/export surface satisfies the selected policy; it does not prove memory safety, component-model type correctness, absence of malicious logic, or runtime isolation.

## Performance and extensibility

Parsing and policy evaluation are linear in input size and declaration count, with a 10 MiB bound. The normalized manifest boundary can later accept WIT/component interfaces, signed manifests, and capability diffs without changing finding semantics. SARIF is a projection of the same deterministic report and introduces no new authority.

## Roadmap

Future versions may add signed capability manifests, WIT normalization, release-to-release policy diffs, and optional adapters around `wasm-tools`. Runtime execution and network access will remain explicit external integrations.

## References

[1]: https://webassembly.org/docs/security/ "WebAssembly security model"
[2]: https://github.com/bytecodealliance/wasm-tools "Bytecode Alliance wasm-tools"
[3]: https://www.w3.org/TR/webassembly-component-model/ "WebAssembly Component Model"
