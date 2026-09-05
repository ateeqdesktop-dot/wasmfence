# WasmFence

**Offline, deterministic WebAssembly capability-manifest gate.**

![CI](https://github.com/ateeqdesktop-dot/wasmfence/actions/workflows/ci.yml/badge.svg)

WasmFence reviews the declared imports and exports of a WebAssembly module before packaging or execution. It rejects forbidden host namespaces, undeclared capability imports, missing required exports, public-interface drift, and excessive import surfaces without loading a Wasm runtime or executing the module.

> WasmFence is an admission-policy gate, not a runtime sandbox, vulnerability scanner, or replacement for `wasm-tools`.

## Why it exists

A Wasm sandbox provides isolation, but the import boundary still describes what the host makes available to a module. Platform teams need a repository-owned policy that can be reviewed alongside a module or component manifest and enforced in CI before deployment. WasmFence keeps that decision local and deterministic.

## Features

| Capability | Behavior |
|---|---|
| Inputs | WAT import/export declarations or normalized JSON capability manifest |
| Import policy | Exact `module.name` allowlist and forbidden namespace denylist |
| Export policy | Required exports and optional public-interface allowlist |
| Surface control | Maximum import count |
| Output | Markdown, JSON schema v2, and SARIF 2.1.0 |
| Safety | 10 MiB bound, no Wasm execution, no runtime loading, no network |
| CI semantics | Exit `0` clean, `1` findings, `2` invalid or oversized input |

## Quick start

```bash
python -m pip install .
wasmfence --format markdown --policy fixtures/policy.json fixtures/module.wat
wasmfence --format json --policy fixtures/policy.json fixtures/module.wat > report.json
wasmfence --format sarif --policy fixtures/policy.json fixtures/module.wat > report.sarif
```

The policy is ordinary JSON and remains reviewable:

```json
{
  "allowed_imports": ["env.log"],
  "forbidden_modules": ["wasi_snapshot_preview1"],
  "required_exports": ["run"],
  "allowed_exports": ["run"],
  "max_imports": 8
}
```

A normalized manifest can be audited without a WAT parser:

```json
{
  "imports": [{"module": "env", "name": "log"}],
  "exports": ["run"]
}
```

## Architecture

```text
WAT or normalized manifest + policy JSON
                    |
             bounded local parser
                    |
             capability declaration
                    |
           deterministic policy engine
             /       |        \
       imports   exports   surface size
                    |
             stable findings + fingerprints
                    |
          Markdown / JSON / SARIF
                    |
                 CI exit code
```

WasmFence never instantiates a module, resolves imports, invokes an export, or asks a runtime to validate bytecode. The input is a declaration artifact. Runtime sandbox configuration remains the responsibility of the deployment platform.

## Security model and limitations

Modules and manifests are untrusted input. The parser uses bounded local reads and a narrow declaration grammar. A clean report means only that the declared boundary satisfies the selected policy; it does not prove memory safety, absence of malicious logic, component-model type correctness, or runtime isolation. Operators should pair WasmFence with a runtime such as Wasmtime and supply-chain verification appropriate to their threat model.

## Development

```bash
python -m pip install -e . pytest ruff
pytest -q
ruff check wasmfence.py tests
python -m compileall -q wasmfence.py
```

## Roadmap

Future work may add signed capability manifests, WIT/component interface normalization, policy diffs across releases, and optional adapters around `wasm-tools`. Execution and network access will remain explicit external integrations.

## License

MIT. See [LICENSE](LICENSE).
