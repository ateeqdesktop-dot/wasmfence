# Security
WasmFence reads WAT as untrusted text, limits input to 10 MiB, never executes WebAssembly, and performs no network or host calls. It reports declared capabilities only; it does not prove runtime isolation.
