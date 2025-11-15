# Implementation Plan (Phased)

- Phase 0 — Workspace Scaffolding [DONE]
  - Create workspace and all crates per spec with minimal code that compiles.
  - Add server and CLI wiring with Ephemeral storage.
  - Acceptance: `cargo build --workspace` succeeds; `gitmem serve --backend ephemeral` starts.

- Phase 1 — Core Model Finalization
  - Validate Memory invariants (id immutability, timestamps monotonicity, allowed types).
  - Add constructors and simple validation errors; prefer `?` and typed errors.
  - Wire stable MCP error codes in a shared mapping module (proto/server boundary).
  - Acceptance: Unit tests for validation; error code mapping table exists.

- Phase 2 — JSON-RPC (stdio) Vertical Slice
  - Implement stdio transport using `jsonrpsee` server.
  - Handlers: `memory.save`, `memory.get`, `memory.delete` against Ephemeral.
  - Add tracing spans; return typed MCP errors (`E_*`).
  - Acceptance: Integration test that calls handlers end-to-end with Ephemeral.

- Phase 3 — Local Storage Adapter
  - Atomic JSON write: temp file → fsync → rename; serde round-trip.
  - Layout: `memories/YYYY/MM/DD/<id>.json`; basic manifest (`meta/MANIFEST.json`).
  - File locks via `fs4`; implement soft delete and optional hard delete.
  - Acceptance: Round-trip tests; crash-safety simulated tests; manifest-driven `list_recent_ids`.

- Phase 4 — Search Index (milli-core default)
  - Engine: milli-core (embedded LMDB) for primary indexing with a memory fallback when LMDB fails to open; keep real Tantivy behind an opt-in feature.
  - Schema: `title` boosted, `content`, `tags`, `type`, `created_at`, `updated_at`, `score`.
  - Implement `update`, `delete`, `search` with BM25 and filters; enforce TTL at query time.
  - Rebuild-on-start if checksum differs; incremental updates on writes.
  - Acceptance: Search unit tests; TTL enforcement; relevance sanity checks.

- Phase 5 — Server: Storage+Index Integration
  - In handlers: write to storage, then update index; delete handles tombstones.
  - Add `memory.search` handler with query mapping; add `memory.update` patching logic.
  - Capabilities announced on initialize; resource list/read for debug.
  - Acceptance: End-to-end tests for save/search/update/delete; resource read returns JSON.

- Phase 6 — GitHub Adapter (gix + optional Contents API)
  - Local clone management (bare or working), device branches, batch commits.
  - `spawn_blocking` for heavy git operations; rate limiting; conflict artifact flow.
  - Optional Contents API fallback via `octocrab` for constrained environments.
  - Acceptance: Contract tests pass for both local and GitHub modes; conflict scenario test produces artifact.

- Phase 7 — CLI and Importer
  - Implement `import` (JSON/JSONL autodetect), mapping via `compat`, dedupe by hash/id.
  - Progress reporting with `indicatif`; batch writes; dry-run mode.
  - Config loader (`config` crate), env overrides, `.env` support; add sample configs in `examples/`.
  - Acceptance: Import large JSONL fixture; report summary; config-driven runs.

- Phase 8 — Crypto (age X25519)
  - Implement encryption/decryption of `title` and `content`; multiple recipients.
  - Redaction in logs; `memory.encrypt`/`memory.decrypt` admin tools.
  - Acceptance: Round-trip tests; deterministic results for identical inputs; no plaintext leaks in logs.

- Phase 9 — Compatibility & Conformance
  - Golden fixtures under `crates/testing/fixtures/compat_basic/`; snapshot tests with `insta`.
  - Ensure parameter schemas parity; capability flags reflect encryption/index availability.
  - Acceptance: Conformance suite passes; snapshots stable.

- Phase 10 — WebSocket Transport & Health
  - Add WS mode with Axum; `/healthz` endpoint; OpenTelemetry optional.
  - Acceptance: WS smoke test; health returns `{ok:true, storage: <mode>}`.

- Phase 11 — CI, Audit, Release
  - Workflows: `ci.yml`, `audit.yml`, `release.yml`, `update-lock.yml` per spec.
  - Matrix builds (Linux/macOS, targets); `cargo audit` and `cargo deny`.
  - Release tags `server-vX.Y.Z`, `cli-vX.Y.Z`; Docker image to GHCR.
  - Acceptance: CI green on matrix; automated release on tag.

- Phase 12 — Benchmarks & Perf Tuning
  - `criterion` benches: save/search/import on 1k/10k/50k datasets.
  - Targets: save p50 < 5 ms local; search p95 < 50 ms on 50k.
  - Acceptance: Bench results documented; regressions gated.

- Phase 13 — Docs & ADRs
  - Update `docs/`, ADRs, examples, CHANGELOG; PR template ready.
  - Acceptance: Docs cover deployment, config, security, and migration; examples runnable.

# Cross-Cutting Concerns

- Error Codes
  - Map typed errors to MCP codes: `E_NOT_FOUND`, `E_VALIDATION`, `E_RATE_LIMIT`, `E_CONFLICT`, `E_ENCRYPTION`, `E_STORAGE_IO`.
- Concurrency
  - Use `tokio` multi-thread; `spawn_blocking` for git/index heavy ops; bounded semaphores for rate limiting.
- Security
  - Secrets from env/keychain; no plaintext content logs when encryption enabled; least-privilege GitHub scopes.
- MSRV & Lints
  - Enforce `RUSTFLAGS=-D warnings`, `clippy -- -D warnings -D clippy::pedantic -A clippy::module_name_repetitions`.

# Milestone Grouping (Suggested)

- M1: Phases 1–2 (stdio vertical slice with Ephemeral)
- M2: Phases 3–5 (Local storage + search index + full handlers)
- M3: Phase 6–7 (GitHub adapter + Importer + Config)
- M4: Phase 8–9 (Crypto + Conformance)
- M5: Phase 10–11 (WS + CI/Release)
- M6: Phase 12–13 (Perf + Docs/ADRs)
