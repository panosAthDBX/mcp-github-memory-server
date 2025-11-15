
# AGENTS.md

Authoring guide for humans and coding agents working on the **MCP GitHub Memory Server**. This file defines guard‑rails, architecture boundaries, crate layout, dependency policy, version constraints, coding standards, CI rules, and checklists for common changes.

> Scope: Rust workspace that implements an MCP server with GitHub and Local storage adapters, a search index, optional encryption, and a CLI. See the main technical spec for behaviour and protocols.

---

## 1. Non‑negotiables

* Preserve MCP tool and schema compatibility with the basic memory surface.
* No blocking calls in async contexts.
* Every public type has `Debug` and `serde` derives as appropriate.
* All new code must compile with `RUSTFLAGS="-D warnings"` and pass `clippy -- -D warnings -D clippy::pedantic -A clippy::module_name_repetitions`.
* Tests, benches, and docs must pass on Linux x86_64, Linux aarch64, macOS arm64, macOS x86_64.
* Minimum Supported Rust Version (MSRV): **1.89.0** (stable as of 2025-08). We pin the toolchain to the latest stable in `rust-toolchain.toml`. New code may rely on features available in this compiler.

---

## 2. Workspace layout

```
./
├─ Cargo.toml                 # workspace with members and shared metadata
├─ rust-toolchain.toml        # pins toolchain channel and components
├─ crates/
│  ├─ core/                   # domain model, validation, merge, ID, TTL
│  ├─ proto/                  # MCP protocol glue, tool schemas, json-rpc types
│  ├─ storage/
│  │  ├─ github/              # GitHub adapter (git2 or gix + octocrab)
│  │  ├─ local/               # Local FS adapter
│  │  └─ ephemeral/           # In-memory adapter for tests
│  ├─ index/
│  │  ├─ tantivy/             # milli-core (LMDB) index by default; optional Tantivy behind feature
│  │  └─ sqlite/              # Optional SQLite FTS5 index (removed in this cycle)
│  ├─ crypto/                 # age-based envelope, key handling
│  ├─ server/                 # MCP server runtime (stdio and websocket)
│  ├─ cli/                    # `gitmem` command line
│  ├─ compat/                 # Basic-memory importers and API shims
│  ├─ testing/                # test utilities, fixtures, property tests
│  └─ benchmarks/             # Criterion performance benchmarks (save/search/import)
├─ .github/workflows/         # CI, audit, release
├─ docs/                      # design docs, ADRs, diagrams
└─ examples/                  # sample configs and scripts
```

**Separation rules**

* `core` has zero async and zero IO. It may depend on `serde`, `uuid`, `chrono`, and error types.
* `proto` contains JSON schemas and MCP surface types. It does not talk to storage or index.
* `storage/*` implement a `Storage` trait from `core`. They own IO and network concerns.
* `index/*` implement an `Index` trait. No storage coupling. Feed it full `Memory` structs.
* `crypto` provides a thin encrypt or decrypt façade. It does not call storage.
* `server` wires `proto` + `storage` + `index` + `crypto` using async runtimes.
* `cli` depends on `server` for long‑running modes and calls `compat` for imports.

---

## 3. Versioning policy and crate constraints

We prefer **major‑line constraints** with caret requirements in `Cargo.toml`. Examples below are expressed as major lines to avoid churn. Lockfile pins exact versions. CI runs a scheduled lockfile refresh and audit.

* Rust edition: `2021` for now. Prepare for `2024` edition migration in a future cycle.
* MSRV: `1.89.0`.

### 3.1 Core dependencies by crate

**crates/core**

```toml
[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "1"
chrono = { version = "0.4", default-features = false, features = ["std", "clock"] }
uuid = { version = "1", features = ["v4", "serde"] }
regex = "1"
```

**crates/proto**

```toml
[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
jsonrpsee = { version = "0.2", features = ["http-client", "ws-client", "server", "macros"] }
schemars = "0.8"
```

**crates/storage/github**

```toml
[dependencies]
octocrab = { version = "0.3" }
# Choose one git backend. Prefer pure-Rust `gix` where feasible.
gix = { version = "0.6", default-features = false, features = ["blocking-http-client","gitoxide-core"] }
# If you need libgit2 features use git2 instead.
# git2 = { version = "0.18" }
tracing = "0.1"
async-trait = "0.1"
```

**crates/storage/local**

```toml
[dependencies]
tokio = { version = "1", features = ["fs", "rt-multi-thread", "macros", "io-util", "time"] }
tracing = "0.1"
fs4 = "0.7" # file locks
```

**crates/index/tantivy**

```toml
[dependencies]
tantivy = "0.2"           # optional, behind the `real_tantivy` feature
serde = { version = "1", features = ["derive"] }
```

~~**crates/index/sqlite**~~ (removed)

```toml
[dependencies]
rusqlite = { version = "0.31", features = ["bundled", "unlock_notify", "functions"] }
r2d2 = "0.8"
```

**crates/crypto**

```toml
[dependencies]
age = "0.10"
secrecy = "0.8"
thiserror = "1"
```

**crates/server**

```toml
[dependencies]
axum = { version = "0.7", features = ["ws"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "signal"] }
jsonrpsee = { version = "0.2", features = ["server", "macros", "ws"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "fmt", "registry"] }
bytes = "1"
```

**crates/cli**

```toml
[dependencies]
clap = { version = "4", features = ["derive", "env", "cargo"] }
config = { version = "0.14", features = ["toml", "yaml", "json"] }
color-eyre = "0.6"
indicatif = "0.17"
tracing = "0.1"
```

**crates/compat**

```toml
[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
rayon = "1"
```

**crates/testing**

```toml
[dev-dependencies]
proptest = "1"
insta = { version = "1", features = ["yaml"] }
assert_cmd = "2"
```

> Note: Numerical versions above indicate the major line and a safe minimum we aim to support. CI pins exact patch levels in the lockfile.

### 3.2 Features and cfgs

Global features surfaced by `workspace.default-members = ["server", "cli"]`:

* `encryption` toggles the `crypto` crate.
* `index-tantivy` selects the search index crate (SQLite backend removed). The default build runs milli-core on LMDB and automatically falls back to the in-process memory index when LMDB cannot be opened (for example, read-only volumes).
* Index engine selection:
  - Default builds run the milli-core engine with BM25 scoring; if milli-core fails to initialise (permission errors, missing mmap support) we degrade gracefully to the memory implementation so developer flows stay unblocked.
  - Enable the real Tantivy backend with the `real_tantivy` feature on non-Apple-ARM targets when Tantivy-specific capabilities are required.
  - On Apple Silicon (aarch64-apple-darwin), leave `real_tantivy` disabled unless you provide the SSSE3 toolchain prerequisites that Tantivy 0.2 expects.
* `backend-github` and `backend-local` select storage adapters.
* `transport-ws` and `transport-stdio` select runtime modes in `server`.

Example workspace `Cargo.toml` snippet:

```toml
[workspace]
members = [
  "crates/core",
  "crates/proto",
  "crates/storage/github",
  "crates/storage/local",
  "crates/storage/ephemeral",
  "crates/index/tantivy",
  "crates/crypto",
  "crates/server",
  "crates/cli",
  "crates/compat",
  "crates/testing"
]
resolver = "2"

[workspace.package]
edition = "2021"
authors = ["MCP GitMem Team"]
license = "Apache-2.0 OR MIT"

[workspace.lints.rust]
unsafe_code = "forbid"

[workspace.lints.clippy]
pedantic = "warn"
unwrap_used = "deny"
expect_used = "deny"

[workspace.metadata.ci]
msrv = "1.89.0"
index_default = "milli"
```

---

## 4. Coding standards

### 4.1 Style

* Use `rustfmt` defaults. No custom format rules.
* Naming: modules `snake_case`, types `UpperCamelCase`, functions `lower_snake_case`.
* Avoid `unwrap` or `expect` in non‑test code. Use `?` and typed errors.
* Prefer `&str` over `String` for API inputs where possible.
* Avoid trait objects unless required. Use generics where it improves clarity.

### 4.2 Errors

* Public API returns typed errors from crates using `thiserror` enums.
* `anyhow` is allowed at binary boundaries only (CLI and server main).
* Include stable `code` fields for MCP tool errors: `E_NOT_FOUND`, `E_VALIDATION`, `E_RATE_LIMIT`, `E_CONFLICT`, `E_ENCRYPTION`, `E_STORAGE_IO`.
* No secrets in error messages. Use redaction helpers in `crypto`.

### 4.3 Concurrency

* Use `tokio` multi‑thread runtime. No blocking IO in async tasks. Use `spawn_blocking` for git or heavy CPU.
* File writes must be atomic: write to temp file, `fsync`, then rename.
* Rate limit outbound GitHub API with a bounded semaphore per host.
* Use `tracing` spans for end‑to‑end operations: save, search, sync.

### 4.4 Data model invariants

* `Memory.id` is unique and immutable.
* `created_at` never changes. `updated_at` increases monotonically.
* `ttl` is enforced at query time. Expired items are filtered out by `Index`.
* Encryption on means both `title` and `content` are ciphertext. Metadata remains clear unless tagged as sensitive.

### 4.5 Security

* Never log plaintext of `content` when encryption is enabled.
* GitHub tokens are read from environment or command helpers, never from files in the repo.
* Use least privilege scopes: repository contents write, pull requests optional.

---

## 5. Git and GitHub integration

* Prefer pure Rust `gix` for repo operations. Fall back to `git2` if you need specific features.
* Device branches follow `devices/<hostname>` by default. Avoid long‑lived diverged branches.
* Commit messages use Conventional Commits with memory context: `feat(mem): add <title> [mem:<id>]`.
* Batch small writes using `commit_batch_ms` grouping.
* Conflicts: try a three‑way JSON merge. If unresolved, emit an artifact under `conflicts/<id>/` and return `E_CONFLICT`.
* Optional PR flow: open a PR to `main` with a standard template. Do not include plaintext content when encryption is on.

Implementation notes (M3):
- Working tree model is the default for local testing and file:// remotes; `push`/`pull` mirror `memories/` and `meta/` and reload the manifest.
- Each project is persisted under `memories/<project>/YYYY/MM/DD/<id>.json` with a companion `meta/<project>/MANIFEST.json`; manifests are rebuilt automatically on pull/reset so multi-project workspaces stay consistent.
- Feature `remote-git` enables real remote push/pull using `git2` (HTTPS/SSH) on the Github storage. The device branch defaults to `devices/<hostname>` and can be overridden via env `GITMEM_DEVICE_BRANCH`.
- Remote name defaults to `sync` and can be changed via CLI config `github.remote_name`.
- Credentials (when `remote-git` is enabled): `helper` (git credential), `userpass` (username + env var password), `token` (username, default `x-access-token`, token from env var), `ssh-agent` (agent‑backed).
- Encryption can be enabled at write time by supplying age recipients via `--encryption-recipient` (repeatable), the `encryption` config section, or `GITMEM_ENCRYPT_RECIPIENTS`; when configured the server encrypts titles/content before persisting and only indexes metadata.
- **Auto-push**: Optional automatic push to remote after every write (`save`, `update`, `delete`). Enabled via CLI (`--auto-push --remote-url <url>`) or config (`github.auto_push = true`, `github.remote_url`). The storage adapter flushes pending commits before pushing. Push failures are logged but do not fail the write operation; commits remain local for manual sync.

---

## 6. MCP surface and compatibility

* Tools: baseline memory commands plus the full OSS basic-memory compatibility layer.
  - Core memory: `memory.save`, `memory.get`, `memory.search`, `memory.update`, `memory.delete`, `memory.import.basic`, `memory.sync`, and (behind `encryption`) `memory.encrypt`/`memory.decrypt`.
  - Project management: `list_memory_projects`, `create_memory_project`, `delete_memory_project`, `list_directory`, `sync_status`.
  - Knowledge compatibility: `write_note`, `read_note`, `view_note`, `edit_note`, `delete_note`, `move_note`, `read_content`, `fetch`, `project_info`, `canvas`.
  - Search & context helpers: `search_notes`, `recent_activity`, `build_context` (delegates to `search_notes` when a query is supplied, otherwise falls back to `recent_activity`), and the formatted `search` + `continue_conversation` prompt shims.
  - Guides & resources: `ai_assistant_guide`, `resource.list`, `resource.read`, `initialize`.
  * MCP `tools/list` responses expose underscore variants (for example `memory_save`) to satisfy the MCP tool name pattern. The server continues accepting the dotted aliases (for example `memory.save`) when handling `tools/call` for backwards compatibility with basic-memory clients.
* Input schemas must remain backward compatible. New fields are opt‑in.
* Keep a golden set of JSON fixtures in `crates/testing/fixtures/compat_basic/` and run conformance tests.

Current support (M3):
- Implemented server handlers: all items above except for the encryption admin tools. `move_note` wraps a storage copy followed by an index update across projects; `search`, `fetch`, `project_info`, `canvas`, `ai_assistant_guide`, and `continue_conversation` now map to the underlying storage/index pipelines so ChatGPT-style clients receive formatted results.
- CLI provides `import` and `sync` subcommands, exercising the compatibility handlers; `memory.import.basic` is wired through the MCP server.
- Encryption admin tools remain planned for M4.

---

## 7. Indexing

* Default engine is milli-core (Meilisearch's embedded LMDB index). We still use BM25 with field boosts so `title` outranks `content`.
* Optional: enable the `real_tantivy` feature for environments that prefer raw Tantivy; keep it disabled on Apple Silicon unless you install the SSSE3 toolchain requirements.
* Index fields: `title`, `content`, `tags`, `type`, `created_at`, `updated_at`, `score`.
* **Async queue architecture**: Index updates are queued via an unbounded `tokio::sync::mpsc` channel. A background worker task processes updates using `spawn_blocking` for CPU-bound index operations. MCP handlers return immediately after queuing, enabling non-blocking writes.
* **Queue monitoring**: Worker logs warnings when queue depth > 5000. Graceful shutdown cancels the worker and drains remaining items (up to 5 seconds).
* Encryption on means only metadata is indexed. Document this clearly in server capability flags.
* Rebuild policy: incremental updates on write and on sync pull. Full rebuild is allowed behind a CLI flag.

---

## 8. Crypto

* Use `age` X25519 recipients. Multiple recipients supported.
* Envelope format: versioned header with `algo`, `kid`, `recipients`.
* Keys are loaded from OS keychain or env and kept in memory using `secrecy::SecretString`.
* Provide `gitmem reencrypt` for rotating keys.
* CLI flag `--encryption-recipient` (or config `encryption.recipients`/env `GITMEM_ENCRYPT_RECIPIENTS`) enables automatic encryption in the server; when enabled both `memory.save` and `memory.update` encrypt title/content and redact plaintext from the search index.

---

## 9. CLI guidelines

* Use `clap` derive. Provide `--config` that reads TOML or YAML via `config` crate.
* Subcommands: `serve`, `import`, `sync`, `link-folder`, `unlink-folder`, `list-links`, `rescan-links`, `reindex`, `reencrypt`.
* `link-folder` returns a full metadata payload (`project`, `path`, `displayPath`, `resolvedPath`, `linkId`, `include`, `exclude`, `watch`, `createdAt`, `lastScan`, `lastError`, `fileCount`, `totalBytes`, `status`). Match the schema Basic Memory exposes so Codex/Cursor clients can reuse compatibility layers.
* `list-links` surfaces the same metadata for every binding and adds `lastRuntimeMs` (duration of the most recent scan). Invoking without `--project` lists links across all projects.
* `rescan-links` and `memory.sync { direction = "external" }` return per-link reports containing `project`, `linkId`, `path`, `displayPath`, `include`, `exclude`, `scanned`, `created`, `updated`, `deleted`, `totalBytes`, `runtimeMs`, and `lastError`.
* Watcher defaults live under `[storage.local.watch]` (mode = `poll`, `poll_interval_ms`, `jitter_pct`, `max_concurrent`). Per-link overrides come from `--watch-mode`, `--poll-interval`, and `--jitter`. Pollers must enforce jitter (deterministic per link) and respect `max_concurrent` when multiple folders trigger simultaneously.
* Exit codes: non‑zero for user errors. Map storage conflicts to 2xx where appropriate for sync status, but non‑zero exit for unrecoverable errors.

---

## 10. Observability

* Structured logs with `tracing` JSON format in server mode.
* Span naming: `memory.save`, `memory.search`, `storage.github.push`, `storage.github.pull`, `index.update`, `crypto.encrypt`.
* Metrics: counters for saves, updates, deletes, conflicts, rate‑limit hits, and queue sizes. Histograms for latencies.
* Provide an optional OpenTelemetry exporter behind a feature.

---

## 11. Testing and quality gates

* Unit tests in each crate.
* Property tests in `crates/testing` for merge logic and TTL handling.
* Integration tests run the server in stdio mode and exercise MCP tools end to end.
* Snapshot tests with `insta` for JSON outputs. Keep fixtures stable.
* Fuzz targets for JSON merge using `cargo fuzz` (optional profile).
* `cargo audit` and `cargo deny` run in CI on every push and nightly.

### 11.1 Benchmarks

* `criterion` benches for save, search, import on synthetic datasets of 1k, 10k, 50k memories.
* Report p50, p95 latencies and throughput.

---

## 12. CI and release

* GitHub Actions workflows:

  * `ci.yml`: lint, build, test matrix across OS and targets. Cache cargo.
  * `audit.yml`: `cargo audit` and `cargo deny`.
  * `release.yml`: tag on `server` and `cli` changes. Build static binaries for Linux musl and macOS universal where possible. Push Docker image to GHCR.
  * `update-lock.yml`: scheduled weekly lockfile update and PR.
* Versioning: Semantic Versioning per crate. Use workspace `package.version` only for binaries.
* Tags: `server-vX.Y.Z`, `cli-vX.Y.Z`.

---

## 13. Developer setup

* Install toolchain via `rustup`, channel: `stable` (pinned via `rust-toolchain.toml`), components: `clippy`, `rustfmt`.
* Optional: `asdf` or `mise` configuration for cross and sccache.
* Run `make setup` which installs pre‑commit hooks for fmt and clippy.
* Build (default milli-core index with automatic memory fallback): `cargo build --workspace --features backend-github,index-tantivy,encryption,transport-stdio`.
* Build with the real Tantivy backend (non-ARM targets): `cargo build --workspace --features real_tantivy,backend-github,index-tantivy,encryption,transport-stdio`.
* Build with real remote push/pull support: add `--features mcp-gitmem-storage-github/remote-git`.
* Run server locally in stdio mode for IDEs.
* HTTP JSON‑RPC (optional): `gitmem serve --backend local --root ./data --http --addr 127.0.0.1:8080`.
* Performance checks: `cargo bench -p mcp-gitmem-benchmarks --bench performance --offline` (save/search/import datasets at 1k, 10k, 50k).

See `docs/integration/stdio-mcp.md` for Cursor / Codex CLI stdio configuration and migration tips.

---

## 14. Checklists

### 14.1 Adding a new field to `Memory`

1. Update `crates/core` types and serde derives.
2. Add validation and defaulting in constructors.
3. Update merge logic and vector‑clock metadata if required.
4. Update both index backends to add the field to schema and mapping.
5. Add migration code that backfills the field for existing records at read time.
6. Update fixtures and snapshots. Add conformance tests.
7. Document the change in `docs/CHANGELOG.md` and the server capability flags.

### 14.2 Implementing a new MCP tool

1. Add the schema and types in `proto`.
2. Implement handler in `server` and route it via JSON‑RPC.
3. Add storage and index calls as needed following existing patterns.
4. Add unit tests in `server` and integration tests in `crates/testing`.
5. Update `AGENTS.md` and main spec if behaviour is notable.

### 14.3 Fix for a GitHub sync bug

1. Write a failing integration test that reproduces the condition.
2. Audit concurrency: look for missing `spawn_blocking` and lock misuse.
3. Add tracing spans with correlation IDs and last remote SHA.
4. Fix, then run the test matrix with `--ignored` if network is mocked.
5. If behaviour changed, adjust PR template notes.

---

## 15. Samples

### 15.1 Workspace `Cargo.toml`

```toml
[workspace]
members = [
  "crates/core",
  "crates/proto",
  "crates/storage/github",
  "crates/storage/local",
  "crates/storage/ephemeral",
  "crates/index/tantivy",
  "crates/crypto",
  "crates/server",
  "crates/cli",
  "crates/compat",
  "crates/testing"
]
resolver = "2"

[workspace.package]
edition = "2021"
license = "Apache-2.0 OR MIT"
authors = ["MCP GitMem Team"]

[workspace.metadata]
msrv = "1.76.0"
```

### 15.2 Server `Cargo.toml` features

```toml
[features]
encryption = ["mcp-gitmem-crypto"]
index-tantivy = ["mcp-gitmem-index-tantivy"]
index-sqlite = ["mcp-gitmem-index-sqlite"]
backend-github = ["mcp-gitmem-storage-github"]
backend-local = ["mcp-gitmem-storage-local"]
transport-stdio = []
transport-ws = ["axum/ws"]
```

### 15.3 PR template

```md
## Summary
- What does this change do and why

## Risk
- Migration impact, compatibility, data model changes

## Tests
- Unit, integration, benchmarks

## Observability
- New spans, metrics, logs

## Rollout
- Flags, config changes, recovery plan
```

---

## 16. Performance targets

* Save p50 < 5 ms local path excluding network. Search p95 < 50 ms on 50k docs. Import throughput > 1k writes per second on SSD.
* Server memory baseline under 50 MiB idle. No unbounded queues.

---

## 17. ADRs and decisions

* ADR‑001 choose milli-core (LMDB) as the default embedded index (supersedes the earlier Tantivy decision).
* ADR‑002 prefer `gix` over `git2` unless a missing feature blocks a use case.
* ADR‑003 encryption uses `age` X25519 with multiple recipients.
* ADR‑004 compatibility mode mirrors basic memory tool and schema shapes.

---

## 18. Glossary

* MCP: Model Context Protocol.
* MSRV: Minimum Supported Rust Version.
* ADR: Architecture Decision Record.
* PR: Pull Request.

---

## 19. Quick start for agents

1. Read the spec in `/docs` and this file end to end.
2. Run `cargo clippy --all-targets -- -D warnings`.
3. Run the test suite `cargo test --workspace`.
4. Implement changes inside the correct crate only. Do not cross layers.
5. Add tests and update snapshots.
6. Run `cargo fmt --all`.
7. Update `CHANGELOG.md` and PR template sections.
8. Push and open a PR targeting `devices/<hostname>` if PR workflow is enabled.

If you are in doubt about a dependency or version, prefer the major‑line policy and let CI pin the lockfile during weekly updates.
