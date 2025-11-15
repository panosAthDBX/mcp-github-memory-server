# Implementation Plan – MCP GitHub Memory Server vs Basic Memory OSS

## Phase 0 – Groundwork
- Audit existing crates to map current behaviour to the updated spec (storage project handling, CLI args, compatibility handlers, missing tools).
- Capture tasks/issues for each major gap (project isolation, tool parity, encryption defaults, observability polish) to track progress.

## Phase 1 – Project Isolation & Routing
- Extend core/storage/index traits to carry a `ProjectId`; update Local and GitHub storage to namespace data under `memories/<project>/…`, manifests, and index paths.
- Introduce project selection precedence in server + CLI (`--project`, config defaults, per-call overrides, discovery mode).
- Update resource URIs and `list_directory`/`list_memory_projects` responses to include project context; enforce project-only mode when configured.
- Adjust fixtures/tests to cover multi-project scenarios.

## Phase 2 – Tool Surface Parity
- Implement the full Basic Memory tool set (knowledge management, search/discovery, project management, utility/visualization, prompt helpers, deprecated shims) alongside existing `memory.*` shortcuts.
- Add schemas in `crates/proto`, handler wiring in `crates/server`, and integration tests ensuring requests/responses match upstream behaviour.
- Status: project management surface (`list_memory_projects`, `create_memory_project`, `delete_memory_project`, `list_directory`, `sync_status`) is merged; knowledge tools (`write_note`, `read_note`, `view_note`, `edit_note`, `delete_note`, `move_note`, `read_content`, `search_notes`, `recent_activity`, `build_context`) are now implemented with regression tests, and the remaining compatibility shims (`search`, `fetch`, `project_info`, `canvas`, `ai_assistant_guide`, `continue_conversation`) now forward to the Rust storage/index layer so ChatGPT-format clients stay in lockstep.

## Phase 3 – Encryption Defaults & Migration Fixes
- Integrate `CryptoFacade` into save/update flows with config-driven recipients; ensure indexing stores metadata-only when encrypted.
- Implement CLI/server `reencrypt` command for key rotation and align import tooling to preserve original timestamps/IDs (`compat.basic_id`, `created_at`, `updated_at`).
- Validate that migrations respect project scoping and produce deterministic IDs.
- Status: server save/update paths now encrypt automatically when recipients are configured (CLI flag, config, or env), redacting plaintext from the index and covering the flow with integration tests; `reencrypt` and migration helpers remain pending.

## Phase 4 – Observability, Sync, and Ops Polishing
- Expand tracing/metrics with `project_id`, add OpenTelemetry exporter, and ensure health endpoints reflect per-project status.
- Implement `reindex` CLI command; ensure `sync_status`/`sync` behave consistently across backends, including local/ephemeral no-ops with clear messaging.
- Complete GitHub adapter work (gix path, Contents API fallback, PR workflow knobs, rate limiting instrumentation).
- Status: GitHub storage now persists memories under `memories/<project>/…`, maintains per-project manifests, and supports both file:// mirroring and (feature-gated) git push/pull with commit batching and credential modes; remaining work is to wire metrics/PR workflow knobs.

## Phase 5 – Documentation & QA
- Update `AGENTS.md`, spec snippets, and examples to document project workflow, tool coverage, encryption defaults, and operational commands.
- Refresh conformance/integration suites, add cross-project regression tests, and run full workspace QA (clippy, fmt, tests, audit).
- Prepare rollout materials: changelog entries, migration guidance, and verification checklists for operators.
