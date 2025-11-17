---
title: Integrating GitMem (MCP) via stdio
tags: [stdio, integration, cursor, configuration, mcp-transport]
type: doc
---

# Integrating GitMem (MCP) via stdio

This guide shows how to run the GitMem server in stdio mode and wire it into stdio‑aware MCP clients such as Cursor and Codex CLI.

## Build the server

Portable build (default milli-core index with automatic in-memory fallback):

```
cargo build --workspace --features backend-github,index-tantivy,transport-stdio
```

Optional features (default build already uses milli-core on LMDB):
- `real_tantivy` (non‑ARM targets) to enable the pure Tantivy backend.
- `mcp-gitmem-storage-github/remote-git` for real remote push/pull using git2 (HTTPS/SSH).
- `encryption` for age X25519 admin tools (`memory.encrypt`/`memory.decrypt`).

## Choose a backend

- Ephemeral (memory only): `gitmem serve --backend ephemeral`
- Local filesystem: `gitmem serve --backend local --root ./data`
- GitHub working tree directory: `gitmem serve --backend github --root ./repo`

Optional config file: `--config examples/gitmem.yaml` (supports YAML/TOML/JSON + env overrides)

## Cursor integration (stdio MCP)

Create `.cursor/mcp.json` in your project (or user) config with a `mcpServers` entry:

```json
{
  "mcpServers": {
    "gitmem": {
      "command": "/absolute/path/to/target/debug/gitmem",
      "args": [
        "serve",
        "--backend", "github",
        "--root", "/absolute/path/to/repo"
      ],
      "env": {
        "GITMEM_DEVICE_BRANCH": "devices/myhost"
      }
    }
  }
}
```

Tips:
- Switch to `local` backend with `--root ./data` for single‑machine use.
- Add `--config /path/gitmem.yaml` to centralize backend settings (remote name, credentials, batching).
- For real remote push/pull, build with `--features mcp-gitmem-storage-github/remote-git` and set credentials in config (`github.credentials`).

## Codex CLI integration (stdio MCP)

Codex CLI supports stdio MCP servers via a configuration file (example `~/.config/codex/mcp.json`):

```json
{
  "servers": [
    {
      "name": "gitmem",
      "command": "/absolute/path/to/target/debug/gitmem",
      "args": ["serve", "--backend", "local", "--root", "./data"],
      "env": {}
    }
  ]
}
```

Adjust paths/backends to your environment. Codex CLI will spawn GitMem and communicate over stdio (JSON‑RPC 2.0).

## HTTP fallback (optional)

If your client doesn’t support stdio MCP yet, you can expose a minimal HTTP JSON‑RPC endpoint:

```
gitmem serve --backend local --root ./data --http --addr 127.0.0.1:8080
```

- POST `/rpc` with the JSON‑RPC request body
- GET `/healthz` returns `{ "ok": true }`

Example JSON-RPC over HTTP (curl):

```
curl -sS http://127.0.0.1:8080/rpc \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize"}'
```

`initialize` returns standard MCP capabilities (resources + tools) and exposes GitMem feature flags under `capabilities.experimental.gitmem` (memory/storage/transport/tool availability).

Call `memory.sync` with remote/branch:

```
curl -sS http://127.0.0.1:8080/rpc \
  -H 'content-type: application/json' \
  -d '{
        "jsonrpc":"2.0",
        "id":2,
        "method":"memory.sync",
        "params": {"direction":"both","remote":"file:///tmp/remote","branch":"devices/myhost"}
      }'
```

When launched from Codex CLI, the server inherits `GITMEM_DEVICE_BRANCH` and `GITMEM_REMOTE_NAME` from `~/.codex/config.toml`. GitMem reads those values automatically, so keep them aligned with the remote you intend to sync (for example update the Codex entry if you repoint the backend root or change the device branch).

### Linked folders (local backend)

Local backends can mirror existing directories (for example an Obsidian vault) into the memory store:

1. Link a folder (overrides watch mode, interval, and jitter if desired):

   ```sh
   gitmem link-folder \
     --root ./data \
     --project notes \
     --path ~/Vault \
     --include "**/*.md" \
     --watch-mode poll \
     --poll-interval 45000 \
     --jitter 10
   ```

   The command registers the folder and performs an initial rescan. Files are parsed (YAML front-matter is honoured) and converted into memories tagged with `linked`. The response echoes the full metadata payload (link id, resolved path, watch settings, file counts, last scan/runtime/error fields) so clients can persist it directly.

2. List current links:

   ```sh
   gitmem list-links --root ./data
   ```

   Each entry prints the link id, project, status (`idle`, `polling`, `error`), last scan timestamp, last runtime in milliseconds, file counts, bytes indexed, and the glob patterns in effect.

3. Trigger a manual rescan (also available through `memory.sync {"direction":"external"}` over MCP):

   ```
   curl -sS http://127.0.0.1:8080/rpc \
     -H 'content-type: application/json' \
     -d '{
           "jsonrpc":"2.0",
           "id":3,
           "method":"memory.sync",
           "params": {"project":"notes","direction":"external","paths":["~/Vault"]}
         }'
   ```

   The result contains `reports` for every matched link with scan deltas, total bytes, runtime, and any last error recorded.

4. Unlink when finished:

   ```sh
   gitmem unlink-folder --root ./data --project notes --path ~/Vault
   ```

The server polls linked folders according to `[storage.local.watch]` defaults (30 s interval, 20 % jitter, max four concurrent scans). Per-link overrides apply immediately and persist in `meta/<project>/links.json`.

## Migration tips

- Import existing basic‑memory data (JSON array or JSONL) into GitMem:

```
gitmem import --from ./memories.jsonl --backend github --root ./repo \
  --map-type note=note --map-type fact=fact
```

- Push/pull via file:// remote (local testing):

```
gitmem sync --backend github --root ./repo --remote file:///tmp/remote --direction both
```

- Real remote push/pull (HTTPS/SSH): build with `--features mcp-gitmem-storage-github/remote-git` and configure:

```yaml
# examples/gitmem.yaml
github:
  remote_name: sync
  credentials:
    # mode: helper | userpass | token | ssh-agent
    mode: helper
    # username: x-access-token     # for token mode
    # secret_env: GITHUB_TOKEN     # env var name for token/password
```

Then:

```
gitmem sync --backend github --root ./repo --remote https://github.com/you/your-repo.git --direction both
```

## Troubleshooting

- Ensure the binary path is absolute in client configs.
- For Apple Silicon, only enable `real_tantivy` if you install the Tantivy 0.2 SSSE3 prerequisites; otherwise stay on the default milli-core engine.
- For git2 remotes, ensure credentials/agent are configured, or use the `helper` mode.
