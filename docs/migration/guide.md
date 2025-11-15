# Migration Guide — Basic Memory to GitMem (MCP)

This guide walks you through moving an existing basic‑memory dataset to the GitMem MCP server, configuring backends, and integrating clients. It’s written to minimize downtime and provide a clear rollback path.

## 1) Prerequisites

- Rust toolchain (stable) installed. Build GitMem:

```
cargo build --workspace --features backend-github,index-tantivy,transport-stdio
```

Optional features (the default build already enables the milli-core LMDB index with automatic in-memory fallback):
- `real_tantivy` (non‑ARM targets) to force the pure Tantivy backend.
- `mcp-gitmem-storage-github/remote-git` for real remote push/pull via git2.
- `encryption` to enable age X25519 admin tools.

## 2) Choose a backend

- Ephemeral (memory‑only): fastest for dev/test.
  - `gitmem serve --backend ephemeral`
- Local filesystem (single machine):
  - `gitmem serve --backend local --root ./data`
- GitHub working tree directory (Git as storage):
  - `gitmem serve --backend github --root ./repo`

Tips:
- Use `--config examples/gitmem.yaml` to centralize settings (batching, remote name, credentials, etc.).
- For GitHub, create an empty working directory (e.g., `./repo`). GitMem will initialize structure as you import.

## 3) Export from basic‑memory

Export your existing memories into JSON array (`.json`) or JSONL (`.jsonl`) format. Ensure each row has `title`, `content`, optional `type`, and optional `tags` array.

Example JSONL row:
```
{"title":"t","content":"c","type":"note","tags":["a","b"]}
```

## 4) Import into GitMem

Dry‑run first to estimate counts:
```
gitmem import --from ./memories.jsonl --backend local --root ./data --dry-run
```

Real import (Local):
```
gitmem import --from ./memories.jsonl --backend local --root ./data
```

Real import (GitHub working tree):
```
gitmem import --from ./memories.jsonl --backend github --root ./repo
```

Type remapping (optional):
```
gitmem import --from ./memories.json --backend local --root ./data \
  --map-type note=note --map-type fact=fact
```

Notes:
- The importer deduplicates within the input by `id` and skips existing IDs in storage.
- Configure commit batching for GitHub in config: `github.commit_batch_ms: 1500`.

## 5) Sync to a remote (GitHub backend)

Local (file://) testing:
```
gitmem sync --backend github --root ./repo --remote file:///tmp/remote --direction both
```

Real remote (HTTPS/SSH): build with remote‑git and set credentials in config:
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

Then push/pull:
```
gitmem sync --backend github --root ./repo --remote https://github.com/you/your-repo.git --direction both
```

Device branch override:
```
export GITMEM_DEVICE_BRANCH=devices/myhost
```

## 6) Integrate clients (Cursor, Codex CLI)

- Cursor (.cursor/mcp.json):
```json
{
  "mcpServers": {
    "gitmem": {
      "command": "/abs/path/to/target/debug/gitmem",
      "args": ["serve", "--backend", "local", "--root", "./data"],
      "env": {}
    }
  }
}
```

- Codex CLI (MCP servers config):
```json
{
  "servers": [
    {
      "name": "gitmem",
      "command": "/abs/path/to/target/debug/gitmem",
      "args": ["serve", "--backend", "github", "--root", "./repo"],
      "env": {"GITMEM_DEVICE_BRANCH": "devices/myhost"}
    }
  ]
}
```

HTTP fallback (when stdio MCP isn’t supported):
```
gitmem serve --backend local --root ./data --http --addr 127.0.0.1:8080
```
- POST /rpc with JSON‑RPC body; GET /healthz returns `{ "ok": true }`.

## 7) Encryption (optional, gradual)

- Build with `--features encryption` to enable admin tools.
- Encrypt a memory by id (admin): call `memory.encrypt` with recipients (X25519 public keys). Decrypt via `memory.decrypt` (X25519 identity).
- When encrypted, only metadata is indexed; title/content ciphertext is not indexed. Plan queries accordingly.
- Recommended: migrate plaintext first, then encrypt gradually.

## 8) Verification

Run server, save and search:
```
gitmem serve --backend local --root ./data
```
Use a stdio or HTTP JSON‑RPC client to call `memory.search` and sample `memory.get` on a few IDs.

## 9) Rollback and recovery

- Local backend: copy `./data` before import. To roll back, restore the snapshot directory.
- GitHub backend: each import writes JSON files and a commit (batched). To roll back, reset to the previous commit in your repo or file:// mirror. Conflicts are written to `conflicts/<id>/...` for inspection.

## 10) Troubleshooting

- Absolute paths in client configs prevent spawn failures.
- Apple Silicon: only enable `real_tantivy` if you install the Tantivy 0.2 SSSE3 toolchain prerequisites; otherwise stay on the default milli-core engine.
- Remote credentials: use git credential helper or configure `github.credentials`.
- If /rpc returns parse errors, verify the request body is a valid JSON‑RPC 2.0 object: `{ "jsonrpc":"2.0", "id":1, "method":"memory.search", "params": { ... } }`.
