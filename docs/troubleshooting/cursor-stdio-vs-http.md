---
title: Cursor MCP Transport - Stdio vs HTTP
tags: [cursor, stdio, http, troubleshooting, mcp-transport]
type: doc
---

# Cursor MCP Transport: Stdio vs HTTP

## Issue

When trying to configure Cursor to connect to a gitmem daemon via HTTP/WebSocket:

```json
{
  "gitmem": {
    "url": "http://127.0.0.1:8080"
  }
}
```

Cursor fails with errors:
```
[error] Client error for command Error POSTing to endpoint (HTTP 404)
[error] Error connecting to streamableHttp server, falling back to SSE
[error] SSE error: Non-200 status code (404)
[error] No server info found
```

## Root Cause

**Cursor IDE only supports stdio transport for MCP servers.**

While the gitmem server implements HTTP/SSE transport (via the `rmcp` library), Cursor's MCP client expects:
1. To spawn a subprocess using `command` + `args`
2. Communicate via JSON-RPC over stdin/stdout
3. Not connect to HTTP endpoints

The HTTP/SSE transport is designed for:
- Web-based MCP clients
- Remote access scenarios  
- Custom integrations
- Testing/development

But **not** for Cursor IDE.

## Solution

Use stdio mode in `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "gitmem": {
      "command": "/usr/local/bin/gitmem",
      "args": [
        "serve",
        "--config", "/Users/YOUR_USERNAME/.config/gitmem.yaml"
      ],
      "env": {
        "GITHUB_TOKEN": "your_token_here",
        "GITMEM_DEVICE_BRANCH": "devices/YOUR_DEVICE"
      }
    }
  }
}
```

## Multi-Instance Concerns

### Original Goal
We wanted a single daemon to avoid:
- Multiple processes (one per Cursor window)
- Git conflicts from concurrent commits
- Stale manifest caches
- Index inconsistencies

### Reality with Stdio Mode

**Each Cursor window spawns its own gitmem process.** However, this is actually safe because:

#### 1. **LMDB Index (Multi-Process Safe)**
- LMDB is designed for concurrent access
- Multiple readers are lock-free
- Single writer with ACID transactions
- No conflicts between processes

#### 2. **Git Operations (GitHub Backend)**
- Each process has its own in-memory manifest cache
- Git commits are atomic (no conflicts)
- Auto-push is serialized by git itself
- Worst case: one push fails, retries on next write

#### 3. **Linked Folder Registry**
- Stored in `meta/<project>/links.json`
- Read at startup, written on changes
- Changes are infrequent (linking/unlinking)
- File system provides atomicity for small writes

### Potential Issues (Edge Cases)

1. **Stale Manifest Cache**
   - **Scenario**: Process A writes a memory, Process B has old manifest
   - **Impact**: Process B might miss the new memory in searches until restart
   - **Mitigation**: Cursor restarts MCP servers frequently enough

2. **Concurrent Git Commits**
   - **Scenario**: Two processes commit at the same time
   - **Impact**: One commit might not include the other's changes
   - **Mitigation**: Git's object store is safe, auto-sync will catch up

3. **Link Registry Conflicts**
   - **Scenario**: Two processes try to link/unlink simultaneously  
   - **Impact**: One update might be lost
   - **Mitigation**: Infrequent operation, user-triggered

### Recommended Approach

**For normal use**: Stdio mode with multiple processes is **fine**. The architecture handles concurrency gracefully.

**For high-frequency writes**: Consider:
1. Using a single Cursor window for writes
2. Or implement a proper multi-process coordination layer (future work)

## When HTTP/SSE Mode Makes Sense

Use daemon mode with HTTP/SSE for:

1. **Web Applications**
   ```javascript
   // Browser-based MCP client
   const client = new McpClient('http://localhost:8080');
   ```

2. **Remote Access**
   ```bash
   # Expose on network interface
   gitmem serve --http --addr 0.0.0.0:8080
   ```

3. **Long-Running Services**
   ```bash
   # Run as systemd service
   gitmem serve --http --addr 127.0.0.1:8080
   ```

4. **Custom Integrations**
   ```python
   # Python script accessing gitmem
   import requests
   r = requests.post('http://localhost:8080/message?sessionId=...')
   ```

## Implementation Details

The gitmem server's HTTP mode uses:
- **`rmcp` library** v0.8.3 with SSE transport
- **Endpoints**:
  - `/sse` - Server-Sent Events stream
  - `/message` - POST JSON-RPC messages
  - `/healthz` - Health check
- **Transport**: SSE (not WebSocket), requires `sessionId` query param

Cursor doesn't support this transport model.

## Testing HTTP Mode

If you want to test the HTTP/SSE mode:

```bash
# Start daemon
gitmem serve --http --addr 127.0.0.1:8080 --backend github --config ~/.config/gitmem.yaml

# Health check
curl http://127.0.0.1:8080/healthz

# Connect to SSE stream (requires SSE client)
curl http://127.0.0.1:8080/sse

# Post message (needs proper sessionId)
curl -X POST 'http://127.0.0.1:8080/message?sessionId=test' \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
```

## Related Documentation

- **[Integration Guide](../integration/stdio-mcp.md)** - Stdio configuration for Cursor
- **[Daemon Setup](../DAEMON_SETUP.md)** - HTTP/SSE mode (for non-Cursor use)
- **[Installation](../INSTALL.md)** - Basic setup

## Summary

| Feature | Stdio Mode | HTTP/SSE Mode |
|---------|-----------|---------------|
| **Cursor Support** | ✅ Yes | ❌ No |
| **Process Model** | One per window | Single daemon |
| **Concurrency** | Safe (LMDB + Git) | N/A for Cursor |
| **Remote Access** | ❌ No | ✅ Yes |
| **Web Clients** | ❌ No | ✅ Yes |
| **Recommended For** | Cursor, local use | Web, remote, custom |

**Bottom line**: Use stdio mode for Cursor. It's safe, supported, and works well.

