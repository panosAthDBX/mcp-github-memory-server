# GitMem Daemon Setup (WebSocket/HTTP Mode)

## ⚠️ Important Note

**Cursor IDE does not support HTTP/SSE transport for MCP servers.** Cursor requires stdio mode.

This daemon setup is useful for:
- Web-based MCP clients
- Custom integrations
- Remote access scenarios
- Testing and development

**For Cursor users**: Use the stdio configuration in your `mcp.json` (see [Integration Guide](integration/stdio-mcp.md)).

## Overview

Running `gitmem` as a daemon with HTTP/WebSocket transport allows multiple clients to connect to a single server, solving:

- ✅ **Shared state** - LMDB index, manifest cache, linked folder registry
- ✅ **No Git conflicts** - one process handles all commits/pushes
- ✅ **Better performance** - no process spawn overhead
- ✅ **Survives restarts** - daemon keeps running across Cursor restarts

## Installation

### 1. Install the LaunchAgent

The daemon configuration is in `~/Library/LaunchAgents/com.gitmem.server.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.gitmem.server</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/gitmem</string>
        <string>serve</string>
        <string>--backend</string>
        <string>github</string>
        <string>--http</string>
        <string>--addr</string>
        <string>127.0.0.1:8080</string>
        <string>--config</string>
        <string>/Users/YOUR_USERNAME/.config/gitmem.yaml</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>GITHUB_TOKEN</key>
        <string>your_github_token_here</string>
        <key>GITMEM_DEVICE_BRANCH</key>
        <string>devices/YOUR_DEVICE</string>
        <key>RUST_LOG</key>
        <string>info</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/Users/YOUR_USERNAME/.gitmem/logs/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/Users/YOUR_USERNAME/.gitmem/logs/stderr.log</string>
    <key>WorkingDirectory</key>
    <string>/Users/YOUR_USERNAME</string>
</dict>
</plist>
```

### 2. Configure Cursor

Update `~/.cursor/mcp.json` to use the WebSocket endpoint:

```json
{
  "mcpServers": {
    "gitmem": {
      "url": "http://127.0.0.1:8080"
    }
  }
}
```

**Note**: Remove the `command`, `args`, and `env` fields - these are only for stdio mode.

## Managing the Daemon

### Start the Daemon

```bash
# Create logs directory
mkdir -p ~/.gitmem/logs

# Load and start
launchctl load ~/Library/LaunchAgents/com.gitmem.server.plist
```

The daemon will auto-start on login thanks to `RunAtLoad`.

### Stop the Daemon

```bash
launchctl unload ~/Library/LaunchAgents/com.gitmem.server.plist
```

### Restart the Daemon

```bash
launchctl unload ~/Library/LaunchAgents/com.gitmem.server.plist
launchctl load ~/Library/LaunchAgents/com.gitmem.server.plist
```

Or simply:

```bash
launchctl kickstart -k gui/$UID/com.gitmem.server
```

### Check Status

```bash
# Check if loaded
launchctl list | grep gitmem

# Check process
ps aux | grep gitmem | grep -v grep

# Check port binding
lsof -i :8080
```

### View Logs

```bash
# Real-time logs
tail -f ~/.gitmem/logs/stderr.log

# Recent logs
tail -50 ~/.gitmem/logs/stderr.log
```

## Troubleshooting

### Daemon won't start

1. Check logs: `tail -50 ~/.gitmem/logs/stderr.log`
2. Verify binary exists: `which gitmem`
3. Test manually: `gitmem serve --http --addr 127.0.0.1:8080 --backend github --config ~/.config/gitmem.yaml`
4. Check permissions: `ls -la ~/Library/LaunchAgents/com.gitmem.server.plist`

### Port already in use

```bash
# Find what's using port 8080
lsof -i :8080

# Kill the process (if it's an old gitmem instance)
pkill -f gitmem
```

### Cursor can't connect

1. Verify daemon is running: `launchctl list | grep gitmem`
2. Test HTTP endpoint: `curl -v http://127.0.0.1:8080`
3. Check Cursor's MCP logs in the developer tools
4. Restart Cursor after updating `mcp.json`

### Update after code changes

After rebuilding the binary:

```bash
# Copy new binary
cargo build --release --features backend-github,index-tantivy,encryption
sudo cp target/release/gitmem /usr/local/bin/

# Restart daemon
launchctl kickstart -k gui/$UID/com.gitmem.server

# Verify it's running the new version
gitmem --version  # from terminal
tail -f ~/.gitmem/logs/stderr.log  # check startup logs
```

## Architecture Benefits

### Single Daemon vs Multiple Processes

| Aspect | Daemon Mode (HTTP) | Stdio Mode |
|--------|-------------------|------------|
| Process count | 1 daemon for all Cursors | 1 per Cursor window |
| LMDB index | Shared, consistent | Separate per process |
| Git operations | No conflicts | Potential conflicts |
| Memory usage | ~50MB shared | ~50MB × N windows |
| Startup time | Instant (already running) | ~100-200ms per spawn |
| State persistence | Survives Cursor restarts | Lost on Cursor exit |

### Concurrency Model

The daemon uses:
- **`Arc<RwLock<...>>`** for in-memory manifest cache
- **LMDB** for full-text index (multi-process safe)
- **File locks (`fs4`)** for critical sections
- **Tokio** for async I/O and request handling

Multiple Cursor instances can safely:
- Read memories concurrently
- Write memories (serialized by RwLock)
- Search index (LMDB handles concurrency)
- Scan linked folders (scheduled scans won't conflict)

## Migration from Stdio to Daemon

If you were previously using stdio mode:

1. **Backup your data** (just in case):
   ```bash
   cp -r ~/memory ~/memory.backup
   ```

2. **Update Cursor config** to use `url` instead of `command`:
   ```json
   {
     "mcpServers": {
       "gitmem": {
         "url": "http://127.0.0.1:8080"
       }
     }
   }
   ```

3. **Start the daemon** using launchctl

4. **Restart Cursor**

The same storage directory (`~/memory`) will be used, so all your existing memories are preserved.

## Security Notes

- The HTTP server binds to `127.0.0.1` (localhost only) - not accessible from network
- Environment variables in the plist file may contain sensitive tokens
- File permissions: `chmod 600 ~/Library/LaunchAgents/com.gitmem.server.plist`
- Log files may contain debugging information - keep secure

## Related Documentation

- [Installation Guide](INSTALL.md)
- [Folder Linking (GitHub Backend)](FOLDER_LINKING_GITHUB.md)
- [Troubleshooting Auto-Push](troubleshooting/auto-push-fix.md)

