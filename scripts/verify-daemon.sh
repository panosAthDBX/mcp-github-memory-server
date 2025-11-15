#!/bin/bash
# Verify GitMem Daemon Setup

set -e

echo "🔍 GitMem Daemon Verification"
echo "=============================="
echo ""

# Check if daemon is running
echo "1. Checking daemon status..."
if launchctl list | grep -q com.gitmem.server; then
    PID=$(launchctl list | grep com.gitmem.server | awk '{print $1}')
    echo "   ✅ Daemon is running (PID: $PID)"
else
    echo "   ❌ Daemon is not running"
    echo "   Run: launchctl load ~/Library/LaunchAgents/com.gitmem.server.plist"
    exit 1
fi

# Check if port is listening
echo ""
echo "2. Checking port binding..."
if lsof -i :8080 | grep -q gitmem; then
    echo "   ✅ Port 8080 is listening"
else
    echo "   ❌ Port 8080 is not listening"
    exit 1
fi

# Check process details
echo ""
echo "3. Process details..."
ps aux | grep gitmem | grep -v grep | head -1

# Show recent logs
echo ""
echo "4. Recent logs (last 5 lines)..."
tail -5 ~/.gitmem/logs/stderr.log 2>/dev/null || echo "   (No logs yet)"

# Check Cursor config
echo ""
echo "5. Cursor MCP configuration..."
if grep -q '"url": "http://127.0.0.1:8080"' ~/.cursor/mcp.json; then
    echo "   ✅ Cursor configured for WebSocket mode"
else
    echo "   ⚠️  Cursor may not be configured correctly"
    echo "   Expected: \"url\": \"http://127.0.0.1:8080\""
fi

# Test HTTP endpoint
echo ""
echo "6. Testing HTTP endpoint..."
if curl -s --max-time 2 http://127.0.0.1:8080 >/dev/null 2>&1; then
    echo "   ✅ HTTP endpoint responding"
else
    echo "   ⚠️  HTTP endpoint not responding (this is normal for MCP SSE)"
fi

echo ""
echo "=============================="
echo "✅ Daemon verification complete!"
echo ""
echo "Next steps:"
echo "  1. Restart Cursor if you haven't already"
echo "  2. Test gitmem tools in Cursor (e.g., search_notes, write_note)"
echo "  3. View logs: tail -f ~/.gitmem/logs/stderr.log"
echo ""

