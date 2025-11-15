#!/bin/bash
set -e

echo "================================"
echo "GitMem Installation Script"
echo "================================"
echo ""

# Check if binary exists
if [ ! -f "./target/release/gitmem" ]; then
    echo "❌ Error: ./target/release/gitmem not found"
    echo "Run: cargo build --release --features backend-github,index-tantivy,encryption,mcp-gitmem-storage-github/remote-git"
    exit 1
fi

echo "✅ Found release binary"

# Check if it has git2 support
if nm ./target/release/gitmem 2>/dev/null | grep -q "libgit2_sys"; then
    echo "✅ Binary has git2 support (remote-git feature enabled)"
else
    echo "⚠️  Warning: Binary may not have git2 support"
    echo "   Consider rebuilding with: --features mcp-gitmem-storage-github/remote-git"
fi

echo ""
echo "Installing to /usr/local/bin/gitmem (requires sudo)..."
sudo cp ./target/release/gitmem /usr/local/bin/gitmem
sudo chmod +x /usr/local/bin/gitmem

echo "✅ Installed to /usr/local/bin/gitmem"
echo ""

# macOS security fix: remove quarantine/provenance attributes and re-sign
echo "Fixing macOS security attributes..."
sudo xattr -d com.apple.quarantine /usr/local/bin/gitmem 2>/dev/null || true
sudo xattr -d com.apple.provenance /usr/local/bin/gitmem 2>/dev/null || true
sudo codesign --force --deep --sign - /usr/local/bin/gitmem 2>/dev/null || echo "⚠️  Warning: codesign failed (continuing anyway)"
echo ""

# Verify installation
echo "Verifying installation..."
/usr/local/bin/gitmem --version

echo ""
echo "================================"
echo "Installation Complete!"
echo "================================"
echo ""
echo "Next steps:"
echo "1. Get a GitHub Personal Access Token:"
echo "   https://github.com/settings/tokens"
echo "   (Select 'repo' scope)"
echo ""
echo "2. Update Cursor MCP config (~/.cursor/mcp.json):"
echo '   "env": { "GITHUB_TOKEN": "your_token_here" }'
echo ""
echo "3. Restart Cursor completely (Cmd+Q, then reopen)"
echo ""
echo "4. Test by saving a memory through Cursor MCP"
echo ""
echo "See docs/INSTALL.md for detailed instructions."

