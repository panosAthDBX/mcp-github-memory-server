#!/bin/bash
set -e

echo "================================"
echo "Fix macOS Gatekeeper/Security"
echo "================================"
echo ""
echo "This script fixes the 'Killed: 9' error on macOS"
echo ""

BINARY="/usr/local/bin/gitmem"

if [ ! -f "$BINARY" ]; then
    echo "❌ Error: $BINARY not found"
    echo "Run ./scripts/install.sh first"
    exit 1
fi

echo "Current binary info:"
file "$BINARY"
echo ""

echo "Checking for quarantine/provenance attributes..."
xattr -l "$BINARY" || echo "(no attributes or permission denied)"
echo ""

echo "Step 1: Removing quarantine and provenance attributes..."
sudo xattr -d com.apple.quarantine "$BINARY" 2>/dev/null && echo "  ✅ Removed quarantine" || echo "  ℹ️  No quarantine attribute"
sudo xattr -d com.apple.provenance "$BINARY" 2>/dev/null && echo "  ✅ Removed provenance" || echo "  ℹ️  No provenance attribute"
echo ""

echo "Step 2: Re-signing binary with ad-hoc signature..."
sudo codesign --force --deep --sign - "$BINARY"
echo "✅ Binary re-signed"
echo ""

echo "Step 3: Verifying signature..."
codesign -dv "$BINARY" 2>&1 | head -5
echo ""

echo "Step 4: Testing binary..."
"$BINARY" --version
echo ""

echo "================================"
echo "✅ Fix Complete!"
echo "================================"
echo ""
echo "The binary should now work. If you still get 'Killed: 9':"
echo "1. Go to System Settings > Privacy & Security"
echo "2. Look for a message about blocking 'gitmem'"
echo "3. Click 'Allow Anyway'"
echo "4. Run the binary again"
echo ""
echo "Or alternatively, try:"
echo "  spctl --add /usr/local/bin/gitmem"
echo "  spctl --enable --label 'Developer ID'"



