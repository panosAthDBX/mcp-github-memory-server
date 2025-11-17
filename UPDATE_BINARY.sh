#!/bin/bash
# Script to update the installed gitmem binary with the fixed version

set -e

echo "🔧 Updating gitmem binary with the fix..."
echo ""

# Kill any running gitmem processes
echo "1. Stopping any running gitmem processes..."
pkill -9 -f "gitmem serve" 2>/dev/null || echo "   No gitmem processes to stop"

echo ""
echo "2. Backing up current binary..."
sudo cp /usr/local/bin/gitmem /usr/local/bin/gitmem.backup.$(date +%Y%m%d_%H%M%S)

echo ""
echo "3. Installing fixed binary..."
sudo cp ./target/release/gitmem /usr/local/bin/gitmem

echo ""
echo "4. Verifying installation..."
/usr/local/bin/gitmem --version

echo ""
echo "✅ Binary updated successfully!"
echo ""
echo "Next steps:"
echo "1. Restart Cursor completely (Cmd+Q to quit, then reopen)"
echo "2. Test the fix by running:"
echo "   write_note with title=\"Test\" and content=\"Testing the fix\""

