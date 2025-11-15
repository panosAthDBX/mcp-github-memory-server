# macOS Security Fix for "Killed: 9" Error

## Problem

When running `/usr/local/bin/gitmem --version`, you get:
```
Killed: 9
```

This is macOS **Gatekeeper** blocking the binary because it was built locally.

## Root Cause

The binary has `com.apple.provenance` attributes that make macOS suspicious of it:

```bash
$ xattr -l /usr/local/bin/gitmem
com.apple.provenance:
```

This triggers macOS security policies that kill the process with SIGKILL (signal 9).

## Solution

### Quick Fix (Run this now)

```bash
cd /Users/panos.athanasiou/code/mcp-github-memory-server
./scripts/fix-macos-security.sh
```

This script will:
1. Remove quarantine/provenance attributes
2. Re-sign the binary with ad-hoc signature
3. Verify the binary works

### Manual Fix (Alternative)

If the script doesn't work, run these commands manually:

```bash
# Remove security attributes
sudo xattr -d com.apple.quarantine /usr/local/bin/gitmem
sudo xattr -d com.apple.provenance /usr/local/bin/gitmem

# Re-sign the binary
sudo codesign --force --deep --sign - /usr/local/bin/gitmem

# Test it
/usr/local/bin/gitmem --version
```

### If Still Blocked

If you still get "Killed: 9" after the above:

1. **Open System Settings** (System Preferences on older macOS)
2. Go to **Privacy & Security**
3. Scroll down to the **Security** section
4. Look for a message like: *"gitmem" was blocked from use because it is not from an identified developer*
5. Click **"Allow Anyway"** or **"Open Anyway"**
6. Try running the binary again

### Alternative: Add to Gatekeeper Allowlist

```bash
sudo spctl --add /usr/local/bin/gitmem
sudo spctl --enable --label 'Developer ID'
```

## Why This Happens

macOS Gatekeeper prevents execution of:
1. Binaries from unknown developers
2. Binaries downloaded from the internet (quarantine attribute)
3. Binaries with certain provenance metadata

Since you built this locally with `cargo build`, it's not signed with an Apple Developer ID certificate, so macOS treats it as potentially unsafe.

## Prevention

The updated `scripts/install.sh` script now automatically:
1. Removes quarantine/provenance attributes
2. Re-signs with ad-hoc signature

So future installs should work without manual intervention.

## Verification

After applying the fix, verify:

```bash
# Check attributes (should be empty or minimal)
xattr -l /usr/local/bin/gitmem

# Check signature
codesign -dv /usr/local/bin/gitmem 2>&1

# Test binary
/usr/local/bin/gitmem --version
```

Expected output:
```
gitmem 0.1.0
```

## Technical Details

The error happens because:
- macOS sends SIGKILL (signal 9) to processes that violate security policies
- No cleanup or error message is possible (immediate termination)
- The kernel logs the block, but it's not visible to the user

The fix works by:
- Removing the attributes that trigger the security check
- Ad-hoc signing tells macOS: "I'm the developer, I trust this binary"
- This is safe for locally-built development tools

## Related Commands

```bash
# Check what killed the process
log show --predicate 'eventMessage contains "gitmem"' --last 1m

# See Gatekeeper decisions
sudo log show --predicate 'subsystem == "com.apple.security.syspolicy"' --last 1h

# Check if binary is blocked
spctl -a -v /usr/local/bin/gitmem
```

## See Also

- [Apple Technical Note: Resolving Gatekeeper Issues](https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution)
- [Signing Binaries on macOS](https://developer.apple.com/documentation/security/signing)



