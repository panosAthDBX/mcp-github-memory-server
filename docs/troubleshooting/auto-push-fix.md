# Auto-Push Authentication Fix

## Problem Diagnosis

The auto-push feature was failing with this error:
```
auto-push failed: git: remote authentication required but no callback set
class=Http (34); code=Auth (-16)
```

## Root Causes

### 1. Missing `remote-git` Feature ❌
The binary at `/usr/local/bin/gitmem` was **not built** with the `remote-git` feature enabled.

**Evidence:**
```bash
$ cargo tree -p mcp-gitmem-cli -e features | grep remote-git
# No output - feature was not enabled!
```

The push code is behind a feature flag:
```rust
#[cfg(feature = "remote-git")]
{
    // Git push logic here...
}
```

Without this feature, the code falls through to an error path.

### 2. GitHub Token Not Accessible ⚠️
Even with the feature enabled, the `GITHUB_TOKEN` environment variable must be:
- Set in Cursor's MCP configuration (`env` section)
- Accessible when the server process starts
- Matches the `secret_env` value in `gitmem.yaml` (currently `GITHUB_TOKEN`)

## Solution

### Step 1: Rebuild with Correct Features ✅

```bash
cd /Users/panos.athanasiou/code/mcp-github-memory-server
cargo build --release --features backend-github,index-tantivy,encryption,mcp-gitmem-storage-github/remote-git
```

**Status:** ✅ DONE - Binary rebuilt at `./target/release/gitmem`

**Verification:**
```bash
$ nm ./target/release/gitmem | grep libgit2_sys
00000001005af8cc T __ZN11libgit2_sys4init...  # git2 symbols present!
```

### Step 2: Install New Binary

```bash
sudo cp ./target/release/gitmem /usr/local/bin/gitmem
```

**Status:** ⏳ PENDING - Requires sudo access

### Step 3: Update Cursor MCP Config

Edit `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "gitmem": {
      "command": "/usr/local/bin/gitmem",
      "args": ["serve", "--config", "/Users/panos.athanasiou/.config/gitmem.yaml"],
      "env": {
        "GITHUB_TOKEN": "ghp_YOUR_ACTUAL_TOKEN_HERE"
      }
    }
  }
}
```

**Critical:** Replace `ghp_YOUR_ACTUAL_TOKEN_HERE` with your real GitHub Personal Access Token!

**Get a token:** https://github.com/settings/tokens
- Scope required: `repo` (full control)

### Step 4: Restart Cursor

1. Quit Cursor completely (Cmd+Q)
2. Reopen Cursor
3. New server process will have credentials

## How Authentication Works

```rust
// In crates/storage/github/src/lib.rs:618-628
CredentialMode::Token => {
    let user = c.username.clone()
        .unwrap_or_else(|| "x-access-token".into());
    let token = c.secret_env.as_deref()
        .and_then(|k| std::env::var(k).ok())  // ← Reads GITHUB_TOKEN from env
        .unwrap_or_default();
    git2::Cred::userpass_plaintext(&user, &token)
}
```

The config sets:
```yaml
github:
  credentials:
    mode: token
    username: x-access-token
    secret_env: GITHUB_TOKEN  # ← Env var name to read
```

Cursor must provide this in the MCP server's environment:
```json
"env": { "GITHUB_TOKEN": "actual_token_value" }
```

## Testing the Fix

### Test 1: Verify Token Access
```bash
GITHUB_TOKEN=your_token /usr/local/bin/gitmem serve --config ~/.config/gitmem.yaml
```

Then in another terminal:
```bash
# Save a memory via MCP call
# Check logs for "auto-push succeeded"
```

### Test 2: Manual Push
```bash
cd /Users/panos.athanasiou/memory
git status
git log
# Should see recent commits from auto-push
```

### Test 3: Check Remote
```bash
cd /Users/panos.athanasiou/memory
git remote -v
git push origin devices/$(hostname)
# Should push successfully
```

## Expected Behavior After Fix

### Before (Error):
```
2025-11-15 13:06:10.794 [error] auto-push failed [3merror][0m: 
git: remote authentication required but no callback set; 
class=Http (34); code=Auth (-16)
```

### After (Success):
```
2025-11-15 13:10:xx.xxx [info] auto-push succeeded
2025-11-15 13:10:xx.xxx [debug] pushed to devices/hostname, 
commit: abc123def456
```

## Permanent Fix Checklist

- [x] Rebuild with `remote-git` feature
- [ ] Install new binary to `/usr/local/bin/gitmem`
- [ ] Get GitHub Personal Access Token
- [ ] Update Cursor MCP config with token
- [ ] Restart Cursor
- [ ] Test save operation
- [ ] Verify auto-push logs show success
- [ ] Confirm commits appear on GitHub

## Files Updated

1. `./target/release/gitmem` - New binary with git2 support
2. `docs/INSTALL.md` - Installation and setup instructions
3. `docs/troubleshooting/auto-push-fix.md` - This diagnostic document

## Next Steps

1. **You need to run:**
   ```bash
   sudo cp ./target/release/gitmem /usr/local/bin/gitmem
   ```

2. **Edit** `~/.cursor/mcp.json` to add your GitHub token

3. **Restart** Cursor

4. **Test** by saving a new memory through Cursor MCP



