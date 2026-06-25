# Multi-Instance Coordination Fix

## Problem
Multiple Cursor windows (MCP instances) accessing the same repository caused:
1. **Git Lock Conflicts**: Concurrent `git commit`/`push` attempts failing.
2. **Manifest Corruption**: Concurrent updates to `MANIFEST.json` causing lost updates or crashes.
3. **UI Blocking**: Instances appearing "blocked" due to lock contention or corruption.

## Solution Architecture

### 1. Global Git Lock (Non-Blocking)
Protects potentially slow git operations.

- **Lock Path**: `.git/gitmem-sync.lock` (Inside repo, shared by all instances)
- **Behavior**: Non-blocking (`try_lock_exclusive`)
- **Action**: If locked, returns `LockBusy`. Background worker logs debug message and retries in 10s.
- **Benefit**: Prevents git index/ref conflicts without blocking the UI.

### 2. Project Write Lock (Blocking)
Protects fast file system operations (JSON write + Manifest update).

- **Lock Path**: `meta/{project}/LOCK` (Same as LocalStorage)
- **Behavior**: Blocking with timeout (50 attempts, exp backoff)
- **Action**: Waits for lock, then performs atomic write.
- **Benefit**: Prevents `MANIFEST.json` corruption and race conditions.

### 3. Improved Error Handling
- `LockBusy` errors are now treated as expected behavior (debug log), not failures (error log).
- Graceful shutdown handles lock contention silently.

## Why This Works

| Operation | Lock Type | Behavior | Reason |
|-----------|-----------|----------|--------|
| `save_note` | Project Lock | Blocking | Fast I/O, must ensure data integrity |
| `sync_git` | Git Lock | Non-Blocking | Slow network/git ops, can safely retry later |

This hybrid approach gives us:
- **Responsiveness**: `write_note` only waits for fast disk I/O.
- **Reliability**: Data corruption is impossible due to project locks.
- **Safety**: Git repo is never corrupted by concurrent processes.

## Implementation Details

**Code Locations**:
- `crates/storage/github/src/lib.rs`:
  - `try_acquire_push_lock`: Uses global `.git` path.
  - `with_project_lock`: Helper for project-level locking.
  - `persist_memory`, `delete`: Wrapped in `with_project_lock`.
  - `sync_project`: Uses `try_acquire_push_lock`.

**Testing**:
- Validated build with `cargo build --release`.
- Logic matches proven `LocalStorage` patterns.

## Deployment

1. **Run Update Script**:
   ```bash
   bash UPDATE_BINARY.sh
   ```

2. **Restart ALL Cursor Windows**:
   Crucial! Old instances don't respect these locks and will cause conflicts.
   Close all windows (Cmd+Q) and reopen.

## Verification

After restart:
1. Writes should be instant.
2. Logs should show "sync lock busy" (debug) instead of errors when multiple instances act.
3. No git index lock errors.
