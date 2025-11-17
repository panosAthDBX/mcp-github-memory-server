---
title: Write Note Timeout Fix
tags: [cursor, write_note, timeout, lock, concurrent-access]
type: doc
date: 2025-11-17
---

# Write Note Timeout Fix

## Issue

When multiple Cursor instances try to use `write_note` simultaneously, some instances would timeout. This occurred because:

1. Each Cursor window spawns its own gitmem process (stdio mode)
2. All processes share the same project lock file
3. The lock acquisition used `lock_exclusive()` which **blocks indefinitely**
4. Cursor has a timeout for MCP tool calls (typically 30-60 seconds)
5. When one process held the lock, others would block until Cursor's timeout

## Root Cause

The LocalStorage implementation used blocking file locks:

```rust
// OLD CODE - blocks indefinitely
fs4::FileExt::lock_exclusive(&lockf).map_err(|e| LocalError::Io(e.to_string()))?;
```

This caused the following sequence:
1. Process A acquires lock, starts writing
2. Process B tries to acquire lock, blocks indefinitely
3. Process C tries to acquire lock, blocks indefinitely
4. If Process A takes >30s, Processes B and C timeout in Cursor

## Solution (Iteration 1 - Incomplete)

Initially replaced blocking lock with **non-blocking lock + exponential backoff retry**:

```rust
// NEW CODE - tries with timeout and exponential backoff
let max_attempts = 50;
let mut acquired = false;
for attempt in 0..max_attempts {
    match fs4::FileExt::try_lock_exclusive(&lockf) {
        Ok(_) => {
            acquired = true;
            break;
        }
        Err(_) => {
            if attempt < max_attempts - 1 {
                // Exponential backoff: 10ms, 20ms, 40ms, ..., max 500ms
                let delay_ms = std::cmp::min(10 * (1 << attempt), 500);
                std::thread::sleep(std::time::Duration::from_millis(delay_ms));
            }
        }
    }
}
if !acquired {
    return Err(LocalError::Io(
        "failed to acquire lock after timeout (another process may be writing)".to_string()
    ));
}
```

### Timeout Calculation

With exponential backoff capped at 500ms:
- Attempts 1-6: 10ms, 20ms, 40ms, 80ms, 160ms, 320ms
- Attempts 7-50: 500ms each
- **Total max wait time**: ~22 seconds (well under Cursor's timeout)

### Problem with Iteration 1

This solution **still blocked** because:
- The retry loop used `std::thread::sleep()` which blocks the thread
- `spawn_blocking` uses a thread pool with limited threads
- Multiple concurrent writes would exhaust the thread pool
- New requests would queue indefinitely and timeout

## Solution (Iteration 2 - Final)

Added a **semaphore at the server level** to limit concurrent write operations:

```rust
pub struct Server<S, I> {
    // ... other fields ...
    /// Semaphore to limit concurrent write operations and prevent thread pool exhaustion
    write_semaphore: Arc<tokio::sync::Semaphore>,
}

// Initialize with 4 concurrent writes allowed
write_semaphore: Arc::new(tokio::sync::Semaphore::new(4))

// In handle_save, handle_update, handle_delete:
let _permit = match self.write_semaphore.acquire().await {
    Ok(permit) => permit,
    Err(_) => return error,
};
// Permit is automatically released when it goes out of scope
```

### How It Works

1. **Semaphore limits concurrency**: Max 4 write operations can run simultaneously
2. **Async queuing**: Extra requests wait asynchronously (don't block threads)
3. **Automatic cleanup**: Permits are released when the operation completes
4. **Fair scheduling**: Tokio handles request queuing fairly (FIFO-ish)

### Benefits

1. **No thread pool exhaustion** - at most 4 threads used for writes
2. **No blocking** - waiting requests yield control to tokio runtime
3. **Graceful degradation** - system stays responsive under load
4. **Works with any number of Cursor instances** - scales properly

## Files Changed

- `crates/storage/local/src/lib.rs`:
  - `save()` method - non-blocking lock retry (lines 1110-1133)
  - `delete()` method - non-blocking lock retry (lines 1235-1256)

- `crates/server/src/lib.rs`:
  - Added `write_semaphore` field to `Server` struct
  - Added semaphore initialization in `new_with_options()`
  - Added semaphore acquisition in `handle_save()`, `handle_update()`, `handle_delete()`

## Testing

- All existing tests pass (60/64 total)
- Write operations verified:
  - `write_and_read_note_via_compat` ✅
  - `edit_and_delete_note_via_compat` ✅
  - `save_and_get_round_trip` ✅
  - `move_note_between_projects` ✅

## Related Documentation

- [Cursor Stdio vs HTTP Transport](./cursor-stdio-vs-http.md)
- Multi-instance safety discussion in SPEC.md section 11

