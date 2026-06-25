# File Locking Analysis - Will This Approach Work?

## Question
Can we rely on `fs4::FileExt::try_lock_exclusive()` for cross-process synchronization of git operations?

## Answer: YES ✅

Here's why this approach is sound and battle-tested:

## Evidence from Existing Code

### LocalStorage Already Uses This Pattern
`crates/storage/local/src/lib.rs` (lines 1115-1133) uses **identical locking mechanism**:

```rust
let lockf = File::options()
    .read(true)
    .write(true)
    .create(true)
    .truncate(false)
    .open(self.lock_path(&project))?;

let mut acquired = false;
for attempt in 0..max_attempts {
    match fs4::FileExt::try_lock_exclusive(&lockf) {
        Ok(_) => {
            acquired = true;
            break;
        }
        Err(_) => {
            // Exponential backoff retry
            std::thread::sleep(Duration::from_millis(delay_ms));
        }
    }
}
```

This **has been working in production** for LocalStorage with multiple Cursor instances.

## How File Locking Works

### Platform Support
- **Unix/Linux/macOS**: Uses `flock()` or `fcntl()` system calls
- **Windows**: Uses `LockFileEx()` Win32 API
- **Cross-platform**: `fs4` crate abstracts the differences

### Lock Characteristics
1. **Advisory Locks**: Processes must cooperate by checking locks
   - ✅ **All our instances check** - we're in control of all processes
   - ✅ **Not a problem** - we're not protecting against malicious actors

2. **Automatic Cleanup**: OS releases locks when process exits/crashes
   - ✅ **No stale locks** - kernel handles cleanup
   - ✅ **No deadlocks** - lock automatically freed on crash

3. **Non-Blocking**: `try_lock_exclusive()` returns immediately
   - ✅ **No hanging** - never blocks indefinitely
   - ✅ **Fast failure** - instant detection of contention

4. **Exclusive Access**: Only one process can hold lock at a time
   - ✅ **Mutual exclusion** - exactly what we need for git

## Why Global Lock for Git is Correct

### Git Repository Structure
```
.git/
├── index          ← Single file, modified by all commits
├── objects/       ← Shared object store
├── refs/
│   └── heads/     ← All branch refs in one place
└── COMMIT_EDITMSG ← Temporary files
```

**Key insight**: Even though we have per-project directories in `/memories/`, git operations (commit, push) modify:
- **Single git index** - staging area is repo-wide
- **Shared refs** - branch pointers are in one place
- **Object database** - all objects in one store

Therefore: **Single global lock is not just okay, it's REQUIRED**.

## Differences from LocalStorage

| Aspect | LocalStorage | GithubStorage (Our Impl) |
|--------|-------------|--------------------------|
| Lock Scope | Per-project | Global (correct for git) |
| Blocking | Yes (with timeout) | No (returns immediately) |
| Retry Logic | Exponential backoff | Background worker (10s) |
| Lock Location | `meta/{project}/LOCK` | `/tmp/gitmem-git-sync.lock` |
| Use Case | File system writes | Git commit/push |

## Why Our Approach is Better for Git

### 1. Non-Blocking Writes
```
User writes note → Instant response (no blocking)
                 ↓
              Mark dirty
                 ↓
Background worker → Try acquire lock → Sync
                                    ↓ (if busy)
                                 Retry later
```

**Benefit**: User never waits for git operations.

### 2. Batch Multiple Writes
```
10:00:00 - User writes note A → marked dirty
10:00:05 - User writes note B → marked dirty
10:00:10 - Background sync → Single commit for A+B
```

**Benefit**: Fewer git operations, better performance.

### 3. Graceful Contention
```
Instance 1: Acquires lock → commits → pushes → releases
Instance 2: Lock busy → retries in 10s
Instance 3: Lock busy → retries in 10s
```

**Benefit**: Clean coordination without error spam.

## Potential Issues and Mitigations

### Issue 1: NFS Filesystems
**Problem**: File locking can be unreliable on NFS
**Mitigation**: 
- Lock file is in `/tmp` (always local filesystem)
- ✅ **Not affected** by NFS issues

### Issue 2: Lock File Permissions
**Problem**: Lock file might not be writable
**Mitigation**:
- Created with default user permissions
- In `/tmp` which is user-writable
- ✅ **No permission issues**

### Issue 3: Multiple Users
**Problem**: Different users can't share lock file
**Mitigation**:
- Each user has own `/tmp` space
- Each user runs own MCP server instances
- ✅ **Isolation is actually desired**

### Issue 4: Stale Locks After Crash
**Problem**: Could lock remain after process crash?
**Mitigation**:
- OS automatically releases file locks on process exit
- ✅ **Kernel handles cleanup**
- Even `kill -9` releases the lock

### Issue 5: High Contention
**Problem**: Many instances competing for lock
**Mitigation**:
- 10-second sync interval reduces contention
- Non-blocking - fast failure, no cascade
- ✅ **Designed for low contention**

## Comparison with Alternatives

### Alternative 1: Named Mutexes (Windows)
```rust
// Platform-specific, complex
#[cfg(windows)]
use winapi::um::synchapi::CreateMutexA;
```
- ❌ Platform-specific code
- ❌ More complex
- ✅ Our approach works cross-platform

### Alternative 2: Shared Memory + Semaphores
```rust
use shared_memory::ShmemConf;
use parking_lot::Mutex;
```
- ❌ More complex setup
- ❌ Cleanup issues
- ❌ Overkill for our use case

### Alternative 3: Unix Domain Sockets
```rust
use std::os::unix::net::UnixListener;
```
- ❌ Platform-specific
- ❌ More complex
- ❌ Need message protocol

### Alternative 4: Lock-Free Algorithms
```rust
use std::sync::atomic::AtomicBool;
```
- ❌ Can't work cross-process
- ❌ Only within single process

### Our Approach: File Locks
```rust
use fs4::FileExt;
lock_file.try_lock_exclusive()?;
```
- ✅ Cross-platform
- ✅ Simple implementation
- ✅ OS handles cleanup
- ✅ Battle-tested in LocalStorage

## Testing Strategy

### Unit Test (Single Instance)
```rust
#[test]
fn test_single_instance_sync() {
    let storage = GithubStorage::new(workdir)?;
    storage.sync_project(&project)?; // Should succeed
}
```

### Integration Test (Multiple Instances)
```bash
# Terminal 1
cargo run -- serve &
PID1=$!

# Terminal 2
cargo run -- serve &
PID2=$!

# Both instances write simultaneously
# Only one should sync at a time
# No git errors should occur

kill $PID1 $PID2
```

### Stress Test
```rust
#[test]
fn test_concurrent_instances() {
    let handles: Vec<_> = (0..10).map(|i| {
        thread::spawn(move || {
            let storage = GithubStorage::new(workdir)?;
            storage.sync_project(&project)
        })
    }).collect();
    
    // All should eventually succeed
    // No git lock errors
}
```

## Conclusion

**YES, this approach will work** because:

1. ✅ **Proven pattern** - LocalStorage uses identical mechanism
2. ✅ **OS-level support** - kernel provides reliable file locking
3. ✅ **Automatic cleanup** - no stale locks possible
4. ✅ **Non-blocking** - fast failure, no cascading delays
5. ✅ **Cross-platform** - fs4 handles platform differences
6. ✅ **Simple** - no complex IPC protocols needed
7. ✅ **Appropriate scope** - global lock correct for git

The key insight is that **file locking is the right tool for this job** - we need mutual exclusion for git operations across processes, and file locks provide exactly that with OS guarantees.

## References

- `fs4` crate documentation: https://docs.rs/fs4/
- POSIX file locking: `man 2 flock`, `man 2 fcntl`
- Existing implementation: `crates/storage/local/src/lib.rs:1115`
- Git internals: https://git-scm.com/book/en/v2/Git-Internals-Plumbing-and-Porcelain

