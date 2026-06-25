# Fix for Automatic project:default Tag Issue

## Problem
The `write_note` tool (and other memory save operations) was automatically adding a `project:default` tag to every note/memory, which was undesired behavior.

## Root Cause
The server code was calling `ensure_project_tag(&mut mem, &project)` on every save and update operation, which automatically added the project tag (e.g., `"project:default"`) to the tags array. This was intended for internal project tracking but manifested as visible metadata that users didn't want.

## Solution
Commented out the `ensure_project_tag()` calls since project association is already handled separately through the `project` parameter passed to storage and index methods. The project tags were redundant and not actually used for filtering or searching.

## Changes Made

### 1. Server Code (`crates/server/src/lib.rs`)
- **Line 735**: Commented out `ensure_project_tag` in `handle_save()` 
- **Line 952**: Commented out `ensure_project_tag` in `handle_update()`
- **Line 3319**: Commented out `ensure_project_tag` in linked folder import handler
- **Line 3318**: Removed unnecessary `mut` from `m_save` variable

### 2. Tests Updated (`crates/server/src/lib.rs`)
- **save_with_tags test**: Updated to expect 3 tags instead of 4, removed project:default assertion
- **update_with_tags test**: Updated to expect 2 tags instead of 3, removed project:default from test data and assertions

### 3. Snapshot Tests Updated
- `crates/testing/src/snapshots/mcp_gitmem_testing__conformance__search_slim_items.snap`: Removed all `project:default` tags
- `crates/testing/src/snapshots/mcp_gitmem_testing__conformance__import_fixture_notes.snap`: Removed all `project:default` tags

## Testing
Build completed successfully:
```bash
cargo build --release
```

## Deployment

### Option 1: Manual Binary Update
Run the provided update script (requires sudo):
```bash
bash UPDATE_BINARY.sh
```

### Option 2: Restart Cursor
Simply restart Cursor (Cmd+Q to quit, then reopen) to reload the MCP server with the changes.

## Verification
After deploying, test with:
```
write_note with title="Test" and content="Testing the fix"
```

The returned note should **not** have `project:default` in its tags array, only the tags you explicitly provide (or an empty array if none provided).

## Impact
- **Breaking Change**: No - Existing memories with project tags are unaffected
- **Behavior Change**: Yes - New notes will no longer automatically get project tags
- **API Compatibility**: Yes - All APIs remain the same, only internal behavior changed
- **Backwards Compatible**: Yes - The system still works with existing project tags in stored memories

## Notes
- Project filtering and isolation still works correctly via the `project` parameter
- The `project:default` tags in existing memories are harmless and don't need to be removed
- This fix only prevents new memories from getting the automatic tag


