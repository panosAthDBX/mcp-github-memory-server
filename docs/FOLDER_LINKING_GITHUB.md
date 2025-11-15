# External Folder Linking with GitHub Backend

## Status: ✅ FULLY IMPLEMENTED

External folder linking for the GitHub backend is now **fully implemented**! You can link external directories (like Obsidian vaults, documentation folders, or any markdown collection) and automatically import them as memories with automatic GitHub sync.

## What is Folder Linking?

Folder linking allows you to monitor external directories and automatically import them as memories. Changes are tracked and synced automatically to your GitHub repository.

## Current Status

### ✅ Fully Implemented
- ✅ Server routing for folder linking with GitHub backend
- ✅ Full folder scanning implementation
- ✅ Automatic commit and push of scanned files to GitHub
- ✅ Front-matter parsing from markdown files
- ✅ File change detection and updates
- ✅ Deleted file tracking
- ✅ Glob pattern matching for include/exclude
- ✅ Watch mechanism with configurable polling
- ✅ Integration with auto-push feature
- ✅ Complete parity with local storage implementation

## How to Use It

You can now link external folders like this:

```javascript
// Via MCP tool
await mcp.call("project.link_folder", {
  project: "default",
  path: "/Users/you/code/mcp-github-memory-server/docs",
  include: ["**/*.md"],
  exclude: ["**/node_modules/**"],
  watchMode: "poll",
  pollIntervalMs: 30000
});
```

The implementation:
1. **Scans** the specified folder for matching files
2. **Parses** markdown files and extracts front-matter
3. **Converts** each file to a memory record
4. **Commits** new memories to the GitHub working tree automatically
5. **Pushes** changes to your GitHub repository (if auto-push is enabled)
6. **Watches** for changes and resyncs automatically

## Getting Started

### Prerequisites

1. **Install the latest version**: Make sure you have the newest binary with folder linking support:
   ```bash
   sudo cp ./target/release/gitmem /usr/local/bin/gitmem
   ```

2. **Restart Cursor**: After installing, restart Cursor completely (Cmd+Q, then reopen) to load the new version.

### Link Your First Folder

#### Via CLI:
```bash
gitmem link-folder \
  --project default \
  --path /Users/you/code/mcp-github-memory-server/docs \
  --include "**/*.md" \
  --exclude "**/node_modules/**" \
  --watch-mode poll \
  --poll-interval 30000
```

#### Via MCP Tool (from code):
```javascript
// Link the folder
await mcp.call("project.link_folder", {
  project: "default",
  path: "/Users/you/code/mcp-github-memory-server/docs",
  include: ["**/*.md"],
  exclude: ["**/node_modules/**"],
  watchMode: "poll",
  pollIntervalMs: 30000
});

// List linked folders
const links = await mcp.call("project.list_links", {
  project: "default"
});

// Trigger a manual rescan
const reports = await mcp.call("memory.sync", {
  direction: "external",
  project: "default"
});
```

### What Happens Next

1. **Initial Scan**: The folder is scanned immediately and all matching `.md` files are imported as memories
2. **Automatic Commits**: Each imported/updated memory is committed to your GitHub repository
3. **Auto-Push**: If auto-push is enabled in your config, changes are pushed to GitHub automatically
4. **Continuous Monitoring**: The folder is polled every 30 seconds (configurable) for changes
5. **Updates Tracked**: Modified files update existing memories, deleted files remove memories

## Implementation Details

### What Gets Imported

- **Markdown files** (`.md`) matching your include patterns
- **Front-matter** is parsed and used to populate memory fields:
  - `title` → Memory title
  - `tags` → Memory tags (in addition to auto-generated tags)
  - `type` → Memory type
  - Other fields are stored in `source.front_matter`

### Memory Metadata

Each imported memory includes rich metadata:
- `source.origin`: "linked_folder"
- `source.relative_path`: Path relative to linked folder root
- `source.file_uri`: Full file:// URI
- `source.checksum_sha256`: Content hash for change detection
- `source.linked_folder_id`: Link ID for tracking
- `source.file_mtime`: Last modified time
- `source.file_size`: File size in bytes
- Tags: `project:<name>` and `linked` are automatically added

### Commit & Push Behavior

- **Automatic Commits**: Every save/update/delete triggers a commit to the local git repository
- **Auto-Push Integration**: If `github.auto_push = true` in your config, changes are pushed immediately
- **Batch-Friendly**: Multiple file changes are batched into efficient commits
- **Error Handling**: Push failures are logged but don't block the import process

## Questions?

- **Will this sync bidirectionally?** No, folder linking is one-way: external folder → gitmem. Changes in gitmem won't modify the original files.
- **What file formats are supported?** Markdown (`.md`) files with optional YAML front-matter.
- **Can I link multiple folders?** Yes, you can link as many folders as you want to a project.
- **Does this work with Obsidian?** Yes! Obsidian vaults are perfect for this feature.
- **How often does it check for changes?** By default every 30 seconds, but you can configure this with `pollIntervalMs`.
- **What happens if a file is deleted?** The corresponding memory is deleted from the repository.
- **Can I manually trigger a rescan?** Yes, use `memory.sync` with `direction: "external"`.

## Troubleshooting

### Folder linking fails
- **Error**: "linked path ... is not a directory"
  - **Solution**: Make sure the path exists and is a directory
- **Error**: "folder already linked"
  - **Solution**: Unlink first with `project.unlink_folder`, then link again
- **Error**: "cannot link a directory inside the GitHub storage root"
  - **Solution**: Don't link folders inside your gitmem storage directory

### Changes aren't being detected
- Check that your include/exclude patterns are correct
- Verify the poll interval isn't too long
- Check logs for scanning errors
- Try a manual rescan with `memory.sync`

### Files not being imported
- Make sure they match your include patterns (default: `**/*.md`)
- Check they're not excluded by exclude patterns
- Verify the files aren't hidden (starting with `.`)
- Check the file encoding is UTF-8

## Example: Link Your Docs Folder

Let's link the docs folder of this project:

```bash
# Install the latest binary
sudo cp ./target/release/gitmem /usr/local/bin/gitmem

# Restart Cursor
# (Cmd+Q, then reopen)

# Now use the MCP tool to link the docs folder
```

Then in your code or MCP client:
```javascript
await mcp.call("project.link_folder", {
  project: "default",
  path: "/Users/you/code/mcp-github-memory-server/docs",
  include: ["**/*.md"]
});
```

All markdown files in the docs folder will now be imported as memories and synced to GitHub!

---

**Status**: ✅ Fully Implemented  
**Last Updated**: 2025-11-15  
**Release**: v0.2.0

