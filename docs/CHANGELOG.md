# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project structure and workspace setup
- Core memory model with validation
- GitHub storage adapter with git2 support
- Local filesystem storage adapter
- Ephemeral storage adapter for testing
- Search indexing with milli-core (default) and optional Tantivy
- Optional end-to-end encryption using age X25519
- MCP server with stdio and WebSocket transports
- CLI tool (`gitmem`) with serve, import, and sync commands
- Full basic memory protocol compatibility layer
- Project management and isolation
- External folder linking for Obsidian/Markdown vaults
- Auto-push support for automatic GitHub sync
- Async index queue for non-blocking writes
- Multi-project support with namespace isolation

### Features
- **Storage Backends**: GitHub (with git2), Local filesystem, Ephemeral
- **Search Engines**: milli-core (LMDB, default), Tantivy (optional, feature-gated)
- **Encryption**: Age X25519 with multiple recipients
- **MCP Tools**: memory.*, write_note, read_note, search_notes, and more
- **Auto-sync**: Optional push after every write operation
- **Folder Linking**: Link external directories with glob patterns and watchers

### Documentation
- Technical specification (SPEC.md)
- Development guide (AGENTS.md)
- Installation guide (INSTALL.md)
- Integration guides for MCP clients
- Troubleshooting guides for common issues

### Performance
- Save: p50 < 5ms (local)
- Search: p95 < 50ms on 50k memories
- Import: > 1k writes/sec
- Memory: < 50 MiB idle baseline

### Known Issues
- Tantivy backend requires SSSE3 on Apple Silicon (use milli-core instead)
- Native file watchers not yet implemented (polling only)
- PR workflow for GitHub storage is optional and not fully automated

### Coming Soon
- Webhook support for remote sync
- Native platform file watchers (FSEvents on macOS)
- Enhanced conflict resolution UI
- OpenTelemetry exporter
- Multi-tenant support

## [0.1.0] - 2025-11-15

### Added
- Initial release
- Core functionality implemented
- Documentation complete
- Ready for first commit

---

## Version Tags

This project uses the following versioning scheme:
- `server-vX.Y.Z` for server releases
- `cli-vX.Y.Z` for CLI releases
- Both follow semantic versioning

## Migration Notes

See [migration/guide.md](migration/guide.md) for detailed migration instructions from other memory servers.

## Upgrade Guide

### From Previous Versions

This is the initial release, so no upgrade path exists yet.

### Future Versions

Check this section for breaking changes and upgrade instructions in future releases.



## Test Update
This is a test to verify auto-push works on folder sync.


## Folder Monitoring Test
Testing that auto-push works with GitHub backend folder monitoring - Sat Nov 15 16:22:06 GMT 2025


## Lock Testing 2025-11-15 19:52:30
Testing file-based locking for multi-instance coordination.
