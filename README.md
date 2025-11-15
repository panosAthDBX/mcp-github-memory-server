# MCP GitHub Memory Server

A high-performance MCP (Model Context Protocol) server that stores memories in GitHub repositories or local filesystems, written in Rust.

[![License](https://img.shields.io/badge/License-Apache%202.0%20OR%20MIT-blue.svg)](LICENSE)
[![Rust Version](https://img.shields.io/badge/rust-1.89%2B-orange.svg)](https://www.rust-lang.org)

## Overview

This MCP server provides drop-in compatibility with the basic memory protocol while offering powerful features like:

- **GitHub Storage**: Store memories in GitHub repositories with full version history
- **Local Storage**: Offline-first local filesystem storage for air-gapped environments
- **Fast Search**: Embedded full-text search using milli-core (LMDB) with BM25 ranking
- **Encryption**: Optional end-to-end encryption using age X25519
- **Multi-Project**: Organize memories across isolated projects
- **Auto-Sync**: Automatic push to remote after every write operation

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/mcp-github-memory-server.git
cd mcp-github-memory-server

# Build the release binary
cargo build --release --features backend-github,index-tantivy,encryption,mcp-gitmem-storage-github/remote-git

# Install using the provided script
./scripts/install.sh
```

**macOS Users**: If you encounter "Killed: 9" errors, run:
```bash
./scripts/fix-macos-security.sh
```

See [docs/troubleshooting/macos-security.md](docs/troubleshooting/macos-security.md) for details.

### Configuration

1. **Get a GitHub Personal Access Token** (for GitHub storage):
   - Visit: https://github.com/settings/tokens
   - Create a token with `repo` scope
   - Save the token securely

2. **Configure your MCP client** (e.g., Cursor):

Create or edit `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "gitmem": {
      "command": "/usr/local/bin/gitmem",
      "args": ["serve", "--config", "/path/to/gitmem.yaml"],
      "env": {
        "GITHUB_TOKEN": "ghp_your_token_here"
      }
    }
  }
}
```

3. **Create a configuration file** (e.g., `~/.config/gitmem.yaml`):

```yaml
server:
  transport: stdio

storage:
  backend: github

github:
  root: /Users/yourname/memory
  auto_push: true
  remote_url: https://github.com/yourusername/memory.git
  credentials:
    mode: token
    username: x-access-token
    secret_env: GITHUB_TOKEN

encryption:
  enabled: false

index:
  engine: tantivy
```

4. **Restart your MCP client** to load the new configuration.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    MCP Client (IDE, Agent)                      │
│           JSON-RPC over stdio or WebSocket                      │
└──────────────┬──────────────────────────────────────────────────┘
               │
        JSON-RPC server (MCP)
               │
┌──────────────▼─────────────────────┐
│        Memory Service Layer        │
│  validation, ID generation, merge  │
└──────────────┬─────────────────────┘
               │
       Storage abstraction
     ┌─────────┴───────────┬────────────┐
     │                     │            │
┌────▼────┐          ┌─────▼─────┐ ┌────▼─────┐
│ GitHub  │          │ Local FS  │ │ Ephemeral│
│ adapter │          │ adapter   │ │ adapter  │
└────┬────┘          └─────┬─────┘ └────┬─────┘
     │                     │            │
     │        ┌────────────▼────────────┐
     │        │   Search Index Engine   │
     │        │  (milli-core or Tantivy)│
     │        └────────────┬────────────┘
     │                     │
     │        ┌────────────▼────────────┐
     │        │   Crypto (optional)     │
     │        │   age X25519            │
     │        └─────────────────────────┘
```

## Features

### MCP Tool Compatibility

Full compatibility with the basic memory protocol plus extended features:

**Core Memory Operations:**
- `memory.save` - Create new memories
- `memory.get` - Retrieve by ID
- `memory.search` - Full-text search with filters
- `memory.update` - Patch existing memories
- `memory.delete` - Soft or hard delete
- `memory.import.basic` - Import from JSONL
- `memory.sync` - Sync with storage backend

**Project Management:**
- `list_memory_projects` - List all projects
- `create_memory_project` - Create new project
- `delete_memory_project` - Remove project

**Knowledge Base (Basic Memory compatibility):**
- `write_note`, `read_note`, `edit_note`, `delete_note`
- `search_notes`, `recent_activity`, `build_context`
- `move_note` - Move notes between projects

**External Folder Linking:**
- `project.link_folder` - Link external folders (e.g., Obsidian vaults)
- `project.unlink_folder` - Remove linked folders
- `project.list_links` - List all folder links

### Storage Backends

**GitHub Storage:**
- Full git history and audit trail
- Device-specific branches (`devices/<hostname>`)
- Auto-push on every write (optional)
- Conflict resolution with three-way merge
- Pull request workflow (optional)

**Local Storage:**
- Offline-first operation
- Atomic file operations with fsync
- File locks for concurrent access
- Same on-disk layout as GitHub for easy migration

### Search & Indexing

- **milli-core (default)**: Embedded LMDB index with BM25 scoring
- **Tantivy (optional)**: Alternative high-performance search engine
- **Async indexing**: Non-blocking index updates via background worker
- **TTL enforcement**: Automatic expiry at query time
- **Field boosting**: Prioritize title matches over content

### Security

- **Optional encryption**: Age X25519 end-to-end encryption
- **Multiple recipients**: Share encrypted memories securely
- **Credential management**: Environment variables, OS keychain, or helpers
- **Least privilege**: Fine-grained GitHub token scopes
- **PII redaction**: Configurable content filters

## Documentation

- **[SPEC.md](docs/SPEC.md)** - Complete technical specification
- **[AGENTS.md](docs/AGENTS.md)** - Development guide for humans and AI agents
- **[INSTALL.md](docs/INSTALL.md)** - Detailed installation instructions
- **[Integration Guide](docs/integration/stdio-mcp.md)** - Cursor/Codex configuration
- **[Migration Guide](docs/migration/guide.md)** - Migrating from basic memory
- **[Troubleshooting](docs/troubleshooting/)** - Common issues and solutions

## Development

### Prerequisites

- Rust 1.89.0 or later (specified in `rust-toolchain.toml`)
- Git
- Optional: Docker for containerized builds

### Building

```bash
# Default build with milli-core index
cargo build --workspace

# With all features
cargo build --workspace --features backend-github,backend-local,index-tantivy,encryption,transport-stdio,mcp-gitmem-storage-github/remote-git

# With real Tantivy backend (non-Apple ARM)
cargo build --workspace --features real_tantivy,backend-github,index-tantivy,encryption

# Release build
cargo build --release --features backend-github,index-tantivy,encryption,mcp-gitmem-storage-github/remote-git
```

### Testing

```bash
# Run all tests
cargo test --workspace

# Run with all features
cargo test --workspace --all-features

# Run benchmarks
cargo bench -p mcp-gitmem-benchmarks --bench performance
```

### Code Quality

```bash
# Format code
cargo fmt --all

# Run linter
cargo clippy --all-targets -- -D warnings -D clippy::pedantic -A clippy::module_name_repetitions

# Check for security issues
cargo audit
```

### Project Structure

```
.
├── crates/
│   ├── core/           # Domain model, validation, types
│   ├── proto/          # MCP protocol definitions
│   ├── storage/
│   │   ├── github/     # GitHub adapter
│   │   ├── local/      # Local filesystem adapter
│   │   └── ephemeral/  # In-memory adapter (testing)
│   ├── index/
│   │   └── tantivy/    # Search index implementations
│   ├── crypto/         # Encryption (age X25519)
│   ├── server/         # MCP server runtime
│   ├── cli/            # Command-line interface
│   ├── compat/         # Basic memory compatibility
│   ├── testing/        # Test utilities and fixtures
│   └── benchmarks/     # Performance benchmarks
├── docs/               # Documentation
├── examples/           # Sample configurations
└── scripts/            # Installation and utility scripts
```

## Performance

- **Save**: p50 < 5ms (local), < 50ms (with GitHub batch push)
- **Search**: p95 < 50ms on 50k memories
- **Import**: > 1k writes/sec to local index
- **Memory**: < 50 MiB baseline idle

See [benchmarks](crates/benchmarks/) for detailed performance data.

## Contributing

Contributions are welcome! Please read [AGENTS.md](docs/AGENTS.md) for:
- Architecture guidelines
- Coding standards
- Testing requirements
- Submission process

### Development Workflow

1. Fork the repository
2. Create a feature branch
3. Make your changes following the coding standards
4. Run tests and linters
5. Submit a pull request

## Roadmap

### Current (v1.0)
- ✅ Basic memory protocol compatibility
- ✅ GitHub and local storage backends
- ✅ Full-text search with milli-core
- ✅ Optional encryption
- ✅ Auto-push support
- ✅ External folder linking

### v1.1 (Planned)
- Webhook support for remote sync
- Automatic PR workflow
- Conflict resolution UI
- Enhanced observability (OpenTelemetry)

### v1.2 (Future)
- Optional embeddings with local models
- Hybrid search (BM25 + vector)
- Re-ranking strategies
- Native platform watchers for linked folders

### v2.0 (Future)
- Multi-tenant support
- Per-tenant encryption keys
- Policy-based access control
- Collaborative memory workflows

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Acknowledgments

- Built on the [Model Context Protocol](https://modelcontextprotocol.io/)
- Inspired by the basic memory MCP servers
- Powered by [milli](https://github.com/meilisearch/milli) and [Tantivy](https://github.com/quickwit-oss/tantivy)
- Encryption via [age](https://github.com/FiloSottile/age)

## Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/mcp-github-memory-server/issues)
- **Documentation**: [docs/](docs/)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/mcp-github-memory-server/discussions)

---

Made with ❤️ by the MCP GitMem Team

