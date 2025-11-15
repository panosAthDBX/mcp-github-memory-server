# MCP GitHub Memory Server - Documentation

Welcome to the documentation for the MCP GitHub Memory Server!

## Quick Links

### Getting Started
- **[Installation Guide](INSTALL.md)** - Step-by-step installation instructions
- **[Daemon Setup](DAEMON_SETUP.md)** - Run as a daemon with WebSocket/HTTP transport
- **[README](../README.md)** - Project overview and quick start

### Technical Documentation
- **[Technical Specification](SPEC.md)** - Complete technical spec and architecture
- **[Development Guide](AGENTS.md)** - Coding standards, guidelines, and checklists

### Implementation
- **[Implementation Plan (Original)](IMPLEMENTATION_PLAN.md)** - Original phased implementation plan
- **[Implementation Plan (Updated)](implementation-plan.md)** - Updated plan aligned with Basic Memory OSS

### Integration
- **[MCP Integration Guide](integration/stdio-mcp.md)** - Configure Cursor and other MCP clients
- **[Migration Guide](migration/guide.md)** - Migrate from basic memory servers

### Troubleshooting
- **[Auto-Push Fix](troubleshooting/auto-push-fix.md)** - Fix GitHub authentication issues
- **[macOS Security](troubleshooting/macos-security.md)** - Resolve "Killed: 9" errors on macOS
- **[Cursor Transport (Stdio vs HTTP)](troubleshooting/cursor-stdio-vs-http.md)** - Why Cursor needs stdio mode

### Development Notes
- **[Status Updates](notes/)** - Development progress and notes

## Documentation Structure

```
docs/
├── README.md                           # This file
├── SPEC.md                             # Technical specification
├── AGENTS.md                           # Development guide
├── INSTALL.md                          # Installation instructions
├── DAEMON_SETUP.md                     # Daemon mode with WebSocket/HTTP
├── CHANGELOG.md                        # Version history
├── IMPLEMENTATION_PLAN.md              # Original implementation plan
├── implementation-plan.md              # Updated implementation plan
├── integration/
│   └── stdio-mcp.md                   # MCP client integration
├── migration/
│   └── guide.md                       # Migration from basic memory
├── troubleshooting/
│   ├── auto-push-fix.md              # GitHub auth issues
│   ├── macos-security.md             # macOS security fixes
│   └── cursor-stdio-vs-http.md       # Cursor transport modes
└── notes/
    └── 2025-10-27-status.md          # Development status
```

## Contributing to Documentation

When adding or updating documentation:

1. **Keep it current**: Update docs alongside code changes
2. **Cross-reference**: Link to related docs where appropriate
3. **Be specific**: Include examples, code snippets, and screenshots
4. **Follow structure**: Place new docs in the appropriate subdirectory
5. **Update this index**: Add new documents to the Quick Links section

## Documentation Standards

- Use **Markdown** for all documentation
- Include **code examples** with syntax highlighting
- Add **diagrams** for architecture and flows (Mermaid preferred)
- Keep **line length** reasonable (80-100 characters)
- Use **relative links** for internal references
- Include **version info** when relevant

## Getting Help

- **Issues**: [GitHub Issues](https://github.com/yourusername/mcp-github-memory-server/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/mcp-github-memory-server/discussions)
- **Spec Questions**: See [SPEC.md](SPEC.md)
- **Dev Questions**: See [AGENTS.md](AGENTS.md)

