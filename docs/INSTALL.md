# GitMem Installation & Setup

## 1. Install the Binary

```bash
# Copy the release binary to /usr/local/bin
sudo cp ./target/release/gitmem /usr/local/bin/gitmem

# Verify installation
/usr/local/bin/gitmem --version
```

## 2. Get Your GitHub Token

Create a GitHub Personal Access Token with `repo` scope:
1. Go to: https://github.com/settings/tokens
2. Click "Generate new token (classic)"
3. Give it a name: "GitMem MCP Server"
4. Select scopes: `repo` (Full control of private repositories)
5. Click "Generate token"
6. **Copy the token** (you won't see it again!)

## 3. Update Cursor MCP Configuration

Edit `.cursor/mcp.json` in your home directory:

```json
{
  "mcpServers": {
    "gitmem": {
      "command": "/usr/local/bin/gitmem",
      "args": [
        "serve",
        "--config",
        "/Users/panos.athanasiou/.config/gitmem.yaml"
      ],
      "env": {
        "GITHUB_TOKEN": "YOUR_GITHUB_TOKEN_HERE"
      }
    }
  }
}
```

**Replace `YOUR_GITHUB_TOKEN_HERE` with your actual token!**

## 4. Restart Cursor

After updating the config:
1. Quit Cursor completely (Cmd+Q)
2. Reopen Cursor
3. The GitMem server will now have access to GitHub credentials

## 5. Test Auto-Push

Try saving a memory through Cursor's MCP interface. Check the logs:

```bash
# Watch the server logs (if running standalone)
tail -f ~/.local/share/gitmem/gitmem.log
```

You should see:
```
[info] auto-push succeeded
```

Instead of authentication errors.

## Troubleshooting

### Still seeing authentication errors?

1. **Verify token is set**: Add a debug line in your config to test:
   ```bash
   env | grep GITHUB_TOKEN
   ```

2. **Check token permissions**: Token must have `repo` scope for private repos

3. **Test manually**:
   ```bash
   GITHUB_TOKEN=your_token_here /usr/local/bin/gitmem serve --config ~/.config/gitmem.yaml
   ```

4. **Check git credentials**:
   ```bash
   git config --global credential.helper
   ```

### Permission denied when copying binary?

```bash
# Make sure you have sudo access
sudo -v

# Try again
sudo cp ./target/release/gitmem /usr/local/bin/gitmem
```

### Build without remote-git feature?

Rebuild with:
```bash
cargo build --release --features backend-github,index-tantivy,encryption,mcp-gitmem-storage-github/remote-git
```



