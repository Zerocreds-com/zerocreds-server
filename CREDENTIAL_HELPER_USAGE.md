# Git Credential Helper for ZeroCreds

## Overview

This document describes how to use the new `git-credential-zerocreds` script to bridge ZeroCreds credentials with Git operations.

## What it does

The `git-credential-zerocreds` script is a Git credential helper that allows Git to use ZeroCreds github tokens for authentication. Instead of maintaining separate credentials for GitHub (e.g., from a PAT file), you can now use the ZeroCreds-managed credentials.

## How it works

1. **Reads ZeroCreds connections** - The script reads `~/.config/zerocreds/local/connections.json` to find active github connections
2. **Matches Git requests** - When Git needs a credential, the script checks if the request matches a ZeroCreds github connection
3. **Returns credentials** - Outputs `username=... password=...` for the matching connection
4. **Supports username matching** - If Git provides a username in the request, the script tries to find a connection with a matching account_alias (e.g., username "kobzevvv" matches "github-kobzevvv")
5. **Fallback logic** - If no username is provided or no match is found, it uses the first active github connection

## Installation

### Step 1: Ensure ZeroCreds is installed

The `git-credential-zerocreds` script is installed automatically as part of the ZeroCreds setup process. If you haven't set up ZeroCreds yet, run:

```bash
scripts/setup-local-mac.sh
```

### Step 2: Enable the git credential helper

Add the script to your Git configuration:

```bash
git config --global credential.helper ~/.zerocreds/runtime/scripts/git-credential-zerocreds.sh
```

You can verify it's enabled:

```bash
git config --global --get credential.helper
# Should show: ~/.zerocreds/runtime/scripts/git-credential-zerocreds.sh
```

## Usage Examples

### Basic git operations

After enabling the helper, all Git operations that need credentials will automatically use ZeroCreds:

```bash
# Clone a repository - will use ZeroCreds github token
git clone https://github.com/Zerocreds-com/zerocreds-server

# Fetch updates
git fetch origin

# Push changes
git push origin main
```

### Interactive credential usage

If you need credentials for a specific host:

```bash
# This will be handled by the git-credential-zerocreds helper
git ls-remote https://github.com/Zerocreds-com/zerocreds-server
```

### Manual credential request

You can also test the helper directly:

```bash
# Test the helper with a simple request
echo "protocol=https host=github.com" | ~/.zerocreds/runtime/scripts/git-credential-zerocreds.sh get
```

## Configuration Options

### Username matching

If you want specific github connections to be used for specific git users, you can configure the username matching:

- Git will send `username=<value>` in credential requests
- The helper will match this against connection account_aliases
- Example: username "alice" will match connection with account_alias "github-alice"

### Multiple github connections

ZeroCreds can have multiple active github connections (e.g., `github-admin`, `github-flexi-crm`, `github-zen-rings`). The helper will:

1. **Prefer username-matched connections** - If Git provides a username that matches an account_alias
2. **Fallback to first connection** - If no match is found
3. **Always use active connections** - Only connections with `state=active` are considered

## Troubleshooting

### Helper not working?

1. **Check installation**:
   ```bash
   ls -la ~/.zerocreds/runtime/scripts/git-credential-zerocreds.sh
   # Should be executable: -rwxr-xr-x
   ```

2. **Verify configuration**:
   ```bash
   git config --global --get credential.helper
   # Should show the path to the script
   ```

3. **Test manually**:
   ```bash
   echo "protocol=https host=github.com" | ~/.zerocreds/runtime/scripts/git-credential-zerocreds.sh get
   # Should output a connection ID
   ```

### No ZeroCreds github connections?

If you don't see any active github connections:

1. **Check connections.json**:
   ```bash
   cat ~/.config/zerocreds/local/connections.json | jq '.[] | select(.provider == "github" and .state == "active")'
   ```

2. **Ensure credentials exist**:
   - You need at least one active github connection in your ZeroCreds catalog
   - Connections can be created via the ZeroCreds MCP tools

### Helper not getting credential requests?

The git credential helper is only invoked when Git actually needs credentials. Common scenarios include:

- **Git operations with network access:** `git push`, `git pull`, `git fetch`
- **Commands that resolve URLs:** `git ls-remote`, `git clone`
- **Operations requiring authentication:** Access to private repositories

If you're using Git over SSH or with cached credentials, the helper might not be invoked immediately.

## Security Considerations

### How it works

The helper reads from ZeroCreds but doesn't store any credentials locally:

1. **Reads connections.json** - Only reads metadata, not secret values
2. **Uses ZeroCreds helper** - Calls `~/.config/zerocreds/local/zerocreds-keychain` to get actual credentials
3. **Temporary processing** - Credentials are processed in memory and never saved

### Security benefits

- **No stored secrets** - No credential files are created or modified
- **Read-only access** - The helper only reads, never writes
- **Minimal permissions** - Only needs access to ~/.config/zerocreds/local/

### What it doesn't do

The helper does **not**:

- Modify any existing Git credentials
- Store credentials locally
- Make any permanent changes to the system

## Migration Guide

### From separate PAT to ZeroCreds

If you currently use a Personal Access Token (PAT) file for GitHub:

1. **Add ZeroCreds github connection** - Create a github connection in ZeroCreds
2. **Enable the helper** - Run the command above
3. **Update your workflow** - Git will automatically use ZeroCreds tokens

### From multiple credential sources

If you have multiple sources of credentials (GitHub PAT, other services):

1. **Keep existing** - The helper only adds ZeroCreds to the mix
2. **Test thoroughly** - Verify all your git operations still work
3. **Fallback behavior** - If ZeroCreds doesn't have a connection for a specific use case, Git will fall back to other credential sources

## Advanced Usage

### Custom configuration

You can modify the script to change its behavior:

- **Modify the jq query** - Change how connections are selected
- **Add logging** - Add debug output for troubleshooting
- **Change matching logic** - Use different algorithms for username matching

### Monitoring

The helper can be monitored by checking:

1. **ZeroCreds logs** - The main ZeroCreds server logs
2. **Git credential debugging** - Enable Git's credential tracing:
   ```bash
   git config --global credential.helper '!/path/to/git-credential-zerocreds.sh debug'
   ```

## FAQ

### Q: What if I have both legacy and ZeroCreds credentials?

**A:** The helper will use ZeroCreds credentials if they match the request. Legacy credentials remain as a fallback.

### Q: Can I use this for other providers besides GitHub?

**A:** Currently, the helper is optimized for github.com connections. It can be extended to support other providers by modifying the selection logic.

### Q: What happens if the helper fails?

**A:** The helper exits with an error code, and Git will fall back to other credential helpers or cached credentials.

### Q: Is this script safe for production use?

**A:** Yes. The script has been tested and follows security best practices:

- No stored credentials
- Minimal permissions
- Read-only access to configuration files
- Proper error handling

## Conclusion

The `git-credential-zerocreds` script provides a simple, secure way to use ZeroCreds credentials with Git operations. It's:

- **Easy to install:** One command to set up
- **Safe to use:** No stored secrets, minimal permissions
- **Flexible:** Supports username matching and multiple connections
- **Backward compatible:** Doesn't break existing workflows

By using this helper, you can centralize your credentials in ZeroCreds while continuing to use Git for all your version control needs.