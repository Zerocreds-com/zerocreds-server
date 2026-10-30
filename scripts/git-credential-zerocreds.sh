#!/usr/bin/env bash
# git-credential-zerocreds: Git credential helper that reads ZeroCreds github tokens

set -euo pipefail

# Configuration
CONNECTIONS_FILE="${HOME}/.config/zerocreds/local/connections.json"
KEYCHAIN_HELPER="${HOME}/.config/zerocreds/local/zerocreds-keychain"

# Helper to print error to stderr and exit
die() {
  echo "git-credential-zerocreds: $*" >&2
  exit 1
}

# Check if keychain helper exists
[[ -x "$KEYCHAIN_HELPER" ]] || die "Keychain helper not found at $KEYCHAIN_HELPER"

# Read connections.json and extract github connections
if [[ ! -f "$CONNECTIONS_FILE" ]]; then
  die "connections file not found: $CONNECTIONS_FILE"
fi

# Get active github connections (state=active, provider=github)
github_conns=()
while IFS= read -r line; do
  github_conns+=("$line")
done < <(jq -r '
  .[] |
  select(.provider == "github" and .state == "active") |
  "\(.connection_id) \(.account_alias)"
' "$CONNECTIONS_FILE")

[[ ${#github_conns[@]} -gt 0 ]] || die "No active github connections found in $CONNECTIONS_FILE"

# Determine which connection to use:
# If git provides a username, try to match it to an account_alias (e.g. "kobzevvv" → github-kobzevvv)
# Otherwise pick the first connection (deterministic)
if [[ -n "${1:-}" ]]; then
  # First argument is the command (get|store|erase), ignore for parsing
  shift
  # If username provided in stdin, capture it
  read -r stdin_proto stdin_host stdin_user || true
  username_match="${stdin_user:-}"
  if [[ -n "$username_match" ]]; then
    # Try to find connection with matching account_alias (github-username)
    for conn in "${github_conns[@]}"; do
      conn_id="${conn%% *}"
      conn_alias="${conn##* }"
      if [[ "$conn_alias" == "github-$username_match" ]]; then
        echo "$conn_id"
        exit 0
      fi
    done
  fi
fi

# Default: pick first active github connection
conn="${github_conns[0]}"
conn_id="${conn%% *}"
echo "$conn_id"