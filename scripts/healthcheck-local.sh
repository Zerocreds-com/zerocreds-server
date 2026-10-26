#!/bin/bash
# ZeroCreds local end-to-end health check.
#
# Exercises the full credential lifecycle against the running local server:
#   1. take a test token (GITHUB_TEST_TOKEN, a read-only fine-grained PAT)
#   2. store it via form creation + submission (single step: form + submit)
#   3. use it directly (curl to api.github.com) and through ZeroCreds (verify)
#   4. overwrite the credential with an invalid value ("1234")
#   5. validate the credential (format + provider check) -> expect "invalid"
#   6. delete the test credential (catalog entry + Keychain entry)
#
# Every step is cleaned up in a trap so a failed run does not leave artifacts.
#
# Usage:
#   GITHUB_TEST_TOKEN=github_pat_... ./scripts/healthcheck-local.sh
#
# The token should be a fine-grained PAT with read-only access to a public
# repository; it is never printed and never leaves this machine.

set -euo pipefail

BASE_URL="${ZEROCREDS_BASE_URL:-http://localhost:8080/zerocreds}"
ADMIN_TOKEN_FILE="${ZEROCREDS_ADMIN_TOKEN_FILE:-$HOME/.config/zerocreds/local/admin-token}"
KEYCHAIN_HELPER="${ZEROCREDS_KEYCHAIN_HELPER:-$HOME/.config/zerocreds/local/zerocreds-keychain}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
PASS=0; FAIL=0

ok()   { echo -e "${GREEN}✓${NC} $1"; PASS=$((PASS+1)); }
bad()  { echo -e "${RED}✗${NC} $1"; FAIL=$((FAIL+1)); }
warn() { echo -e "${YELLOW}⚠${NC} $1"; }

ADMIN_TOKEN="$(cat "$ADMIN_TOKEN_FILE" 2>/dev/null || true)"
TEST_TOKEN="${GITHUB_TEST_TOKEN:-}"

if [ -z "$ADMIN_TOKEN" ]; then echo "missing admin token at $ADMIN_TOKEN_FILE"; exit 2; fi
if [ -z "$TEST_TOKEN" ]; then
  echo "GITHUB_TEST_TOKEN is not set."
  echo "Create a fine-grained PAT with read-only access to a public repo and run:"
  echo "  GITHUB_TEST_TOKEN=github_pat_... ./scripts/healthcheck-local.sh"
  exit 2
fi

UID_SUFFIX="hc-$(date +%s)-$$"
SERVICE_SLUG="github"
STORAGE_ACCOUNT="${SERVICE_SLUG}-${UID_SUFFIX}"
CONNECTION_ID=""

cleanup() {
  if [ -n "$CONNECTION_ID" ]; then
    curl -s -X DELETE -H "Authorization: Bearer $ADMIN_TOKEN" \
      "$BASE_URL/api/local/connections/$CONNECTION_ID" >/dev/null 2>&1 || true
  fi
  "$KEYCHAIN_HELPER" delete zerocreds "$STORAGE_ACCOUNT" >/dev/null 2>&1 || true
}
trap cleanup EXIT

api() { # method path [json_body]
  local method="$1" path="$2" body="${3:-}"
  if [ -n "$body" ]; then
    curl -s --max-time 20 -X "$method" -H "Authorization: Bearer $ADMIN_TOKEN" \
      -H "Content-Type: application/json" "$BASE_URL$path" -d "$body"
  else
    curl -s --max-time 20 -X "$method" -H "Authorization: Bearer $ADMIN_TOKEN" "$BASE_URL$path"
  fi
}

echo "=== ZeroCreds local health check ==="
echo "server: $BASE_URL   token: ${TEST_TOKEN:0:14}… (read-only)"

# ── 1. store the test token (form create + submit) ────────────────────────────
echo
echo "[1/6] Store test token via form"
FORM="$(api POST /api/forms "{\"name\":\"hc-${UID_SUFFIX}\",\"kind\":\"token\",\"title\":\"healthcheck\",\"destination\":\"mac-keychain\",\"ttl_minutes\":10,\"uid\":\"${UID_SUFFIX}\",\"service_slug\":\"${SERVICE_SLUG}\"}")"
FORM_ID="$(echo "$FORM" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("form_id",""))' 2>/dev/null || true)"
MANIFEST_ID="$(echo "$FORM" | python3 -c 'import sys,json; print(json.load(sys.stdin)["manifest"]["manifest_id"])' 2>/dev/null || true)"
if [ -z "$FORM_ID" ] || [ -z "$MANIFEST_ID" ]; then bad "form creation: $FORM"; else
  SUBMIT="$(api POST "/api/forms/$FORM_ID/submit" "{\"manifest_id\":\"$MANIFEST_ID\",\"fields\":{\"token\":\"$TEST_TOKEN\"}}")"
  if echo "$SUBMIT" | python3 -c 'import sys,json; d=json.load(sys.stdin); exit(0 if d.get("ok") else 1)' 2>/dev/null; then
    ok "token stored (form create + submit)"
  else
    bad "submit: $SUBMIT"
  fi
fi

# ── 2. resolve the new connection id from the catalog ─────────────────────────
echo
echo "[2/6] Locate connection in catalog"
CONNECTION_ID="$(api GET /api/local/connections | python3 -c "
import sys, json
d = json.load(sys.stdin)
for c in d.get('connections', []):
    if c.get('account_alias') == '$UID_SUFFIX':
        print(c.get('connection_id', ''))
        break
" 2>/dev/null || true)"
if [ -n "$CONNECTION_ID" ]; then ok "connection found: $CONNECTION_ID"; else bad "connection not catalogued"; fi

# ── 3. use directly AND through ZeroCreds ─────────────────────────────────────
echo
echo "[3/6] Use token"
if curl -s --max-time 15 -H "Authorization: Bearer $TEST_TOKEN" https://api.github.com/user \
   | python3 -c 'import sys,json; d=json.load(sys.stdin); exit(0 if d.get("login") else 1)' 2>/dev/null; then
  ok "direct GitHub API call (curl)"
else
  bad "direct GitHub API call failed"
fi

VERIFY="$(api POST /api/local/connections/verify "{\"provider\":\"$SERVICE_SLUG\",\"account_alias\":\"$UID_SUFFIX\"}")"
if echo "$VERIFY" | python3 -c 'import sys,json; d=json.load(sys.stdin); exit(0 if d.get("verification")=="valid" else 1)' 2>/dev/null; then
  ok "verify through ZeroCreds -> valid"
else
  bad "verify through ZeroCreds: $VERIFY"
fi

# ── 4. overwrite with an invalid value ────────────────────────────────────────
echo
echo "[4/6] Overwrite credential with invalid value \"1234\""
FORM2="$(api POST /api/forms "{\"name\":\"hc2-${UID_SUFFIX}\",\"kind\":\"token\",\"title\":\"healthcheck\",\"destination\":\"mac-keychain\",\"ttl_minutes\":10,\"uid\":\"${UID_SUFFIX}\",\"service_slug\":\"${SERVICE_SLUG}\"}")"
FORM2_ID="$(echo "$FORM2" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("form_id",""))' 2>/dev/null || true)"
MANIFEST2_ID="$(echo "$FORM2" | python3 -c 'import sys,json; print(json.load(sys.stdin)["manifest"]["manifest_id"])' 2>/dev/null || true)"
if [ -n "$FORM2_ID" ] && [ -n "$MANIFEST2_ID" ]; then
  SUBMIT2="$(api POST "/api/forms/$FORM2_ID/submit" "{\"manifest_id\":\"$MANIFEST2_ID\",\"fields\":{\"token\":\"1234\"}}")"
  if echo "$SUBMIT2" | python3 -c 'import sys,json; d=json.load(sys.stdin); exit(0 if d.get("ok") else 1)' 2>/dev/null; then
    ok "overwrite submitted (same uid -> Keychain overwritten)"
  else
    bad "overwrite submit: $SUBMIT2"
  fi
else
  bad "overwrite form creation: $FORM2"
fi

# ── 5. validate the credential (format + provider) ────────────────────────────
echo
echo "[5/6] Validate credential"
VERIFY2="$(api POST /api/local/connections/verify "{\"provider\":\"$SERVICE_SLUG\",\"account_alias\":\"$UID_SUFFIX\"}")"
if echo "$VERIFY2" | python3 -c 'import sys,json; d=json.load(sys.stdin); exit(0 if d.get("verification")=="invalid" else 1)' 2>/dev/null; then
  CODE="$(echo "$VERIFY2" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("diagnostic",{}).get("upstream_code",""))' 2>/dev/null || true)"
  ok "credential rejected as invalid (code=$CODE)"
else
  bad "expected invalid, got: $VERIFY2"
fi

# ── 6. delete the test credential ─────────────────────────────────────────────
echo
echo "[6/6] Delete test credential"
DEL="$(api DELETE "/api/local/connections/$CONNECTION_ID")"
if echo "$DEL" | python3 -c 'import sys,json; d=json.load(sys.stdin); exit(0 if d.get("deleted") else 1)' 2>/dev/null; then
  ok "connection deleted (catalog entry removed)"
  CONNECTION_ID=""
else
  bad "delete: $DEL"
fi

if "$KEYCHAIN_HELPER" exists zerocreds "$STORAGE_ACCOUNT" >/dev/null 2>&1; then
  bad "Keychain entry still present after delete"
else
  ok "Keychain entry erased"
fi

echo
echo "=== Result: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -eq 0 ]; then
  echo -e "${GREEN}ZeroCreds local health: OK${NC}"
else
  echo -e "${RED}ZeroCreds local health: FAIL${NC}"
  exit 1
fi
