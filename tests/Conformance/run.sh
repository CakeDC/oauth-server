#!/usr/bin/env bash
# Runs the official MCP conformance scenarios for authorization servers
# (authorization-server-metadata-endpoint, authorization-code-grant) against examples/standalone.
set -euo pipefail
cd "$(dirname "$0")/../.."

PORT="${OAUTH_CONFORMANCE_PORT:-8090}"
CALLBACK_PORT="${OAUTH_CONFORMANCE_CALLBACK_PORT:-3000}"
SUITE="@modelcontextprotocol/conformance@0.2.0-alpha.11"
WORK="tests/Conformance/tmp"
RESULTS="tests/Conformance/results"

rm -rf "$WORK" "$RESULTS"
mkdir -p "$WORK"
export OAUTH_EXAMPLE_DB="$PWD/$WORK/oauth.sqlite"
export OAUTH_EXAMPLE_ISSUER="http://127.0.0.1:$PORT"
export OAUTH_EXAMPLE_AUTO_LOGIN=1

SERVER=""
RUNNER=""
trap 'kill $SERVER $RUNNER 2>/dev/null || true' EXIT

CLIENT_ID="$(php examples/standalone/setup.php 'Conformance runner')"
php -S "127.0.0.1:$PORT" examples/standalone/server.php > "$WORK/server.log" 2>&1 &
SERVER=$!

for _ in $(seq 1 50); do
  curl -fsS "http://127.0.0.1:$PORT/.well-known/oauth-authorization-server" > /dev/null 2>&1 && break
  sleep 0.2
done

npx --yes "$SUITE" authorization --url "http://127.0.0.1:$PORT" --client-id "$CLIENT_ID" \
  --port "$CALLBACK_PORT" -o "$RESULTS" > "$WORK/conformance.log" 2>&1 &
RUNNER=$!

# The authorization-code scenario prints the URL a person would open; follow it with curl.
# The example signs alice in and she already consented, so the server redirects straight to the
# runner's callback.
URL=""
for _ in $(seq 1 150); do
  URL="$(grep -oE "http://127\.0\.0\.1:$PORT/oauth/authorize\?[^[:space:]]+" "$WORK/conformance.log" | head -1 || true)"
  [ -n "$URL" ] && break
  sleep 0.2
done
if [ -z "$URL" ]; then
  echo "The conformance runner printed no authorization URL." >&2
  cat "$WORK/conformance.log" >&2
  exit 1
fi
curl -fsS -L -o /dev/null "$URL"

set +e
wait "$RUNNER"
STATUS=$?
set -e
cat "$WORK/conformance.log"
if [ "$STATUS" -ne 0 ] || grep -rqs '"FAILURE"' "$RESULTS"; then
  echo "Conformance failed." >&2
  exit 1
fi
echo "Conformance passed."
