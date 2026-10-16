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
# UNSAFE outside this run: the example clicks "Allow" on every consent page. The runner's client is a
# public loopback client, which is asked every time (RFC 8252 section 8.6), and nobody is there to click.
export OAUTH_EXAMPLE_AUTO_APPROVE=1

SERVER=""
RUNNER=""

# Stops a process and all its descendants (npx starts node as a child).
kill_tree() {
  local child
  for child in $(pgrep -P "$1" 2>/dev/null || true); do
    kill_tree "$child"
  done
  kill "$1" 2>/dev/null || true
}
trap '[ -n "$RUNNER" ] && kill_tree "$RUNNER"; [ -n "$SERVER" ] && kill_tree "$SERVER"; true' EXIT

CLIENT_ID="$(php examples/standalone/setup.php 'Conformance runner')"
php -S "127.0.0.1:$PORT" examples/standalone/server.php > "$WORK/server.log" 2>&1 &
SERVER=$!

READY=""
for _ in $(seq 1 50); do
  if curl -fsS "http://127.0.0.1:$PORT/.well-known/oauth-authorization-server" > /dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 0.2
done
if [ -z "$READY" ]; then
  echo "The example server never answered on port $PORT." >&2
  cat "$WORK/server.log" >&2
  exit 1
fi

npx --yes "$SUITE" authorization --url "http://127.0.0.1:$PORT" --client-id "$CLIENT_ID" \
  --port "$CALLBACK_PORT" -o "$RESULTS" > "$WORK/conformance.log" 2>&1 &
RUNNER=$!

# The authorization-code scenario prints the URL a person would open; follow it with curl.
# The example signs alice in and answers the consent page with "Allow", so the server redirects to the
# runner's callback.
URL=""
for _ in $(seq 1 150); do
  URL="$(grep -oE "http://127\.0\.0\.1:$PORT/oauth/authorize\?[^[:space:]]+" "$WORK/conformance.log" | head -1 || true)"
  [ -n "$URL" ] && break
  if ! kill -0 "$RUNNER" 2>/dev/null; then
    echo "The conformance runner exited before printing an authorization URL." >&2
    cat "$WORK/conformance.log" >&2
    exit 1
  fi
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
if [ "$STATUS" -ne 0 ]; then
  echo "Conformance failed: the runner exited with status $STATUS." >&2
  exit 1
fi

# Prove success positively: both scenarios wrote a checks.json with at least one check, and every
# check is SUCCESS. An empty or missing results directory must not pass.
php -r '
$dir = $argv[1];
$failed = false;
foreach (["authorization-server-metadata-endpoint", "authorization-code-grant"] as $scenario) {
    $files = glob($dir . "/authorization-server-" . $scenario . "-*/checks.json") ?: [];
    if ($files === []) {
        fwrite(STDERR, "No results for scenario $scenario in $dir.\n");
        $failed = true;
        continue;
    }
    $checks = json_decode((string)file_get_contents($files[0]), true);
    if (!is_array($checks) || $checks === []) {
        fwrite(STDERR, "Scenario $scenario reported no checks.\n");
        $failed = true;
        continue;
    }
    foreach ($checks as $check) {
        $status = is_array($check) ? ($check["status"] ?? "missing") : "invalid";
        if ($status !== "SUCCESS") {
            fwrite(STDERR, "Scenario $scenario: check " . ($check["id"] ?? "?") . " is $status.\n");
            $failed = true;
        }
    }
}
exit($failed ? 1 : 0);
' "$RESULTS" || { echo "Conformance failed." >&2; exit 1; }
echo "Conformance passed."
