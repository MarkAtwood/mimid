#!/usr/bin/env bash
# Acceptance test of jmap-chat-js, unmodified, against mimid-agent (bead
# mimid-1wgh.13.11). Copies the committed tree of jmap-chat-js (git
# archive, so local edits never leak in) to a scratch directory, installs
# its locked dependencies there, starts one in-process mimid server with
# alice's and bob's daemons (mimid-agent's acceptance_fixture example),
# and runs:
#   1. agent.test.ts under the app's own Vitest, in Node: session.ts,
#      client.ts and push/eventsource.ts against the daemons;
#   2. browser.spec.ts under the app's own Playwright, in Chromium, the
#      same code served by the app's Vite dev server, cross-origin; only
#      when a Chromium for that Playwright is installed (see below).
# Nothing in the jmap-chat-js checkout changes.
#
# Usage: tools/acceptance/jmap-chat-js/run.sh
# Environment:
#   JMAP_CHAT_JS  the jmap-chat-js checkout   (/data/PROJECT/jmap-chat-js)
#   REV           its revision to test        (7789c2b)
#   WORK          scratch directory           (a new mktemp -d, removed)
#   APP_PORT      the Vite dev server's port  (5173)
#   PLAYWRIGHT_BROWSERS_PATH  where Playwright's Chromium is; to install
#       one there: (cd $WORK/app && npx playwright install chromium)
#   SKIP_BROWSER=1  run only the Node half
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
JMAP_CHAT_JS=${JMAP_CHAT_JS:-/data/PROJECT/jmap-chat-js}
REV=${REV:-7789c2b}
APP_PORT=${APP_PORT:-5173}
export APP_PORT
if [ -z "${WORK:-}" ]; then
  WORK=$(mktemp -d)
  trap 'rm -rf "$WORK"' EXIT
fi
APP=$WORK/app

echo "== jmap-chat-js $(git -C "$JMAP_CHAT_JS" rev-parse "$REV") into $APP"
rm -rf "$APP"
mkdir -p "$APP"
git -C "$JMAP_CHAT_JS" archive "$REV" | tar -x -C "$APP"
(cd "$APP" && npm ci --no-audit --no-fund --loglevel=error)
mkdir "$APP/acceptance"
cp "$HERE"/*.ts "$APP/acceptance/"

echo "== the fixture: a mimid server and two daemons"
(cd "$ROOT" && cargo build -q -p mimid-agent --example acceptance_fixture)
FIXTURE_BIN=${CARGO_TARGET_DIR:-$ROOT/target}/debug/examples/acceptance_fixture
# stdin stays open on a FIFO until we are done; closing it stops the fixture.
rm -f "$WORK/stdin" "$WORK/fixture.json"
mkfifo "$WORK/stdin"
"$FIXTURE_BIN" "http://localhost:$APP_PORT" <"$WORK/stdin" >"$WORK/fixture.json" &
FIXTURE_PID=$!
exec 3>"$WORK/stdin"
stop_fixture() { exec 3>&-; wait "$FIXTURE_PID" || true; }
trap 'stop_fixture; [ -n "${KEEP:-}" ] || rm -rf "$WORK"' EXIT
for _ in $(seq 300); do
  [ -s "$WORK/fixture.json" ] && break
  kill -0 "$FIXTURE_PID" 2>/dev/null || { echo "fixture died" >&2; exit 1; }
  sleep 0.1
done
AGENT_FIXTURE=$(head -n1 "$WORK/fixture.json")
export AGENT_FIXTURE

rc=0
echo "== Node: Vitest"
(cd "$APP" && npx vitest run --config acceptance/vitest.config.ts) || rc=1

if [ -n "${SKIP_BROWSER:-}" ]; then
  echo "== Chromium: skipped (SKIP_BROWSER)"
elif ! (cd "$APP" && node -e '
    const { chromium } = require("@playwright/test");
    process.exit(require("fs").existsSync(chromium.executablePath()) ? 0 : 1)'); then
  echo "== Chromium: skipped, no Playwright Chromium (set PLAYWRIGHT_BROWSERS_PATH)"
else
  echo "== Chromium: Playwright"
  (cd "$APP/acceptance" && npx playwright test --config playwright.config.ts) || rc=1
fi
exit $rc
