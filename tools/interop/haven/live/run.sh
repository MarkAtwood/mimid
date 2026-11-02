#!/usr/bin/env bash
# Live interop harness (mimid bead mimid-1wgh.46.1.5): runs Haven's mimi-hubd
# behind a socat TLS proxy that supplies the mTLS client certificate, inside a
# private user+network namespace so the proxy can own haven.localhost:443
# without root. Usage: ./run.sh <command> [args...]   (the command runs inside)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
HAVEN=${HAVEN:?set HAVEN to a checkout of github.com/havenmessenger/interop}
CACHE=${XDG_CACHE_HOME:-$HOME/.cache}
export CARGO_TARGET_DIR=${HAVEN_TARGET:-$CACHE/mimid-haven-target}
cargo build --quiet --manifest-path "$HAVEN/Cargo.toml" -p mimi-hubd
export HUBD="$CARGO_TARGET_DIR/debug/mimi-hubd"
export WORK
mkdir -p "$CACHE"
WORK=$(mktemp -d "$CACHE/mimid-haven-live.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
"$HERE/certs.sh" "$WORK/certs"
unshare --user --map-root-user --net "$HERE/up.sh" "$@"
