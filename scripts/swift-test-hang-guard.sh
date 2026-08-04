#!/bin/sh
set -eu

repeats=3
timeout=30
build_timeout=120
while [ "$#" -gt 0 ]; do
  case "$1" in
  --repeats) repeats="$2"; shift 2 ;;
  --timeout) timeout="$2"; shift 2 ;;
    --build-timeout) build_timeout="$2"; shift 2 ;;
    --) shift; break ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
"$root/scripts/check-sync-shutdown-in-deinit.sh" "$root/Sources" "$root/Tests"

# Build all test products once under a separate, longer budget. The execution
# budget below must measure the test process, not SwiftPM compilation time.
"$root/scripts/swift-test-timeout.sh" "$build_timeout" \
  swift build --package-path "$root" --build-tests

i=1
while [ "$i" -le "$repeats" ]; do
  "$root/scripts/swift-test-timeout.sh" "$timeout" \
    swift test --package-path "$root" --skip-build "$@"
  # Match the helper's test-bundle invocation rather than the guard's own
  # diagnostic command (which would otherwise contain the search string).
  if pgrep -f 'swiftpm-testing-helper --test-bundle-path' >/dev/null 2>&1; then
    echo "ERROR: stale swiftpm-testing-helper remains after run $i" >&2
    exit 1
  fi
  i=$((i + 1))
done
echo "OK: $repeats test runs completed without timeout or stale helper"
