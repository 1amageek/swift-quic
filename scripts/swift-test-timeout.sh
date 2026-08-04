#!/bin/sh
set -eu

limit="$1"
shift
if [ "$limit" -le 0 ] || [ "$limit" -gt 120 ]; then
  echo "timeout must be between 1 and 120 seconds" >&2
  exit 2
fi

"$@" &
child="$!"
cleanup() {
  kill "$child" 2>/dev/null || true
}
trap cleanup INT TERM

start=$(date +%s)
while kill -0 "$child" 2>/dev/null; do
  now=$(date +%s)
  if [ $((now - start)) -ge "$limit" ]; then
    kill "$child" 2>/dev/null || true
    wait "$child" 2>/dev/null || true
    echo "ERROR: test command exceeded ${limit}s" >&2
    exit 124
  fi
  sleep 1
done
wait "$child"
