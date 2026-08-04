#!/bin/sh
set -eu

roots="${*:-Sources Tests}"
if rg -n -U 'deinit[^{]*\{[^}]{0,2000}(shutdown|syncShutdownGracefully)\(' $roots; then
  echo "ERROR: synchronous shutdown from deinit detected" >&2
  exit 1
fi
echo "OK: no synchronous shutdown from deinit"
