#!/bin/bash

if ! [ -d "$1" ]; then
	echo "Usage: $0 [log dir]"
	exit 1
fi
LOG_DIR=$(realpath "$1")

ROOT=$(realpath "$(dirname "$0")")
if echo "$ROOT" | grep ' '; then
	echo "Sorry babe, no spaces in filenames"
	exit 1
fi

if [ -z "$VIRTUAL_ENV" ]; then
	echo "Must be in a virtualenv"
	exit 1
fi

CMD=$(head -n1 "$ROOT/list")
PACKAGE=$(echo "$CMD" | cut -d'#' -f2)
tail -n+2 "$ROOT/list" > "$ROOT/list2"
mv "$ROOT/list2" "$ROOT/list"

TEMP=$(mktemp -d)
cd "$TEMP"
$ROOT/$CMD > "$LOG_DIR/$PACKAGE.log" 2>&1
cd -
rm -rf "$TEMP"
