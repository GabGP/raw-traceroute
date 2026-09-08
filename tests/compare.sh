#!/bin/bash
# compare.sh - Side-by-side comparison against the system traceroute.
#
# Runs both our custom raw traceroute and system traceroute with identical
# parameters, saving logs to tests/logs/ and displaying a side-by-side diff.
#
#   Usage: tests/compare.sh [HOST] [ARGS...]
#   Default: HOST=8.8.8.8  ARGS=-n -m 20 -w 2
#
# Both commands require root privileges because they open RAW sockets.

set -u

DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$DIR/build/bin/traceroute"
[ ! -x "$BIN" ] && BIN="$DIR/traceroute"

HOST="${1:-8.8.8.8}"
[ $# -gt 0 ] && shift
ARGS=("$@")
[ ${#ARGS[@]} -eq 0 ] && ARGS=(-n -m 20 -w 2)

if [ ! -x "$BIN" ]; then
    echo "compare.sh: falta $BIN, compila primero con 'make'" >&2
    exit 1
fi
if ! command -v traceroute >/dev/null 2>&1; then
    echo "compare.sh: el traceroute del sistema no esta instalado" >&2
    echo "            (sudo apt-get install traceroute) - solo se usa para comparar" >&2
    exit 1
fi

SUDO="sudo"
if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
fi

LOGS="$DIR/tests/logs"
mkdir -p "$LOGS"
SAFE="${HOST//[^A-Za-z0-9._-]/_}"
OWN="$LOGS/own_$SAFE.log"
SYS="$LOGS/system_$SAFE.log"

echo "=== propio:  $SUDO ./traceroute ${ARGS[*]} $HOST"
$SUDO "$BIN" "${ARGS[@]}" "$HOST" | tee "$OWN"

echo
echo "=== sistema: $SUDO traceroute ${ARGS[*]} $HOST"
$SUDO traceroute "${ARGS[@]}" "$HOST" | tee "$SYS"

echo
echo "=== diff lado a lado (izquierda = propio, derecha = sistema)"
echo "    logs: $OWN"
echo "          $SYS"
diff -y --width=150 "$OWN" "$SYS"

exit 0
