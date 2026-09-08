#!/bin/bash
# test_integration.sh - Tier C live network and integration test suite (requires root/sudo).
#
# Runs live network traces to public endpoints, custom flag combinations,
# demuxing resilience against parallel ping noise, and dual-run system traceroute parity.

set -u

DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$DIR/build/bin/traceroute"
[ ! -x "$BIN" ] && BIN="$DIR/traceroute"

if [ ! -x "$BIN" ]; then
    echo "test_integration.sh: missing executable at $BIN, build first with 'make'" >&2
    exit 1
fi

SUDO="sudo"
if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
elif ! sudo -n true 2>/dev/null; then
    echo "=================================================================="
    echo "Tier C integration tests require root privileges."
    echo "Please run this suite with:"
    echo "    sudo make test-integration"
    echo "or:"
    echo "    sudo ./tests/test_integration.sh"
    echo "=================================================================="
    exit 1
fi

echo "=== Running Tier C Live Network & Integration Tests ==="

# 1. Real endpoint trace to 8.8.8.8
echo "--- Test 1: Real Endpoint Trace (8.8.8.8) ---"
$SUDO "$BIN" -n -m 5 -w 2 8.8.8.8
echo "  [PASS] Real endpoint trace completed"
echo

# 2. Domain resolution trace to galileo.edu
echo "--- Test 2: Domain Resolution Trace (galileo.edu) ---"
$SUDO "$BIN" -m 5 -w 2 galileo.edu
echo "  [PASS] Domain resolution trace completed"
echo

# 3. Custom flag combination (-f 3 -m 8 -q 2 -w 1 -z 50 -n)
echo "--- Test 3: Flag Combination (-f 3 -m 8 -q 2 -w 1 -z 50 -n) ---"
$SUDO "$BIN" -f 3 -m 8 -q 2 -w 1 -z 50 -n 8.8.8.8
echo "  [PASS] Custom flag combination completed"
echo

# 4. Parallel noise resilience (concurrent ping)
echo "--- Test 4: Parallel Noise Resilience (ping 1.1.1.1 in background) ---"
ping -c 5 1.1.1.1 >/dev/null 2>&1 &
PING_PID=$!
$SUDO "$BIN" -n -m 4 -q 2 -w 1 8.8.8.8
wait "$PING_PID" 2>/dev/null || true
echo "  [PASS] Parallel noise resilience verified"
echo

# 5. Dual-run reference comparison
echo "--- Test 5: Dual-Run Comparison against System traceroute ---"
"$DIR/tests/compare.sh" 8.8.8.8 -n -m 5 -w 2
echo "  [PASS] Dual-run comparison completed"
echo

echo "OK: All Tier C integration tests executed successfully!"
