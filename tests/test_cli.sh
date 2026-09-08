#!/bin/bash
# test_cli.sh - Tier B automated tests for CLI parameter bounds and permissions (no root required).
#
# Validates flag boundary enforcement (-f, -m, -q, -w, -z), non-numeric input rejection,
# relational checks (-f > -m), missing/excess argument usage, and non-root execution check.

set -u

DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$DIR/build/bin/traceroute"
[ ! -x "$BIN" ] && BIN="$DIR/traceroute"

if [ ! -x "$BIN" ]; then
    echo "test_cli.sh: missing executable at $BIN, build first with 'make'" >&2
    exit 1
fi

TOTAL=0
PASSED=0

run_test() {
    local desc="$1"
    local expected_code="$2"
    local expected_pattern="$3"
    shift 3
    local cmd=("$@")

    TOTAL=$((TOTAL + 1))
    local output
    output=$("$BIN" "${cmd[@]}" 2>&1)
    local code=$?

    if [ "$code" -ne "$expected_code" ]; then
        echo "  [FAIL] $desc (got exit code $code, expected $expected_code)"
        echo "         Output: $output"
        return 1
    fi

    if [ -n "$expected_pattern" ] && ! echo "$output" | grep -qE "$expected_pattern"; then
        echo "  [FAIL] $desc (output did not match: '$expected_pattern')"
        echo "         Output: $output"
        return 1
    fi

    echo "  [PASS] $desc"
    PASSED=$((PASSED + 1))
    return 0
}

echo "=== Running Tier B CLI & Validation Tests ==="

# 1. Root privilege check on normal execution
run_test "Root privilege requirement check" 1 "raw sockets require root privileges; run it with sudo" 8.8.8.8

# 2. Missing host argument
run_test "Missing host argument" 1 "usage: traceroute"

# 3. Extra positional arguments
run_test "Multiple hosts / positional arguments" 1 "usage: traceroute" 8.8.8.8 1.1.1.1

# 4. Unknown option flag
run_test "Unrecognized flag -x" 1 "usage: traceroute" -x 8.8.8.8

# 5. Relational validation: first_ttl > max_ttl
run_test "Relational: first_ttl (10) > max_ttl (5)" 1 "first ttl \(10\) may not be greater than max ttl \(5\)" -f 10 -m 5 8.8.8.8

# 6. Flag boundary tests: -f (valid 1..255)
run_test "Flag -f lower bound violation (-f 0)" 1 "invalid value for -f: \"0\"" -f 0 8.8.8.8
run_test "Flag -f upper bound violation (-f 256)" 1 "invalid value for -f: \"256\"" -f 256 8.8.8.8
run_test "Flag -f non-numeric argument (-f abc)" 1 "invalid value for -f: \"abc\"" -f abc 8.8.8.8

# 7. Flag boundary tests: -m (valid 1..255)
run_test "Flag -m lower bound violation (-m 0)" 1 "invalid value for -m: \"0\"" -m 0 8.8.8.8
run_test "Flag -m upper bound violation (-m 256)" 1 "invalid value for -m: \"256\"" -m 256 8.8.8.8
run_test "Flag -m non-numeric argument (-m abc)" 1 "invalid value for -m: \"abc\"" -m abc 8.8.8.8

# 8. Flag boundary tests: -q (valid 1..10)
run_test "Flag -q lower bound violation (-q 0)" 1 "invalid value for -q: \"0\"" -q 0 8.8.8.8
run_test "Flag -q upper bound violation (-q 11)" 1 "invalid value for -q: \"11\"" -q 11 8.8.8.8
run_test "Flag -q non-numeric argument (-q abc)" 1 "invalid value for -q: \"abc\"" -q abc 8.8.8.8

# 9. Flag boundary tests: -w (valid 1..60)
run_test "Flag -w lower bound violation (-w 0)" 1 "invalid value for -w: \"0\"" -w 0 8.8.8.8
run_test "Flag -w upper bound violation (-w 61)" 1 "invalid value for -w: \"61\"" -w 61 8.8.8.8
run_test "Flag -w non-numeric argument (-w abc)" 1 "invalid value for -w: \"abc\"" -w abc 8.8.8.8

# 10. Flag boundary tests: -z (valid 0..10000)
run_test "Flag -z negative value violation (-z -1)" 1 "invalid value for -z: \"-1\"" -z -1 8.8.8.8
run_test "Flag -z upper bound violation (-z 10001)" 1 "invalid value for -z: \"10001\"" -z 10001 8.8.8.8
run_test "Flag -z non-numeric argument (-z abc)" 1 "invalid value for -z: \"abc\"" -z abc 8.8.8.8

echo
if [ "$PASSED" -eq "$TOTAL" ]; then
    echo "OK: All $PASSED/$TOTAL Tier B CLI validation tests passed successfully!"
    exit 0
else
    echo "FAILED: Only $PASSED/$TOTAL Tier B CLI validation tests passed."
    exit 1
fi
