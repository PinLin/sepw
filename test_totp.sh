#!/bin/bash
# Tests for sepw's TOTP computation, run against RFC 6238 Appendix B vectors.
#
# These exercise the pure base32-decode + TOTP pipeline through the hidden
# `_totp <secret-or-uri> <unixtime> [flags]` test seam, which bypasses the
# Secure Enclave (the real `totp` command requires Touch ID and can't run
# unattended). The RFC seeds are ASCII; we base32-encode them here so the test
# stays self-contained and free of transcription errors.
set -uo pipefail
cd "$(dirname "$0")"

./build.sh >/dev/null || { echo "build failed"; exit 1; }

PASS=0
FAIL=0

b32() { python3 -c "import base64,sys;print(base64.b32encode(sys.argv[1].encode()).decode())" "$1"; }

# RFC 6238 seeds
SEED_SHA1="12345678901234567890"                                             # 20 bytes
SEED_SHA256="12345678901234567890123456789012"                               # 32 bytes
SEED_SHA512="1234567890123456789012345678901234567890123456789012345678901234" # 64 bytes
B32_SHA1=$(b32 "$SEED_SHA1")
B32_SHA256=$(b32 "$SEED_SHA256")
B32_SHA512=$(b32 "$SEED_SHA512")

check() { # description expected actual
  if [[ "$2" == "$3" ]]; then
    PASS=$((PASS+1))
  else
    FAIL=$((FAIL+1))
    echo "FAIL: $1 — expected '$2', got '$3'"
  fi
}

# --- RFC 6238 Appendix B, 8-digit, SHA1 ---
check "SHA1 t=59"          94287082 "$(./sepw _totp "$B32_SHA1" 59          --digits 8 --algorithm SHA1)"
check "SHA1 t=1111111109"  07081804 "$(./sepw _totp "$B32_SHA1" 1111111109  --digits 8 --algorithm SHA1)"
check "SHA1 t=1111111111"  14050471 "$(./sepw _totp "$B32_SHA1" 1111111111  --digits 8 --algorithm SHA1)"
check "SHA1 t=1234567890"  89005924 "$(./sepw _totp "$B32_SHA1" 1234567890  --digits 8 --algorithm SHA1)"
check "SHA1 t=2000000000"  69279037 "$(./sepw _totp "$B32_SHA1" 2000000000  --digits 8 --algorithm SHA1)"
check "SHA1 t=20000000000" 65353130 "$(./sepw _totp "$B32_SHA1" 20000000000 --digits 8 --algorithm SHA1)"

# --- RFC 6238 Appendix B, 8-digit, SHA256 / SHA512 ---
check "SHA256 t=59"         46119246 "$(./sepw _totp "$B32_SHA256" 59 --digits 8 --algorithm SHA256)"
check "SHA512 t=59"         90693936 "$(./sepw _totp "$B32_SHA512" 59 --digits 8 --algorithm SHA512)"

# --- default is 6 digits, 30s, SHA1 ---
check "default 6-digit t=59" 287082 "$(./sepw _totp "$B32_SHA1" 59)"

# --- otpauth:// URI: parameters read from the URI ---
URI8="otpauth://totp/ACME:alice?secret=$B32_SHA1&digits=8&algorithm=SHA1&period=30"
check "otpauth digits=8 from URI" 94287082 "$(./sepw _totp "$URI8" 59)"
URI_NODIGITS="otpauth://totp/ACME:alice?secret=$B32_SHA1"
check "otpauth no digits -> default 6" 287082 "$(./sepw _totp "$URI_NODIGITS" 59)"

# --- precedence: CLI flag overrides the URI value ---
URI6="otpauth://totp/ACME:alice?secret=$B32_SHA1&digits=6"
check "CLI --digits overrides URI" 94287082 "$(./sepw _totp "$URI6" 59 --digits 8)"

# --- base32 tolerance: lowercase, spaces, padding ---
LOWER=$(echo "$B32_SHA1" | tr 'A-Z' 'a-z')
check "lowercase base32" 94287082 "$(./sepw _totp "$LOWER" 59 --digits 8)"
SPACED="${B32_SHA1:0:4} ${B32_SHA1:4}"
check "spaced base32" 94287082 "$(./sepw _totp "$SPACED" 59 --digits 8)"

# --- errors exit non-zero ---
fails() { # description: command should exit non-zero
  if "${@:2}" >/dev/null 2>&1; then
    FAIL=$((FAIL+1)); echo "FAIL: $1 — expected non-zero exit"
  else
    PASS=$((PASS+1))
  fi
}
fails "invalid base32"        ./sepw _totp "0189!!" 59
fails "digits out of range"   ./sepw _totp "$B32_SHA1" 59 --digits 9
fails "otpauth without secret" ./sepw _totp "otpauth://totp/ACME:alice?digits=8" 59
fails "unknown algorithm"     ./sepw _totp "$B32_SHA1" 59 --algorithm SHA3

echo
echo "Passed: $PASS  Failed: $FAIL"
[[ $FAIL -eq 0 ]]
