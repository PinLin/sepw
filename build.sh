#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

# On Apple Silicon the linker ad-hoc signs automatically, so the Secure Enclave
# key works without a separate codesign step.
swiftc -O sepw.swift -o sepw \
  -framework Security -framework LocalAuthentication

echo "Built: $(pwd)/sepw"
echo "Optional — install to PATH:  sudo cp sepw /usr/local/bin/"
