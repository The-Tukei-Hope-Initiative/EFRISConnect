#!/usr/bin/env sh
# Reset a lost EFRIS Connect owner password (password and recovery code both lost).
# Equivalent of windows/EFRISConnect.bat option 7. Writes a one-time reset code,
# valid 24 hours, to "EFRIS Connect setup code.txt" in the relay's data folder.
# Then, on the relay's own computer, open EFRIS Connect -> "Forgot password" and
# enter the owner name, the code and a new password.
#
# Usage: unix/reset-owner.sh [owner-name]
# Run it as the user the relay runs as (or with sudo), so it can write the data folder.
# If the relay uses DATA_DIR_OVERRIDE, set the same value here.
set -e
DIR="$(cd "$(dirname "$0")/.." && pwd)"
NODE="$(command -v node || true)"
if [ -z "$NODE" ]; then echo "Node.js not found on PATH. Install Node 20+ first."; exit 1; fi
"$NODE" "$DIR/backend/reset-owner.js" "$@"
