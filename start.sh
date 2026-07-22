#!/usr/bin/env sh
# EFRISConnect launcher for macOS and Linux.
# Starts the relay from the backend folder. Requires Node.js 18+.
#   chmod +x start.sh    # first time only
#   ./start.sh
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR/backend"
if ! command -v node >/dev/null 2>&1; then
  echo "Node.js is not installed. Install Node 18+ from https://nodejs.org and try again."
  exit 1
fi
if [ ! -d node_modules ]; then
  echo "Installing dependencies (first run)..."
  npm install
fi
echo "Starting EFRISConnect. Open http://localhost:3000 (or https://localhost:5443/extension)."
exec node server.js
