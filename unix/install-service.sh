#!/usr/bin/env sh
# Install EFRISConnect as a background service (equivalent of windows/install-service.js).
# Linux  -> systemd unit (system service).   macOS -> launchd LaunchAgent (per user).
# Run from anywhere; it resolves the repo root from this script's location.
set -e
DIR="$(cd "$(dirname "$0")/.." && pwd)"
BACKEND="$DIR/backend"
NODE="$(command -v node || true)"
if [ -z "$NODE" ]; then echo "Node.js not found on PATH. Install Node 18+ first."; exit 1; fi

OS="$(uname -s)"
if [ "$OS" = "Linux" ]; then
  UNIT=/etc/systemd/system/efrisconnect.service
  echo "Installing systemd service at $UNIT (needs sudo)..."
  sudo sh -c "cat > $UNIT" <<UNIT
[Unit]
Description=EFRISConnect relay
After=network.target

[Service]
Type=simple
WorkingDirectory=$BACKEND
ExecStart=$NODE $BACKEND/server.js
Restart=on-failure
User=$(id -un)

[Install]
WantedBy=multi-user.target
UNIT
  sudo systemctl daemon-reload
  sudo systemctl enable --now efrisconnect
  echo "Done. Manage with: sudo systemctl {status|restart|stop} efrisconnect"
elif [ "$OS" = "Darwin" ]; then
  PLIST="$HOME/Library/LaunchAgents/org.tukeihope.efrisconnect.plist"
  mkdir -p "$HOME/Library/LaunchAgents"
  echo "Installing launchd agent at $PLIST ..."
  cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>org.tukeihope.efrisconnect</string>
  <key>ProgramArguments</key><array><string>$NODE</string><string>$BACKEND/server.js</string></array>
  <key>WorkingDirectory</key><string>$BACKEND</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict></plist>
PLIST
  launchctl unload "$PLIST" 2>/dev/null || true
  launchctl load "$PLIST"
  echo "Done. Manage with: launchctl {load|unload} $PLIST"
else
  echo "Unsupported OS: $OS. Run the relay with ./start.sh instead."
  exit 1
fi
