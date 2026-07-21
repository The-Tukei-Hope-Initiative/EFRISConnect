#!/usr/bin/env sh
# Remove the EFRISConnect background service (equivalent of windows/uninstall-service.js).
set -e
OS="$(uname -s)"
if [ "$OS" = "Linux" ]; then
  echo "Removing systemd service (needs sudo)..."
  sudo systemctl disable --now efrisconnect 2>/dev/null || true
  sudo rm -f /etc/systemd/system/efrisconnect.service
  sudo systemctl daemon-reload
  echo "Removed."
elif [ "$OS" = "Darwin" ]; then
  PLIST="$HOME/Library/LaunchAgents/org.tukeihope.efrisconnect.plist"
  launchctl unload "$PLIST" 2>/dev/null || true
  rm -f "$PLIST"
  echo "Removed."
else
  echo "Unsupported OS: $OS."
fi
