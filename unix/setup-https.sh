#!/usr/bin/env sh
# Local HTTPS setup for macOS / Linux (equivalent of windows/setup-https.ps1).
# Generates a self-signed certificate for localhost + 127.0.0.1 and writes it where
# the relay reads it: backend/data/https_cert.pem and backend/data/https_key.pem.
# Requires openssl (preinstalled on macOS and most Linux). For a browser-trusted
# cert, prefer mkcert (see docs/self-hosting.md); this script uses openssl so it
# works with no extra tools.
set -e
DIR="$(cd "$(dirname "$0")/.." && pwd)"
DATA="$DIR/backend/data"
mkdir -p "$DATA"
if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is not installed. Install it, or use mkcert (see docs/self-hosting.md)."
  exit 1
fi
# Names tills on the shop network may use (unix/start-lan.sh): this computer's
# name, name.local and its private IPv4 addresses, besides localhost.
HOST="$(hostname -s 2>/dev/null || hostname)"
if command -v ip >/dev/null 2>&1; then
  ALL_IPS="$(ip -4 -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1)"
else
  ALL_IPS="$(ifconfig 2>/dev/null | awk '/inet /{print $2}' | sed 's/addr://')"
fi
SAN="DNS:localhost,IP:127.0.0.1"
[ -n "$HOST" ] && SAN="$SAN,DNS:$HOST,DNS:$HOST.local"
for ip in $(printf '%s\n' $ALL_IPS | grep -E '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' | sort -u); do SAN="$SAN,IP:$ip"; done
echo "Generating a self-signed certificate (10 years) for: $SAN"
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$DATA/https_key.pem" -out "$DATA/https_cert.pem" \
  -days 3650 -subj "/CN=EFRISConnect Local HTTPS" \
  -addext "subjectAltName=$SAN"
chmod 600 "$DATA/https_key.pem"
echo "Done. Wrote:"
echo "  $DATA/https_cert.pem"
echo "  $DATA/https_key.pem"
echo ""
echo "Restart the relay; it will serve https://localhost:5443/extension."
echo "To make the browser trust it (self-signed), see docs/self-hosting.md:"
echo "  macOS: security add-trusted-cert ... System.keychain"
echo "  Linux: copy to /usr/local/share/ca-certificates and run update-ca-certificates"
echo "Or use mkcert instead for automatic trust."
