#!/usr/bin/env sh
# Start EFRISConnect for the shop network (LAN) on macOS / Linux - the
# equivalent of windows\EFRISConnect.bat option 8. Tills on the same private
# Wi-Fi/LAN then open https://<this computer>:5443/extension.
#
#   unix/start-lan.sh              (Manager Server Edition on port 5000)
#   MANAGER_PORTS=8080 unix/start-lan.sh
#
# Needs the HTTPS certificate first (unix/setup-https.sh). Makes no firewall
# changes: allow inbound TCP 5443 (and Manager Server's port) from the LAN
# yourself if a firewall is on (see the hint printed below).
set -e
DIR="$(cd "$(dirname "$0")/.." && pwd)"
DATA="${DATA_DIR_OVERRIDE:-$DIR/backend/data}"

if ! command -v node >/dev/null 2>&1; then echo "Node.js not found on PATH. Install Node 20+ first."; exit 1; fi
if [ ! -f "$DATA/https.pfx" ] && [ ! -f "$DATA/https_cert.pem" ]; then
  echo "HTTPS is not set up yet. Run unix/setup-https.sh once, then start again."
  exit 1
fi

HOST="$(hostname -s 2>/dev/null || hostname)"
HOST="$(printf '%s' "$HOST" | tr 'A-Z' 'a-z')"
# Private IPv4 addresses only (10.x, 172.16-31.x, 192.168.x).
if command -v ip >/dev/null 2>&1; then
  ALL_IPS="$(ip -4 -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1)"
else
  ALL_IPS="$(ifconfig 2>/dev/null | awk '/inet /{print $2}' | sed 's/addr://')"
fi
IPS="$(printf '%s\n' $ALL_IPS | grep -E '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' | sort -u | tr '\n' ' ')"
if [ -z "$IPS" ]; then
  echo "This computer has no private network address. Connect it to the shop Wi-Fi/LAN first."
  exit 1
fi
HOSTS="$HOST,$HOST.local"
for ip in $IPS; do HOSTS="$HOSTS,$ip"; done

export BIND_HOST=0.0.0.0
export ALLOWED_HOSTS="$HOSTS"
export LAN_MODE=1
export MANAGER_PORTS="${MANAGER_PORTS:-5000}"

echo "============================================================"
echo "  Shop network mode"
echo "  Tills open (after trusting the certificate once):"
for h in $HOST $IPS; do echo "    https://$h:5443/extension"; done
echo "  Manager custom button URL: https://$HOST:5443/extension"
MGR_HTTPS=$(( ${MANAGER_PORTS%%,*} + 1 ))
echo "  Manager for tills (encrypted): https://$HOST:$MGR_HTTPS"
echo "  Till kit (certificate + README): $DATA/till-kit"
echo "  Firewall: allow inbound TCP 5443 and $MGR_HTTPS (Manager over HTTPS)"
echo "  from the LAN only, e.g. Linux: sudo ufw allow from 192.168.0.0/16 to any port 5443 proto tcp"
echo "  macOS: System Settings > Network > Firewall (allow incoming for node)."
echo "============================================================"
cd "$DIR/backend"
exec node server.js
