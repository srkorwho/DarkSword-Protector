#!/bin/bash
set -e

echo "=============================================="
echo "    DarkSword Protector - Auto Deployer"
echo "=============================================="

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (use sudo)"
  exit 1
fi

echo "[*] Updating system packages..."
apt-get update -y > /dev/null

echo "[*] Installing dependencies..."
apt-get install -y wireguard iptables qrencode python3-pip python3-venv > /dev/null

echo "[*] Generating WireGuard Keys..."
WG_DIR="/etc/wireguard"
mkdir -p $WG_DIR
cd $WG_DIR

SERVER_PRIV_KEY=$(wg genkey)
SERVER_PUB_KEY=$(echo $SERVER_PRIV_KEY | wg pubkey)
CLIENT_PRIV_KEY=$(wg genkey)
CLIENT_PUB_KEY=$(echo $CLIENT_PRIV_KEY | wg pubkey)

IFACE=$(ip route | grep default | awk '{print $5}' | head -n 1)
PUBLIC_IP=$(curl -s ifconfig.me)

echo "[*] Configuring WireGuard Server (wg0)..."
cat > $WG_DIR/wg0.conf <<EOF
[Interface]
Address = 10.8.0.1/24
ListenPort = 51820
PrivateKey = $SERVER_PRIV_KEY

# Route traffic to mitmproxy (running in transparent mode on port 8080)
PostUp = iptables -t nat -A PREROUTING -i wg0 -p tcp --dport 80 -j REDIRECT --to-port 8080
PostUp = iptables -t nat -A PREROUTING -i wg0 -p tcp --dport 443 -j REDIRECT --to-port 8080
PostUp = iptables -t nat -A POSTROUTING -o $IFACE -j MASQUERADE
PostDown = iptables -t nat -D PREROUTING -i wg0 -p tcp --dport 80 -j REDIRECT --to-port 8080
PostDown = iptables -t nat -D PREROUTING -i wg0 -p tcp --dport 443 -j REDIRECT --to-port 8080
PostDown = iptables -t nat -D POSTROUTING -o $IFACE -j MASQUERADE
EOF

cat >> $WG_DIR/wg0.conf <<EOF

[Peer]
PublicKey = $CLIENT_PUB_KEY
AllowedIPs = 10.8.0.2/32
EOF

echo "[*] Configuring WireGuard Client (iPhone)..."
cat > $WG_DIR/client.conf <<EOF
[Interface]
PrivateKey = $CLIENT_PRIV_KEY
Address = 10.8.0.2/24
DNS = 1.1.1.1

[Peer]
PublicKey = $SERVER_PUB_KEY
Endpoint = $PUBLIC_IP:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

echo "[*] Enabling IP forwarding..."
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sysctl -p > /dev/null

echo "[*] Configuring Firewall (UFW)..."

ufw allow 51820/udp > /dev/null 2>&1 || true
ufw allow 8080/tcp > /dev/null 2>&1 || true

echo "[*] Enabling and routing WireGuard..."
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

echo "[*] Setting up Mitmproxy Environment..."
cd /root
mkdir -p darksword
cd darksword


echo "[*] Downloading darksword blocker script from GitHub..."
wget -qO darksword_blocker.py "https://raw.githubusercontent.com/sermet/DarkSword-Protector/main/darksword_blocker.py" || true
if [ ! -f "darksword_blocker.py" ]; then
    echo "[!] Failed to fetch Python script, please copy it manually to /root/darksword/darksword_blocker.py"
fi

python3 -m venv venv
source venv/bin/activate
pip install mitmproxy > /dev/null

echo "[*] Waiting for Python environment to settle..."
sleep 5

echo "[*] Starting Mitmproxy in the background (Transparent Mode)..."

nohup mitmdump --mode transparent --listen-port 8080 -s darksword_blocker.py > mitm.log 2>&1 &

echo "=============================================="
echo "    INSTALLATION COMPLETE!                    "
echo "=============================================="
echo ""
echo "Your WireGuard Client Profile is ready."
echo "Scan the QR code below from your iPhone WireGuard App:"
echo ""
qrencode -t ansiutf8 < $WG_DIR/client.conf
echo ""
echo "Note: The very first time you connect, you MUST visit http://mitm.it on your iPhone"
echo "to install the mitmproxy certificate to allow HTTPS inspection!"
echo ""
echo "Mitmproxy is running in the background. Logs are at /root/darksword/mitm.log"
echo "=============================================="
