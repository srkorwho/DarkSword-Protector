# DarkSword-Protector
DarkSword-Protector utilizes WireGuard and mitmproxy to intercept, scan, and neutralize iOS exploit payloads at network-level.



# How to setup on your server
1. Clone the repository and run the setup script:
```bash
wget https://raw.githubusercontent.com/srkorwho/DarkSword-Protector/refs/heads/main/deploy.sh
bash deploy.sh
```
2. Scan the provided QR code with your WireGuard app on iOS.
3. Install the Mitmproxy Certificate via `http://mitm.it`.
4. Done. Your device is now immune to targeted RCE chains.
