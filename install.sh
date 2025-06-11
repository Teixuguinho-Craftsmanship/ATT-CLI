#!/usr/bin/env bash
set -e

echo "[-] Creating directory ~/.mitre/"
mkdir -p  ~/.mitre/

echo "[-] Getting MITRE ATT&CK Matrix JSON"
curl -L "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json" > ~/.mitre/matrix.json

echo "[-] Compiling Rust binary"
cd ./attcli
cargo build --release
cd ..

echo "[-] Moving binary to PATH directory"
INSTALL_PATH="/usr/local/bin/attcli"
chmod +x ./attcli/target/release/attcli
sudo cp attcli/target/release/attcli "$INSTALL_PATH"

echo "[-] Cleaning up"
cd ./attcli
cargo clean
cd ..

echo "[*] ATT&CLI is now installed, you can delete this folder."
echo "[*] Thank you for running."
