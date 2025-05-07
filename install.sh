#!/bin/bash
set -e

BIN_NAME="nexus"
TARGET_BIN="/usr/local/bin/$BIN_NAME"
CONF_FILE="examples/nexus.conf"
CONF_DEST="/etc/$CONF_FILE"

echo "[+] Building Nexus..."
cargo build --release

echo "[+] Installing binary to $TARGET_BIN"
sudo install -o root -g root -m 4755 target/release/$BIN_NAME $TARGET_BIN

echo "[+] Installing config to $CONF_DEST"
if [ ! -f "$CONF_DEST" ]; then
    sudo cp "$CONF_FILE" "$CONF_DEST"
    echo "[+] Default config installed."
else
    echo "[!] Config already exists at $CONF_DEST – not overwritten."
fi

echo "[+] Done. Run with: $BIN_NAME <command>"
