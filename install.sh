#!/bin/bash
set -e

BIN_NAME="elev"
TARGET_BIN="/usr/bin/$BIN_NAME"
CONF_SRC="./examples/elev.conf"
CONF_DEST="/etc/elev.conf"

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root."
    exit 1
fi

echo "[+] Building elev..."
cargo build --release

echo "[+] Installing binary to $TARGET_BIN"
install -o root -g root -m 4755 target/release/$BIN_NAME $TARGET_BIN

echo "[+] Installing config to $CONF_DEST"
if [ ! -f "$CONF_DEST" ]; then
    cp "$CONF_SRC" "$CONF_DEST"
    echo "[+] Default config installed."
else
    echo "[!] Config already exists at $CONF_DEST – not overwritten."
fi

echo "[+] Done. You can now run: elev whoami"
