#!/bin/bash

# Author: cjwsam
# License: MIT License
#
# MIT License
#
# Copyright (c) 2025 cjwsam
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Enhanced VPN & Port Forwarding Manager
# Manages VPN setups (OpenVPN, L2TP/IPSec), users, client configs, and port forwarding
# Includes predefined ports for HTPC apps (LinuxServer.io) and gaming devices

# Exit on errors
set -e

# Ensure script runs as root
if [ "$EUID" -ne 0 ]; then
    echo -e "\e[1;31mError: Please run as root (use sudo)\e[0m"
    exit 1
fi

# Configuration
SERVER_IP="IP"  # Your specified server IP
INTERFACE=$(ip route | grep default | awk '{print $5}')  # Auto-detect default interface (e.g., eth0)
OPEN_VPN_SUBNET="10.8.0.0/24"
L2TP_SUBNET="10.9.0.0/24"
BACKUP_DIR="/tmp/iptables_backups"
mkdir -p "$BACKUP_DIR"

# Color codes for UI
RED='\e[1;31m'
GREEN='\e[1;32m'
YELLOW='\e[1;33m'
BLUE='\e[1;34m'
PURPLE='\e[1;35m'
CYAN='\e[1;36m'
NC='\e[0m'

# Spinner for feedback
spin() {
    local -a spinner=('/' '-' '\' '|')
    for i in {1..5}; do
        for s in "${spinner[@]}"; do
            echo -ne "\r${YELLOW}Working... $s${NC}"
            sleep 0.1
        done
    done
    echo -ne "\r${GREEN}Done!         ${NC}\n"
}

# Utility Functions
validate_ip() {
    local ip=$1
    if ! [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then return 1; fi
    IFS='.' read -r a b c d <<< "$ip"
    [ "$a" -lt 0 ] || [ "$a" -gt 255 ] || [ "$b" -lt 0 ] || [ "$b" -gt 255 ] || \
    [ "$c" -lt 0 ] || [ "$c" -gt 255 ] || [ "$d" -lt 0 ] || [ "$d" -gt 255 ] && return 1
    ([ "$a" -eq 10 ] && [ "$b" -eq 8 ] && [ "$c" -eq 0 ]) || \
    ([ "$a" -eq 10 ] && [ "$b" -eq 9 ] && [ "$c" -eq 0 ]) && return 0 || return 1
}

validate_port() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ] && return 0 || return 1; }
validate_protocol() { [ "$1" = "tcp" ] || [ "$1" = "udp" ] && return 0 || return 1; }
backup_iptables() { local t=$(date +%s); iptables-save > "$BACKUP_DIR/iptables_backup_$t.rules"; echo -e "${GREEN}Backup: $BACKUP_DIR/iptables_backup_$t.rules${NC}"; }
restore_iptables() {
    local b=$(ls -t "$BACKUP_DIR"/*.rules 2>/dev/null | head -n1)
    [ -z "$b" ] && { echo -e "${RED}No backups found!${NC}"; return 1; }
    iptables-restore < "$b"; echo -e "${GREEN}Rolled back to $b${NC}"; rm -f "$b"
}
check_existing_rule() { iptables -t nat -L PREROUTING -n | grep "DNAT" | grep " $1 " | grep "dpt:$2 " > /dev/null; }

# Predefined Ports (LinuxServer.io HTPC + Gaming)
declare -A port_to_device
port_to_device["32400:tcp"]="Plex"
port_to_device["8989:tcp"]="Sonarr"
port_to_device["7878:tcp"]="Radarr"
port_to_device["8080:tcp"]="qBittorrent Web UI"
port_to_device["6881:tcp"]="qBittorrent Torrent"  # Your qBittorrent torrent port
port_to_device["6881:udp"]="qBittorrent Torrent"  # UDP for torrent traffic
port_to_device["9117:tcp"]="Jackett"
port_to_device["3389:tcp"]="RDP (Computer)"
port_to_device["8181:tcp"]="Tautulli"
for port in 3478 3479 3480; do
    port_to_device["$port:tcp"]="PS4/PS5"
    port_to_device["$port:udp"]="PS4/PS5"
done
port_to_device["3074:tcp"]="Xbox"
for port in 88 500 3074 3544 4500; do
    port_to_device["$port:udp"]="Xbox"
done

get_predefined_ports() {
    local device=$1
    case $device in
        1) echo "32400:tcp" ;; # Plex
        2) echo "8989:tcp" ;; # Sonarr
        3) echo "7878:tcp" ;; # Radarr
        4) echo "8080:tcp 6881:udp" ;; # qBittorrent (torrent ports, per your request)
        5) echo "9117:tcp" ;; # Jackett
        6) echo "3389:tcp" ;; # RDP
        7) echo "8181:tcp" ;; # Tautulli
        8) echo "3478:tcp 3479:tcp 3480:tcp 3478:udp 3479:udp 3480:udp" ;; # PS4/PS5
        9) echo "3074:tcp 88:udp 500:udp 3074:udp 3544:udp 4500:udp" ;; # Xbox
        *) return 1 ;;
    esac
}

# VPN Functions
clean_setup() {
    echo -e "${PURPLE}Cleaning up VPN configs...${NC}"
    read -p "Are you sure? This will wipe all VPN settings! (y/n): " confirm
    [ "$confirm" != "y" ] && { echo -e "${YELLOW}Aborted cleanup.${NC}"; return; }
    spin
    systemctl stop openvpn@server xl2tpd strongswan || true
    rm -rf /etc/openvpn/* /etc/xl2tpd/* /etc/ppp/* /etc/ipsec.* || true
    echo -e "${GREEN}VPN configs cleaned!${NC}"
}

setup_vpn_servers() {
    echo -e "${BLUE}Setting up VPN servers...${NC}"
    spin
    apt update -y
    apt install -y openvpn easy-rsa strongswan xl2tpd iptables-persistent ufw
    # Enable IP forwarding
    sysctl -w net.ipv4.ip_forward=1
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    # OpenVPN setup
    make-cadir /etc/openvpn/easy-rsa
    cd /etc/openvpn/easy-rsa
    ./easyrsa init-pki
    ./easyrsa build-ca nopass
    ./easyrsa gen-dh
    ./easyrsa build-server-full server nopass
    cp pki/ca.crt pki/dh.pem pki/issued/server.crt pki/private/server.key /etc/openvpn/
    cat > /etc/openvpn/server.conf <<EOF
port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
keepalive 10 120
EOF
    systemctl enable openvpn@server
    systemctl start openvpn@server
    ufw allow 1194/udp
    # L2TP/IPSec setup
    cat > /etc/ipsec.conf <<EOF
config setup
    charondebug="ike 2, knl 2, cfg 2"
conn l2tp
    auto=add
    keyexchange=ikev1
    type=transport
    left=%defaultroute
    leftprotoport=17/1701
    right=%any
    rightprotoport=17/%any
    authby=secret
    forceencaps=yes
EOF
    echo ": PSK \"your_shared_secret\"" > /etc/ipsec.secrets
    cat > /etc/xl2tpd/xl2tpd.conf <<EOF
[lns default]
ip range = 10.9.0.2-10.9.0.10
local ip = 10.9.0.1
require chap = yes
refuse pap = yes
require authentication = yes
pppoptfile = /etc/ppp/options.xl2tpd
EOF
    cat > /etc/ppp/options.xl2tpd <<EOF
require-mschap-v2
ms-dns 8.8.8.8
asyncmap 0
auth
lock
proxyarp
EOF
    touch /etc/ppp/chap-secrets
    systemctl enable strongswan xl2tpd
    systemctl start strongswan xl2tpd
    ufw allow 500/udp
    ufw allow 4500/udp
    ufw allow 1701/udp
    echo -e "${GREEN}VPN servers setup complete!${NC}"
}

add_l2tp_users() {
    echo -e "${BLUE}Adding L2TP/IPSec users...${NC}"
    read -p "How many users to add? " num_users
    for ((i=1; i<=num_users; i++)); do
        read -p "Username $i: " username
        read -s -p "Password $i: " password
        echo ""
        echo "$username * $password *" >> /etc/ppp/chap-secrets
        echo -e "${GREEN}Added user: $username${NC}"
    done
    systemctl restart xl2tpd
    echo -e "${GREEN}All users added!${NC}"
}

generate_ovpn_files() {
    echo -e "${BLUE}Generating OpenVPN .ovpn files...${NC}"
    cd /etc/openvpn/easy-rsa || { echo -e "${RED}Easy-RSA not found!${NC}"; return; }
    read -p "How many clients to generate? " num_clients
    for ((i=1; i<=num_clients; i++)); do
        read -p "Client name $i: " client_name
        ./easyrsa build-client-full "$client_name" nopass
        cat > "/etc/openvpn/$client_name.ovpn" <<EOF
client
dev tun
proto udp
remote $SERVER_IP 1194
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
cert $client_name.crt
key $client_name.key
verb 3
EOF
        cp pki/ca.crt pki/issued/"$client_name".crt pki/private/"$client_name".key /etc/openvpn/
        echo -e "${GREEN}Generated /etc/openvpn/$client_name.ovpn${NC}"
    done
    echo -e "${GREEN}All .ovpn files generated!${NC}"
}

# Port Forwarding Functions
setup_device_or_app() {
    echo -e "\n${PURPLE}Setup port forwarding for a device/app${NC}"
    echo "Select a device or app:"
    echo "1. Plex (HTPC)"
    echo "2. Sonarr (HTPC)"
    echo "3. Radarr (HTPC)"
    echo "4. qBittorrent (HTPC)"
    echo "5. Jackett (HTPC)"
    echo "6. Computer (RDP)"
    echo "7. Tautulli (HTPC)"
    echo "8. PS4/PS5 (Gaming)"
    echo "9. Xbox (Gaming)"
    read -p "Enter number: " device_num
    local ports=$(get_predefined_ports "$device_num")
    [ -z "$ports" ] && { echo -e "${RED}Invalid selection${NC}"; return; }
    while true; do
        read -p "Internal IP: " internal_ip
        validate_ip "$internal_ip" && break || echo -e "${RED}Invalid IP. Use $OPEN_VPN_SUBNET or $L2TP_SUBNET${NC}"
    done
    backup_iptables
    for port_proto in $ports; do
        local port=$(echo "$port_proto" | cut -d':' -f1)
        local proto=$(echo "$port_proto" | cut -d':' -f2)
        check_existing_rule "$proto" "$port" && { echo -e "${RED}Rule for $proto:$port exists${NC}"; continue; }
        spin
        ufw allow "$port/$proto"
        iptables -t nat -A PREROUTING -i "$INTERFACE" -p "$proto" --dport "$port" -j DNAT --to-destination "$internal_ip:$port"
        iptables -t nat -A POSTROUTING -s "$internal_ip" -o "$INTERFACE" -j MASQUERADE
        iptables-save > /etc/iptables/rules.v4
        echo -e "${GREEN}Added: $port/$proto -> $internal_ip${NC}"
    done
}

add_custom_port() {
    echo -e "\n${PURPLE}Add custom port forwarding${NC}"
    while true; do
        read -p "Internal IP: " internal_ip
        validate_ip "$internal_ip" && break || echo -e "${RED}Invalid IP. Use $OPEN_VPN_SUBNET or $L2TP_SUBNET${NC}"
    done
    while true; do
        read -p "External port: " external_port
        validate_port "$external_port" && break || echo -e "${RED}Port must be 1-65535${NC}"
    done
    read -p "Internal port (default: $external_port): " internal_port
    internal_port=${internal_port:-$external_port}
    validate_port "$internal_port" || { echo -e "${RED}Invalid internal port${NC}"; return; }
    while true; do
        read -p "Protocol (tcp/udp): " protocol
        validate_protocol "$protocol" && break || echo -e "${RED}Protocol must be 'tcp' or 'udp'${NC}"
    done
    check_existing_rule "$protocol" "$external_port" && { echo -e "${RED}Rule exists${NC}"; return; }
    backup_iptables
    spin
    ufw allow "$external_port/$protocol"
    iptables -t nat -A PREROUTING -i "$INTERFACE" -p "$protocol" --dport "$external_port" -j DNAT --to-destination "$internal_ip:$internal_port"
    iptables -t nat -A POSTROUTING -s "$internal_ip" -o "$INTERFACE" -j MASQUERADE
    iptables-save > /etc/iptables/rules.v4
    echo -e "${GREEN}Added: $external_port/$protocol -> $internal_ip:$internal_port${NC}"
}

list_port_forwarding() {
    echo -e "\n${PURPLE}Current port forwarding rules:${NC}"
    local rules=$(iptables -t nat -L PREROUTING -n --line-numbers | grep DNAT)
    [ -z "$rules" ] && { echo -e "${YELLOW}No rules found.${NC}"; return; }
    while read -r line; do
        local num=$(echo "$line" | awk '{print $1}')
        local proto=$(echo "$line" | awk '{print $3}')
        local dpt=$(echo "$line" | awk '{for (i=1; i<=NF; i++) if ($i ~ /dpt:/) {split($i, a, ":"); print a[2]}}')
        local to=$(echo "$line" | awk '{for (i=1; i<=NF; i++) if ($i ~ /to:/) {split($i, a, ":"); print a[2]}}')
        if [ -n "$proto" ] && [ -n "$dpt" ] && [ -n "$to" ]; then
            local key="$dpt:$proto"
            local device=${port_to_device[$key]:-Custom}
            echo -e "$num: $proto:$dpt -> $to ${CYAN}[$device]${NC}"
        else
            echo -e "$num: $line"
        fi
    done <<< "$rules"
}

remove_port_forwarding() {
    echo -e "\n${PURPLE}Remove port forwarding rule${NC}"
    list_port_forwarding
    read -p "Enter line number to remove: " line_num
    [[ "$line_num" =~ ^[0-9]+$ ]] || { echo -e "${RED}Invalid number${NC}"; return; }
    backup_iptables
    iptables -t nat -D PREROUTING "$line_num"
    iptables-save > /etc/iptables/rules.v4
    echo -e "${GREEN}Rule $line_num removed${NC}"
}

# Main Menu
while true; do
    clear
    echo -e "${GREEN}=== VPN & Port Forwarding Manager ===${NC}"
    echo -e "${BLUE}Server IP: $SERVER_IP${NC}"
    echo -e "${BLUE}Subnets: OpenVPN ($OPEN_VPN_SUBNET), L2TP ($L2TP_SUBNET)${NC}"
    echo -e "${YELLOW}------------------------------------${NC}"
    echo "1. Setup VPN Servers (with clean option)"
    echo "2. Add L2TP/IPSec Users"
    echo "3. Generate OpenVPN .ovpn Files"
    echo "4. Setup Device/App Port Forwarding"
    echo "5. Add Custom Port Forwarding"
    echo "6. List Port Forwarding Rules"
    echo "7. Remove Port Forwarding Rule"
    echo "8. Undo Last Change"
    echo "9. Exit"
    echo -e "${YELLOW}------------------------------------${NC}"
    read -p "Choice [1-9]: " choice
    case $choice in
        1)
            read -p "Clean setup? (y/n): " clean_choice
            [ "$clean_choice" = "y" ] && clean_setup
            setup_vpn_servers
            ;;
        2) add_l2tp_users ;;
        3) generate_ovpn_files ;;
        4) setup_device_or_app ;;
        5) add_custom_port ;;
        6) list_port_forwarding ;;
        7) remove_port_forwarding ;;
        8) restore_iptables ;;
        9) echo -e "${GREEN}Exiting...${NC}"; exit 0 ;;
        *) echo -e "${RED}Invalid choice${NC}" ;;
    esac
    read -p "Press Enter to continue..."
done
