# AutoVPNSetupForVPS

**Repository:** [cjwsam/AutoVPNSetupForVPS](https://github.com/cjwsam/AutoVPNSetupForVPS)  
**Author:** cjwsam

## Overview

Overview
AutoVPNSetupForVPS is an enhanced VPN and port forwarding manager designed for VPS environments. This Bash script automates the setup of VPN servers (supporting OpenVPN and L2TP/IPSec), manages VPN users and client configurations, and configures port forwarding rules – including predefined ports for popular HTPC applications (inspired by LinuxServer.io) and gaming devices.

Note: This script must be run with root privileges. It includes interactive menus and safety checks (backups and rollbacks) to help you manage iptables rules and ensure that your VPN and port forwarding configurations remain consistent.

Features
VPN Server Setup:

Automates installation and configuration for OpenVPN and L2TP/IPSec.

Generates server configuration files and sets up IP forwarding.

User Management:

Add L2TP/IPSec users interactively.

Generate individual OpenVPN client configuration files (.ovpn).

Port Forwarding:

Configure device/app specific port forwarding for HTPC applications (e.g., Plex, Sonarr, Radarr) and gaming consoles (e.g., PS4/PS5, Xbox).

Option to add custom port forwarding rules.

Lists and removes existing iptables port forwarding rules.

Backs up iptables rules before changes and supports rollbacks.

Predefined Configurations:

Preloaded port mappings for common apps/devices to streamline your setup.

Requirements
A Debian-based or similar Linux distribution with the apt package manager.

Must be executed as root (or using sudo).

Required packages: openvpn, easy-rsa, strongswan, xl2tpd, iptables-persistent, and ufw.

Installation
Clone the Repository:

bash
Copy
git clone https://github.com/cjwsam/AutoVPNSetupForVPS.git
cd AutoVPNSetupForVPS
Make the Script Executable:

Replace vpn_manager.sh with the actual script filename if different.

bash
Copy
chmod +x vpn_manager.sh
Run the Script as Root:

bash
Copy
sudo ./vpn_manager.sh
Configuration
Before running the script, ensure you update the following settings in the script to suit your environment:

SERVER_IP:
Replace "IP" with your server’s public or dedicated IP address.

Subnets:
Adjust the OpenVPN (10.8.0.0/24) and L2TP (10.9.0.0/24) subnets if necessary.

Predefined Port Mappings:
The script includes a default set of port mappings for HTPC apps and gaming devices. You can customize these in the associative array within the script.

Usage
After executing the script, you will be presented with an interactive menu to:

Set up or clean VPN servers.

Add L2TP/IPSec users.

Generate OpenVPN client configuration files.

Configure port forwarding for predefined devices/apps.

Add custom port forwarding rules.

List current port forwarding rules.

Remove a specific port forwarding rule.

Undo the last iptables change.

Follow the on-screen prompts to complete your configuration.

Security Notice
Run as Root: The script must be executed as root. Ensure you understand the changes it makes to system configurations and firewall settings.

Test in a Controlled Environment: It is recommended to test the script in a safe environment before deploying it in production.

Backup: The script creates backups of your iptables rules in /tmp/iptables_backups before making changes.

Credits
Developed by: cjwsam

Inspiration:

Predefined ports for HTPC applications are based on recommendations from LinuxServer.io.

This project leverages and integrates several open source projects (OpenVPN, Easy-RSA, StrongSwan, XL2TPD, iptables, UFW).

License
This project is licensed under the MIT License. The full license text is provided below:

MIT License

Copyright (c) 2025 cjwsam

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Contributing
Contributions, issues, and feature requests are welcome!
Feel free to check issues page if you want to contribute.

Fork the repository.

Create your feature branch: git checkout -b feature/my-feature

Commit your changes: git commit -am 'Add some feature'

Push to the branch: git push origin feature/my-feature

Create a new Pull Request.

Enjoy a streamlined VPN and port forwarding setup for your VPS!
