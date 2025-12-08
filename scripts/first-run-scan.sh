#!/bin/bash
#
# Linux Anti-Executable First Run Scanner
#
# This script performs the initial system scan to whitelist
# all existing executables before enabling protection.
#

set -e

LEXEC_DAEMON="/usr/local/sbin/lexec-daemon"
DB_PATH="/var/lib/lexec/whitelist.db"

echo "=== Linux Anti-Executable Initial Setup ==="
echo ""

# Check for root
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root"
    exit 1
fi

# Check kernel version for fanotify support
KERNEL_VERSION=$(uname -r | cut -d. -f1-2)
KERNEL_MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
KERNEL_MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)

if [[ $KERNEL_MAJOR -lt 5 ]]; then
    echo "Warning: Kernel $KERNEL_VERSION detected."
    echo "FAN_OPEN_EXEC_PERM requires kernel 5.0 or later."
    echo ""
fi

# Create directories
echo "Creating directories..."
mkdir -p /var/lib/lexec
mkdir -p /var/run/lexec
mkdir -p /etc/lexec

# Install configuration
if [[ ! -f /etc/lexec/lexec.conf ]]; then
    echo "Installing default configuration..."
    cp "$(dirname "$0")/../config/lexec.conf" /etc/lexec/
fi

# Perform initial scan
echo ""
echo "Starting initial system scan..."
echo "This will whitelist all existing executables."
echo ""

$LEXEC_DAEMON --scan --foreground &
DAEMON_PID=$!

# Wait for scan to complete (daemon will continue running)
sleep 2

echo ""
echo "Initial scan started. The daemon is now running."
echo ""
echo "Options:"
echo "  1. Keep running in learning mode (recommended for first hour)"
echo "  2. Stop and enable strict mode"
echo ""
read -p "Enter choice [1/2]: " choice

case $choice in
    1)
        echo "Learning mode enabled. New executables will be auto-whitelisted."
        echo "Run 'sudo systemctl restart lexec-daemon' when ready to switch to strict mode."
        ;;
    2)
        kill $DAEMON_PID 2>/dev/null || true
        echo "Installing systemd service..."
        cp "$(dirname "$0")/../config/lexec-daemon.service" /etc/systemd/system/
        systemctl daemon-reload
        systemctl enable lexec-daemon
        systemctl start lexec-daemon
        echo "Strict mode enabled. Unknown executables will be blocked."
        ;;
    *)
        echo "Invalid choice. Daemon is still running."
        ;;
esac

echo ""
echo "Setup complete!"
echo ""
echo "Useful commands:"
echo "  sudo systemctl status lexec-daemon  - Check daemon status"
echo "  sudo systemctl stop lexec-daemon    - Stop protection"
echo "  lexec-gui                           - Open management GUI"
echo ""
