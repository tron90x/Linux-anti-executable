#!/bin/bash
#
# Install SELinux policy for Linux Anti-Executable
# Only needed on Fedora, RHEL, CentOS, etc.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_DIR="$SCRIPT_DIR/../config"

# Check if SELinux is enabled
if ! command -v getenforce &> /dev/null; then
    echo "SELinux tools not found. Skipping policy installation."
    exit 0
fi

SELINUX_STATUS=$(getenforce)
if [ "$SELINUX_STATUS" = "Disabled" ]; then
    echo "SELinux is disabled. No policy needed."
    exit 0
fi

echo "SELinux is $SELINUX_STATUS"
echo "Installing SELinux policy for lexec..."

# Check for required tools
if ! command -v checkmodule &> /dev/null; then
    echo "Installing SELinux development tools..."
    if command -v dnf &> /dev/null; then
        sudo dnf install -y selinux-policy-devel
    elif command -v yum &> /dev/null; then
        sudo yum install -y selinux-policy-devel
    else
        echo "Please install selinux-policy-devel manually"
        exit 1
    fi
fi

# Compile and install policy
cd "$CONFIG_DIR"

echo "Compiling policy module..."
checkmodule -M -m -o lexec.mod lexec.te

echo "Creating policy package..."
semodule_package -o lexec.pp -m lexec.mod

echo "Installing policy..."
sudo semodule -i lexec.pp

echo ""
echo "SELinux policy installed successfully!"
echo ""
echo "If you still encounter issues, you can temporarily set SELinux to permissive:"
echo "  sudo setenforce 0"
echo ""
echo "To check for denials:"
echo "  sudo ausearch -m AVC -ts recent"
echo ""

# Cleanup
rm -f lexec.mod lexec.pp
