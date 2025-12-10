#!/bin/bash
#
# Linux Anti-Executable - Dependency Installer
# Automatically detects distribution and installs required packages
#

set -e

echo "=== Linux Anti-Executable Dependency Installer ==="
echo ""

# Detect distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        DISTRO_VERSION=$VERSION_ID
        DISTRO_NAME=$NAME
    elif [ -f /etc/lsb-release ]; then
        . /etc/lsb-release
        DISTRO=$DISTRIB_ID
        DISTRO_VERSION=$DISTRIB_RELEASE
        DISTRO_NAME=$DISTRIB_DESCRIPTION
    else
        DISTRO="unknown"
    fi
}

detect_distro

echo "Detected: $DISTRO_NAME"
echo ""

case "$DISTRO" in
    ubuntu|debian|linuxmint|pop)
        echo "Installing dependencies for Debian/Ubuntu..."
        sudo apt update
        sudo apt install -y \
            build-essential \
            libsqlite3-dev \
            libssl-dev \
            libgtk-4-dev \
            pkg-config
        echo ""
        echo "Dependencies installed successfully!"
        ;;

    fedora)
        echo "Installing dependencies for Fedora..."
        sudo dnf install -y \
            gcc \
            make \
            sqlite-devel \
            openssl-devel \
            gtk4-devel \
            pkg-config
        echo ""
        echo "Dependencies installed successfully!"
        echo ""
        echo "NOTE: Fedora uses SELinux. If you encounter permission issues,"
        echo "you may need to create an SELinux policy or run:"
        echo "  sudo setenforce 0  (temporarily disable SELinux for testing)"
        ;;

    rhel|centos|rocky|alma)
        echo "Installing dependencies for RHEL/CentOS..."
        sudo dnf install -y epel-release
        sudo dnf install -y \
            gcc \
            make \
            sqlite-devel \
            openssl-devel \
            gtk4-devel \
            pkg-config
        echo ""
        echo "Dependencies installed successfully!"
        ;;

    arch|manjaro)
        echo "Installing dependencies for Arch Linux..."
        sudo pacman -S --needed \
            base-devel \
            sqlite \
            openssl \
            gtk4 \
            pkgconf
        echo ""
        echo "Dependencies installed successfully!"
        ;;

    opensuse*|suse)
        echo "Installing dependencies for openSUSE..."
        sudo zypper install -y \
            gcc \
            make \
            sqlite3-devel \
            libopenssl-devel \
            gtk4-devel \
            pkg-config
        echo ""
        echo "Dependencies installed successfully!"
        ;;

    *)
        echo "Unknown distribution: $DISTRO"
        echo ""
        echo "Please install these packages manually:"
        echo "  - gcc and make (build tools)"
        echo "  - SQLite3 development files"
        echo "  - OpenSSL development files"
        echo "  - GTK4 development files"
        echo "  - pkg-config"
        exit 1
        ;;
esac

# Check kernel version
KERNEL_VERSION=$(uname -r | cut -d. -f1,2)
KERNEL_MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
KERNEL_MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)

echo ""
echo "Kernel version: $(uname -r)"

if [ "$KERNEL_MAJOR" -lt 5 ]; then
    echo "WARNING: Kernel $KERNEL_VERSION detected."
    echo "FAN_OPEN_EXEC_PERM requires kernel 5.0 or later."
    echo "Please upgrade your kernel before using this application."
else
    echo "Kernel version OK (5.0+ required, you have $KERNEL_VERSION)"
fi

echo ""
echo "=== Ready to Build ==="
echo ""
echo "Next steps:"
echo "  1. make"
echo "  2. sudo make install"
echo "  3. sudo lexec-daemon --scan --learn --foreground"
echo ""
