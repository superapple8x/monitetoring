#!/bin/bash

# Monitetoring System-Wide Installation Script
# This script helps install monitetoring to /usr/local/bin for easier sudo access

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CARGO_BIN="$HOME/.cargo/bin/monitetoring"
SYSTEM_BIN="/usr/local/bin/monitetoring"

echo "🚀 Monitetoring System-Wide Installation"
echo "========================================"
echo

# Check if monitetoring is installed via cargo
if [ ! -f "$CARGO_BIN" ]; then
    echo "❌ Monitetoring not found in ~/.cargo/bin/"
    echo "   Please install it first with: cargo install monitetoring"
    exit 1
fi

echo "✅ Found monitetoring at: $CARGO_BIN"
echo

# Check if we're running as root (not recommended)
if [ "$EUID" -eq 0 ]; then
    echo "⚠️  Warning: Running as root. This script should be run as a regular user."
    echo "   It will use sudo when needed."
    echo
fi

# Check if system binary already exists
if [ -f "$SYSTEM_BIN" ]; then
    echo "📋 System-wide installation already exists at: $SYSTEM_BIN"
    echo "   Current version: $(sudo $SYSTEM_BIN --version 2>/dev/null || echo 'unknown')"
    echo "   Cargo version:   $($CARGO_BIN --version)"
    echo
    
    read -p "🔄 Update system-wide installation? [Y/n]: " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]] && [[ ! -z $REPLY ]]; then
        echo "❌ Installation cancelled."
        exit 0
    fi
    echo
fi

# Create the symlink
echo "🔗 Creating system-wide symlink..."
if sudo ln -sf "$CARGO_BIN" "$SYSTEM_BIN"; then
    echo "✅ Successfully created symlink: $SYSTEM_BIN -> $CARGO_BIN"
else
    echo "❌ Failed to create symlink. Check permissions."
    exit 1
fi

# Verify the installation
echo
echo "🧪 Testing installation..."
if sudo "$SYSTEM_BIN" --version >/dev/null 2>&1; then
    echo "✅ System-wide installation successful!"
    echo
    echo "🎉 You can now run: sudo monitetoring --iface any"
    echo "   (No need for full path anymore)"
else
    echo "❌ Installation verification failed."
    exit 1
fi

echo
echo "📝 Note: This creates a symlink, so updates via 'cargo install monitetoring'"
echo "   will automatically update the system-wide version too."
echo
echo "🗑️  To remove: sudo rm $SYSTEM_BIN" 