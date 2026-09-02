#!/usr/bin/env bash
# Double-clickable macOS Setup for Finder
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"
chmod +x "$DIR/scripts/install.sh" "$DIR/scripts/VAJRA-Setup.command" 2>/dev/null || true
echo "============================================================"
echo "          VAJRA · macOS One-Click Installer                 "
echo "============================================================"
echo ""
bash "$DIR/scripts/install.sh"
echo ""
read -p "Press [Enter] to exit..."
