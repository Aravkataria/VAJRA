#!/usr/bin/env bash
# Double-clickable Linux Setup Installer
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"
chmod +x "$DIR/scripts/install.sh" 2>/dev/null || true
echo "============================================================"
echo "          VAJRA · Linux One-Click Installer                 "
echo "============================================================"
echo ""
bash "$DIR/scripts/install.sh"
echo ""
read -p "Press [Enter] to exit..."
