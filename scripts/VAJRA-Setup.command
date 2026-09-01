#!/usr/bin/env bash

# VAJRA-Setup.command
# Double-clickable macOS Setup Wizard for Finder (Zero Terminal Typing Required)

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Ensure executable permissions
chmod +x "$0" || true

echo "============================================================"
echo "          VAJRA · macOS Graphical Setup Wizard             "
echo "============================================================"
echo ""

# Run the installer script or GUI wizard
if command -v python3 >/dev/null 2>&1; then
    if [ -f "$DIR/bootstrap_gui.py" ]; then
        python3 "$DIR/bootstrap_gui.py"
        exit 0
    fi
fi

# Fallback to 1-line installation engine
if [ -f "$DIR/install.sh" ]; then
    bash "$DIR/install.sh"
else
    curl -fsSL https://raw.githubusercontent.com/Aravkataria/VAJRA-test/main/scripts/install.sh | bash
fi

echo ""
echo "Installation complete! You can find VAJRA in your Applications folder."
read -p "Press [Enter] to exit..."
