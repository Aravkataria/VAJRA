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

# Run the native Graphical Setup Wizard
if command -v python3 >/dev/null 2>&1; then
    if [ -f "$DIR/bootstrap_gui.py" ]; then
        python3 "$DIR/bootstrap_gui.py"
        exit 0
    elif [ -f "$DIR/scripts/bootstrap_gui.py" ]; then
        python3 "$DIR/scripts/bootstrap_gui.py"
        exit 0
    else
        TMP_DIR="$(mktemp -d)"
        TMP_GUI="$TMP_DIR/bootstrap_gui.py"
        if curl -fsSL "https://raw.githubusercontent.com/Aravkataria/VAJRA/main/scripts/bootstrap_gui.py" -o "$TMP_GUI" 2>/dev/null; then
            python3 "$TMP_GUI"
            rm -rf "$TMP_DIR"
            exit 0
        fi
    fi
fi

# Fallback to terminal installation engine
if [ -f "$DIR/install.sh" ]; then
    bash "$DIR/install.sh"
elif [ -f "$DIR/scripts/install.sh" ]; then
    bash "$DIR/scripts/install.sh"
else
    curl -fsSL https://raw.githubusercontent.com/Aravkataria/VAJRA/main/scripts/install.sh | bash
fi

echo ""
echo "Installation complete! You can find VAJRA in your Applications folder."
read -p "Press [Enter] to exit..."
