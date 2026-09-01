#!/usr/bin/env bash
# scripts/install.sh
# Universal 1-Line Bootstrapper & Installer for macOS & Linux
# Usage: curl -fsSL https://raw.githubusercontent.com/Aravkataria/VAJRA-test/main/scripts/install.sh | bash

set -e

BOLD="\033[1m"
GREEN="\033[0;32m"
BLUE="\033[0;34m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
RESET="\033[0m"

echo -e "${BOLD}${BLUE}"
echo "================================================================"
echo "    VAJRA · Autonomous Cyber-Reasoning & Verification System    "
echo "        Universal Bootstrapper for macOS & Linux                "
echo "================================================================"
echo -e "${RESET}"

# 1. Detect OS
OS_TYPE="$(uname -s)"
case "$OS_TYPE" in
    Darwin*)  PLATFORM="macOS" ;;
    Linux*)   PLATFORM="Linux" ;;
    *)        PLATFORM="Unix" ;;
esac

echo -e "[1/5] Detected Operating System: ${GREEN}${PLATFORM}${RESET}"

# 2. Check for Python 3.10+
PYTHON_BIN=""
for cmd in python3.13 python3.12 python3.11 python3.10 python3 python; do
    if command -v "$cmd" >/dev/null 2>&1; then
        VERSION_CHECK=$("$cmd" -c 'import sys; print(int(sys.version_info >= (3, 10)))' 2>/dev/null || echo "0")
        if [ "$VERSION_CHECK" = "1" ]; then
            PYTHON_BIN="$(command -v "$cmd")"
            break
        fi
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo -e "${RED}[ERROR] Python 3.10 or higher is required.${RESET}"
    if [ "$PLATFORM" = "macOS" ]; then
        echo -e "${YELLOW}Install with Homebrew: brew install python3${RESET}"
    else
        echo -e "${YELLOW}Install with apt: sudo apt update && sudo apt install -y python3 python3-venv python3-pip${RESET}"
    fi
    exit 1
fi

echo -e "[2/5] Using Python: ${GREEN}$($PYTHON_BIN --version)${RESET} (${PYTHON_BIN})"

# 3. Setup directories in ~/.vajra
VAJRA_HOME="$HOME/.vajra"
VAJRA_APP="$VAJRA_HOME/app"
VAJRA_VENV="$VAJRA_HOME/venv"
VAJRA_BIN="$HOME/.local/bin"

mkdir -p "$VAJRA_HOME" "$VAJRA_BIN"

echo -e "[3/5] Setting up isolated application environment in ${BLUE}${VAJRA_HOME}${RESET}..."

# Download or update source code
REPO_URL="https://github.com/Aravkataria/VAJRA-test/archive/refs/heads/main.zip"
TEMP_ZIP="$VAJRA_HOME/source.zip"

echo -e "      Downloading latest VAJRA source..."
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$REPO_URL" -o "$TEMP_ZIP"
elif command -v wget >/dev/null 2>&1; then
    wget -q "$REPO_URL" -O "$TEMP_ZIP"
else
    echo -e "${RED}[ERROR] Neither curl nor wget was found.${RESET}"
    exit 1
fi

rm -rf "$VAJRA_APP"
mkdir -p "$VAJRA_APP"
unzip -q "$TEMP_ZIP" -d "$VAJRA_HOME"
mv "$VAJRA_HOME/VAJRA-test-main"/* "$VAJRA_APP"/ 2>/dev/null || mv "$VAJRA_HOME"/VAJRA-test-*/* "$VAJRA_APP"/
rm -rf "$TEMP_ZIP" "$VAJRA_HOME"/VAJRA-test-*

# 4. Provision Python Virtual Environment
echo -e "[4/5] Provisioning isolated Python virtual environment..."
if [ ! -d "$VAJRA_VENV" ]; then
    "$PYTHON_BIN" -m venv "$VAJRA_VENV"
fi

"$VAJRA_VENV/bin/pip" install --upgrade pip --quiet
"$VAJRA_VENV/bin/pip" install -r "$VAJRA_APP/requirements.txt" --quiet

# 5. Create Executable CLI Shim in ~/.local/bin/vajra
cat << 'EOF' > "$VAJRA_BIN/vajra"
#!/usr/bin/env bash
VAJRA_HOME="$HOME/.vajra"
export PYTHONPATH="$VAJRA_HOME/app:$PYTHONPATH"
exec "$VAJRA_HOME/venv/bin/python" -m app.launcher "$@"
EOF

chmod +x "$VAJRA_BIN/vajra"

# Add ~/.local/bin to PATH in shell profile if not present
for rcfile in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.profile"; do
    if [ -f "$rcfile" ]; then
        if ! grep -q '\.local/bin' "$rcfile"; then
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$rcfile"
        fi
    fi
done

# 6. Desktop OS Integration
echo -e "[5/5] Creating Desktop Launcher..."
if [ "$PLATFORM" = "macOS" ]; then
    # Create macOS .app bundle in ~/Applications
    APP_BUNDLE="$HOME/Applications/VAJRA.app"
    mkdir -p "$APP_BUNDLE/Contents/MacOS" "$APP_BUNDLE/Contents/Resources"

    cat << EOF > "$APP_BUNDLE/Contents/Info.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>vajra_launcher</string>
    <key>CFBundleIdentifier</key>
    <string>ai.vajra.desktop</string>
    <key>CFBundleName</key>
    <string>VAJRA</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>2.4.0</string>
</dict>
</plist>
EOF

    cat << EOF > "$APP_BUNDLE/Contents/MacOS/vajra_launcher"
#!/usr/bin/env bash
export PATH="\$HOME/.local/bin:\$PATH"
exec "\$HOME/.vajra/venv/bin/python" -m app.launcher "\$@"
EOF
    chmod +x "$APP_BUNDLE/Contents/MacOS/vajra_launcher"
    echo -e "      Created ${GREEN}~/Applications/VAJRA.app${RESET} (Spotlight / Launchpad ready)"

elif [ "$PLATFORM" = "Linux" ]; then
    # Create FreeDesktop .desktop file
    DESKTOP_DIR="$HOME/.local/share/applications"
    mkdir -p "$DESKTOP_DIR"
    cat << EOF > "$DESKTOP_DIR/vajra.desktop"
[Desktop Entry]
Name=VAJRA
Comment=Autonomous Cyber-Reasoning & Verification System
Exec=$VAJRA_BIN/vajra
Terminal=false
Type=Application
Categories=Development;Security;
EOF
    chmod +x "$DESKTOP_DIR/vajra.desktop"
    echo -e "      Created ${GREEN}~/.local/share/applications/vajra.desktop${RESET}"
fi

echo -e "\n${BOLD}${GREEN}================================================================${RESET}"
echo -e "${BOLD}${GREEN}        VAJRA Installation Complete! Ready to Run.              ${RESET}"
echo -e "${BOLD}${GREEN}================================================================${RESET}"
echo -e ""
echo -e "  To launch the Desktop App:      ${BOLD}vajra${RESET}"
echo -e "  To launch the Local Web Server: ${BOLD}vajra --web${RESET}"
echo -e "  To scan a folder from CLI:      ${BOLD}vajra scan /path/to/project${RESET}"
echo -e "  To check for updates:           ${BOLD}vajra update${RESET}"
echo -e ""
