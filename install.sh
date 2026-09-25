#!/usr/bin/env bash
set -e

echo "======================================================="
echo "  ULPF-X Standalone Engine Initializer"
echo "======================================================="

# Reliably resolve repository root directory (supports root or scripts/ location)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/scripts/audit.py" ]; then
    ROOT_DIR="$SCRIPT_DIR"
elif [ -f "$SCRIPT_DIR/../scripts/audit.py" ]; then
    ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
else
    ROOT_DIR="$SCRIPT_DIR"
fi

TARGET_DIR="$HOME/.ulpx"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# --- Step 1: Pre-flight Verification & Atomic Backup ---
echo "[1/5] Checking host environment..."
if [ -d "$TARGET_DIR" ]; then
    echo "  ↳ Existing ULPF-X engine detected at $TARGET_DIR"
    echo "  ↳ Backing up existing engine configuration..."
    mv "$TARGET_DIR" "${TARGET_DIR}_backup_${TIMESTAMP}"
fi

# --- Step 2: Target Directory Provisioning ---
echo "[2/5] Creating engine home directory structure..."
mkdir -p "$TARGET_DIR/bin"
mkdir -p "$TARGET_DIR/scripts"
mkdir -p "$TARGET_DIR/logs"

# --- Step 3: Clean Extraction & Mirroring ---
echo "[3/5] Mirroring engine core files into $TARGET_DIR..."
cd "$ROOT_DIR"
tar --exclude='./install.sh' \
    --exclude='./install.bat' \
    --exclude='./.git*' \
    --exclude='*.zip' \
    --exclude='*.tar.gz' \
    --exclude='./dist' \
    --exclude='./venv' \
    --exclude='./node_modules' \
    --exclude='./.next' \
    --exclude='./.pytest_cache' \
    -cf - . | (cd "$TARGET_DIR" && tar -xf -)

chmod +x "$TARGET_DIR/bin/"* 2>/dev/null || true
chmod +x "$TARGET_DIR/scripts/"* 2>/dev/null || true

# --- Step 4: Multi-Shell Hook Registration (Bash, Zsh, macOS Darwin) ---
echo "[4/5] Registering shell configuration hooks..."

register_shell_config() {
    local RC_FILE="$1"
    local SHELL_NAME="$2"

    if [ -f "$RC_FILE" ] || [ "$SHELL_NAME" = "zsh" ] || [ "$SHELL_NAME" = "bash" ]; then
        touch "$RC_FILE"
        if ! grep -q '# --- ULPF-X ENGINE ---' "$RC_FILE"; then
            echo "" >> "$RC_FILE"
            echo '# --- ULPF-X ENGINE ---' >> "$RC_FILE"
            echo 'export PATH="$HOME/.ulpx/bin:$PATH"' >> "$RC_FILE"
            echo 'alias ulpx-test="python3 ~/.ulpx/scripts/audit.py"' >> "$RC_FILE"
            echo '[ -f "$HOME/.ulpx/env.sh" ] && source "$HOME/.ulpx/env.sh"' >> "$RC_FILE"
            echo '[ -f "$HOME/.ulpx/scripts/env.sh" ] && source "$HOME/.ulpx/scripts/env.sh"' >> "$RC_FILE"
            echo "  ✔ Registered ULPF-X hooks in $RC_FILE ($SHELL_NAME)"
        fi
    fi
}

register_shell_config "$HOME/.bashrc" "bash"
register_shell_config "$HOME/.zshrc" "zsh"

if [ "$(uname)" = "Darwin" ]; then
    register_shell_config "$HOME/.zprofile" "zsh-profile"
fi

# --- Step 5: Post-Install Verification ---
echo "[5/5] Testing environment state..."
export PATH="$TARGET_DIR/bin:$PATH"

if [ -f "$TARGET_DIR/scripts/audit.py" ]; then
    echo "  ✔ Engine core successfully verified."
fi

echo "======================================================="
echo "  ULPF-X Installation Complete!"
echo "======================================================="
echo "To activate ULPF-X in your current terminal session, run:"
echo "    source ~/.zshrc   # (or source ~/.bashrc)"
echo "Then run 'ulpx-test' to verify installation."
echo "======================================================="