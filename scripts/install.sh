#!/usr/bin/env bash
# ==============================================================================
# ULPF-X Autonomous Engine Installer (Unix/Linux/macOS/Git Bash)
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "======================================================="
echo "  ULPF-X Standalone Engine Initializer"
echo "======================================================="

TARGET_DIR="$HOME/.ulpx"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# --- Step 1: Pre-flight Verification ---
echo "[1/5] Checking host environment..."
if [ -d "$TARGET_DIR" ]; then
    echo "  ↳ Existing ULPF-X engine detected at $TARGET_DIR"
    echo "  ↳ Backing up existing engine configuration..."
    mv "$TARGET_DIR" "${TARGET_DIR}_backup_${TIMESTAMP}"
    echo "  ↳ Backup created: ${TARGET_DIR}_backup_${TIMESTAMP}"
fi

# --- Step 2: Target Directory Provisioning ---
echo "[2/5] Creating engine home directory structure..."
mkdir -p "$TARGET_DIR/bin"
mkdir -p "$TARGET_DIR/scripts"
mkdir -p "$TARGET_DIR/logs"

# --- Step 3: Clean Extraction & Mirroring ---
echo "[3/5] Mirroring engine core files into $TARGET_DIR..."
# Mirror from repository root using tar stream
(
    cd "$ROOT_DIR"
    tar --exclude='./install.sh' \
        --exclude='./install.bat' \
        --exclude='./.git*' \
        --exclude='../*.zip' \
        --exclude='./dist' \
        -cf - .
) | (cd "$TARGET_DIR" && tar -xf -)

# Ensure scripts/env.sh is mirrored to $TARGET_DIR/env.sh for backwards compatibility
if [ -f "$TARGET_DIR/scripts/env.sh" ]; then
    cp "$TARGET_DIR/scripts/env.sh" "$TARGET_DIR/env.sh" 2>/dev/null || true
fi

# Ensure execution permissions on bin/ and scripts/
chmod +x "$TARGET_DIR/bin/"* 2>/dev/null || true
chmod +x "$TARGET_DIR/scripts/"* 2>/dev/null || true

# --- Step 4: Multi-Shell Hook Registration (Bash & Zsh Support) ---
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
            echo '[ -f "$HOME/.ulpx/scripts/env.sh" ] && source "$HOME/.ulpx/scripts/env.sh"' >> "$RC_FILE"
            echo '[ -f "$HOME/.ulpx/env.sh" ] && source "$HOME/.ulpx/env.sh"' >> "$RC_FILE"
            echo "  ✔ Registered ULPF-X hooks in $RC_FILE ($SHELL_NAME)"
        else
            echo "  ℹ Hooks already present in $RC_FILE ($SHELL_NAME)"
        fi
    fi
}

# Automatically apply to both ~/.bashrc and ~/.zshrc if applicable
register_shell_config "$HOME/.bashrc" "bash"
register_shell_config "$HOME/.zshrc" "zsh"

# If running on macOS with default zsh, ensure profile fallback
if [ "$(uname)" = "Darwin" ]; then
    register_shell_config "$HOME/.zprofile" "zsh-profile"
fi

# --- Step 5: Post-Install Verification & Terminal Integration ---
echo "[5/5] Testing environment state..."

# Source into current running subshell for immediate execution test
export PATH="$TARGET_DIR/bin:$PATH"
alias ulpx-test="python3 $TARGET_DIR/scripts/audit.py"

if [ -f "$TARGET_DIR/scripts/audit.py" ]; then
    echo "  ✔ Engine core successfully verified."
else
    echo "  ✘ Warning: audit script missing from engine target."
fi

echo "======================================================="
echo "  ULPF-X Installation Complete!"
echo "======================================================="
echo "  To activate in your current session, run:"
if [ -n "$ZSH_VERSION" ] || [ -f "$HOME/.zshrc" ]; then
    echo "    source ~/.zshrc"
else
    echo "    source ~/.bashrc"
fi
echo "  Then run 'ulpx-test' to execute system diagnostics."
echo "======================================================="
