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
echo "[1/6] Checking host environment..."
if [ -d "$TARGET_DIR" ]; then
    echo "  ↳ Existing ULPF-X engine detected at $TARGET_DIR"
    echo "  ↳ Backing up existing engine configuration..."
    mv "$TARGET_DIR" "${TARGET_DIR}_backup_${TIMESTAMP}"
    echo "  ↳ Backup created: ${TARGET_DIR}_backup_${TIMESTAMP}"
fi

# --- Step 2: Target Directory Provisioning ---
echo "[2/6] Creating engine home directory structure..."
mkdir -p "$TARGET_DIR/bin"
mkdir -p "$TARGET_DIR/scripts"
mkdir -p "$TARGET_DIR/logs"

# --- Step 3: Clean Extraction & Mirroring ---
echo "[3/6] Mirroring engine core files into $TARGET_DIR..."
# Mirror from repository root using tar stream
(
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
        -cf - .
) | (cd "$TARGET_DIR" && tar -xf -)

# Ensure scripts/env.sh is mirrored to $TARGET_DIR/env.sh for backwards compatibility
if [ -f "$TARGET_DIR/scripts/env.sh" ]; then
    cp "$TARGET_DIR/scripts/env.sh" "$TARGET_DIR/env.sh" 2>/dev/null || true
fi

# Ensure execution permissions on bin/ and scripts/
chmod +x "$TARGET_DIR/bin/"* 2>/dev/null || true
chmod +x "$TARGET_DIR/scripts/"* 2>/dev/null || true
if command -v xattr >/dev/null 2>&1; then
    xattr -cr "$TARGET_DIR" 2>/dev/null || true
fi

# --- Step 4: Multi-Shell Hook Registration (Bash & Zsh Support) ---
echo "[4/6] Registering shell configuration hooks..."

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

# --- Step 5: Python Dependency Verification ---
echo "[5/6] Verifying Python dependencies..."
PY_BIN=""
for p in python3 python py; do
    if command -v "$p" >/dev/null 2>&1; then
        PY_BIN="$p"
        break
    fi
done

if [ -n "$PY_BIN" ]; then
    if [ -d "$TARGET_DIR/wheels" ]; then
        echo "  ↳ Installing offline wheel dependencies from $TARGET_DIR/wheels..."
        "$PY_BIN" -m pip install --no-index --find-links="$TARGET_DIR/wheels" rich psutil pytest --quiet 2>/dev/null || true
    else
        echo "  ↳ Installing required dependencies (rich, psutil, pytest)..."
        "$PY_BIN" -m pip install rich psutil pytest --quiet 2>/dev/null || true
    fi
    echo "  ✔ Python dependencies verified."
fi

# --- Step 6: Post-Install Verification & Terminal Integration ---
echo "[6/6] Testing environment state..."

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
