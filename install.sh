#!/usr/bin/env bash
set -e

INSTALL_DIR="$HOME/.ulpx"
echo "📦 Registering ULPF-X Engine globally at: $INSTALL_DIR"

# 1. Copy repository contents into central home directory
mkdir -p "$INSTALL_DIR"
cp -r . "$INSTALL_DIR"

# 2. Register with CMake User Package Registry (Offline Support)
CMAKE_REG_DIR="$HOME/.cmake/packages/ulpx"
mkdir -p "$CMAKE_REG_DIR"
echo "$INSTALL_DIR" > "$CMAKE_REG_DIR/ulpx-config"
echo "  ✓ Registered with CMake User Package Registry"

# 3. Create global CLI launchers in local bin directory
BIN_DIR="$HOME/.local/bin"
mkdir -p "$BIN_DIR"

if command -v python3 >/dev/null 2>&1; then
    PY_EXEC="$(command -v python3)"
elif command -v python >/dev/null 2>&1; then
    PY_EXEC="$(command -v python)"
else
    echo "Python 3 is required but was not found in PATH." >&2
    exit 1
fi

echo "Installing Python dependencies..."
if [ -f "$INSTALL_DIR/requirements.txt" ]; then
    "$PY_EXEC" -m pip install --quiet -r "$INSTALL_DIR/requirements.txt"
else
    "$PY_EXEC" -m pip install --quiet rich psutil
fi

cat << LAUNCHER > "$BIN_DIR/ulpx"
#!/usr/bin/env bash
exec "$PY_EXEC" "\$HOME/.ulpx/scripts/demo.py" "\$@"
LAUNCHER

cat << LAUNCHER > "$BIN_DIR/ulpx-test"
#!/usr/bin/env bash
exec "$PY_EXEC" "\$HOME/.ulpx/scripts/audit.py" "\$@"
LAUNCHER

chmod +x "$BIN_DIR/ulpx" "$BIN_DIR/ulpx-test"

# 4. Inject environment hooks into shell profile files
touch "$HOME/.bashrc" "$HOME/.bash_profile"

SHELL_HOOK="
# --- ULPF-X GLOBAL SYSTEM INTEGRATION ---
export ULPX_HOME=\"$INSTALL_DIR\"
export PATH=\"$HOME/.local/bin:\$PATH\"
# ----------------------------------------
"

for RC in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.bash_profile"; do
    if [ -f "$RC" ]; then
        if ! grep -q "ULPX_HOME" "$RC"; then
            echo "$SHELL_HOOK" >> "$RC"
            echo "  ✓ Injected persistent hook into $RC"
        fi
    fi
done

echo ""
echo "✅ ULPF-X is active across all terminals and CMake contexts!"
echo "👉 Run 'ulpx' from ANY terminal to launch the interactive dashboard."
echo "👉 Run 'ulpx-test' from ANY terminal to execute the continuous audit engine."
