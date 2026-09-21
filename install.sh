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

# 3. Dynamic Python Discovery (Prioritize Native Windows Python over MSYS2)
PY_EXEC=""

# Search common Windows Python installation paths
POSSIBLE_PYTHONS=(
    "$LOCALAPPDATA/Programs/Python/Python310/python.exe"
    "$LOCALAPPDATA/Programs/Python/Python311/python.exe"
    "$LOCALAPPDATA/Programs/Python/Python312/python.exe"
    "/c/Users/$USER/AppData/Local/Programs/Python/Python310/python.exe"
    "/c/Users/$USER/AppData/Local/Programs/Python/Python311/python.exe"
    "/c/Users/$USER/AppData/Local/Programs/Python/Python312/python.exe"
)

for py_candidate in "${POSSIBLE_PYTHONS[@]}"; do
    if [ -f "$py_candidate" ]; then
        PY_EXEC="$py_candidate"
        break
    fi
done

# Fallback to system PATH binaries if explicit path isn't found
if [ -z "$PY_EXEC" ]; then
    if command -v python >/dev/null 2>&1 && python -c "import sys; print(sys.prefix)" 2>/dev/null | grep -vq "msys"; then
        PY_EXEC="$(command -v python)"
    elif command -v python3 >/dev/null 2>&1 && python3 -c "import sys; print(sys.prefix)" 2>/dev/null | grep -vq "msys"; then
        PY_EXEC="$(command -v python3)"
    else
        PY_EXEC="$(command -v python 2>/dev/null || command -v python3 2>/dev/null)"
    fi
fi

if [ -z "$PY_EXEC" ]; then
    echo "❌ Error: Python 3 was not found on system." >&2
    exit 1
fi

echo "  • Selected Python Runtime: $PY_EXEC"

# Ensure pip is bootstrapped if missing
"$PY_EXEC" -m ensurepip --default-pip >/dev/null 2>&1 || true

# 4. Install required Python dependencies
echo "Installing Python dependencies..."
if [ -f "$INSTALL_DIR/requirements.txt" ]; then
    "$PY_EXEC" -m pip install --quiet -r "$INSTALL_DIR/requirements.txt" || "$PY_EXEC" -m pip install --quiet rich psutil pytest
else
    "$PY_EXEC" -m pip install --quiet rich psutil pytest
fi

# 5. Create global CLI launchers in local bin directory
BIN_DIR="$HOME/.local/bin"
mkdir -p "$BIN_DIR"

cat << LAUNCHER > "$BIN_DIR/ulpx"
#!/usr/bin/env bash
export ULPX_HOME="$INSTALL_DIR"
cd "$INSTALL_DIR" && "$PY_EXEC" "$INSTALL_DIR/scripts/demo.py" "\$@"
LAUNCHER

cat << LAUNCHER > "$BIN_DIR/ulpx-test"
#!/usr/bin/env bash
export ULPX_HOME="$INSTALL_DIR"
cd "$INSTALL_DIR" && "$PY_EXEC" "$INSTALL_DIR/scripts/audit.py" "\$@"
LAUNCHER

chmod +x "$BIN_DIR/ulpx" "$BIN_DIR/ulpx-test"

# 6. Inject environment hooks into shell profile files
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