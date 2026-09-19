#!/usr/bin/env bash
#
# One-time setup so you can fire the kill switch "at will":
#   1. adds a  labstop  (and labstart) alias to your ~/.zshrc,
#   2. drops a double-clickable "Stop Lab.command" launcher on your Desktop.
#
# After running this, open a new terminal and just type:  labstop
# or double-click "Stop Lab" on the Desktop.
#
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STOP="$DIR/stop-all.sh"
START="$DIR/start-all.sh"
chmod +x "$STOP" "$START" 2>/dev/null || true

# 1. Aliases in ~/.zshrc (idempotent).
ZRC="$HOME/.zshrc"
touch "$ZRC"
if ! grep -q 'alias labstop=' "$ZRC"; then
  {
    echo ""
    echo "# Azure lab kill switch"
    echo "alias labstop='$STOP'"
    echo "alias labstart='$START'"
  } >> "$ZRC"
  echo "Added 'labstop' and 'labstart' aliases to $ZRC"
else
  echo "Aliases already present in $ZRC"
fi

# 2. Desktop double-click launcher.
LAUNCHER="$HOME/Desktop/Stop Lab.command"
cat > "$LAUNCHER" <<LAUNCH
#!/usr/bin/env bash
# Double-click kill switch for the Azure lab.
"$STOP"
echo ""
echo "Press any key to close..."
read -r -n 1
LAUNCH
chmod +x "$LAUNCHER"
echo "Created launcher: $LAUNCHER  (double-click it in Finder)"

echo ""
echo "Done. Use any of these to stop the lab instantly:"
echo "  labstop                 (new terminal, or run: source ~/.zshrc)"
echo "  double-click 'Stop Lab' on the Desktop"
echo "  $STOP"
echo "Bring it back with:  labstart"
