#!/bin/sh
# Install or update claude-bridge as a launchd agent on the bridge Mac. Idempotent.
# Run from the repo checkout:  sh deploy/install.sh
set -eu
REPO="$(cd "$(dirname "$0")/.." && pwd)"
LABEL=ai.claude-bridge
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
CONFIG="$HOME/.config/claude-bridge/config.json"
PY=/opt/homebrew/bin/python3

mkdir -p "$HOME/.claude-bridge" "$(dirname "$CONFIG")"
chmod 700 "$HOME/.claude-bridge"
if [ ! -f "$CONFIG" ]; then
  cp "$REPO/config.example.json" "$CONFIG"
  echo "Created $CONFIG from the example; review it."
fi
chmod 600 "$CONFIG"

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$PY</string>
    <string>$REPO/bridge.py</string>
    <string>--config</string>
    <string>$CONFIG</string>
    <string>serve</string>
  </array>
  <key>WorkingDirectory</key><string>$HOME/.claude-bridge</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key><string>$HOME/.local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    <key>HOME</key><string>$HOME</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>StandardOutPath</key><string>$HOME/.claude-bridge/server.log</string>
  <key>StandardErrorPath</key><string>$HOME/.claude-bridge/server.log</string>
</dict>
</plist>
EOF

launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"
echo "Loaded $LABEL. Log: ~/.claude-bridge/server.log"
