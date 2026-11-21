#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
SWIFT_DIR="$ROOT_DIR/macos/GridShieldApp"
DIST_DIR="$ROOT_DIR/dist"
APP_BUNDLE="$DIST_DIR/GridShieldVPN.app"

mkdir -p "$DIST_DIR"

if [ ! -x "$DIST_DIR/gridshield" ]; then
  echo "==> Building Go VPN core binary..."
  (cd "$ROOT_DIR" && go build -ldflags="-s -w" -o "$DIST_DIR/gridshield" ./cmd/gridshield)
fi

echo "==> Building Native SwiftUI macOS App (release)..."
(cd "$SWIFT_DIR" && swift build -c release)
SWIFT_BIN="$SWIFT_DIR/.build/release/GridShieldApp"

echo "==> Packaging $APP_BUNDLE..."
rm -rf "$APP_BUNDLE"
mkdir -p "$APP_BUNDLE/Contents/MacOS" "$APP_BUNDLE/Contents/Resources"

cp "$SWIFT_BIN" "$APP_BUNDLE/Contents/MacOS/GridShieldApp"
cp "$DIST_DIR/gridshield" "$APP_BUNDLE/Contents/Resources/gridshield"
chmod +x "$APP_BUNDLE/Contents/MacOS/GridShieldApp" "$APP_BUNDLE/Contents/Resources/gridshield"

cat > "$APP_BUNDLE/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleExecutable</key>
  <string>GridShieldApp</string>
  <key>CFBundleIdentifier</key>
  <string>dev.gridshield.vpn</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>GridShield VPN</string>
  <key>CFBundleDisplayName</key>
  <string>GridShield VPN</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>1.0.0</string>
  <key>CFBundleVersion</key>
  <string>1</string>
  <key>LSMinimumSystemVersion</key>
  <string>14.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>NSAppTransportSecurity</key>
  <dict>
    <key>NSAllowsLocalNetworking</key>
    <true/>
  </dict>
</dict>
</plist>
PLIST

# Ad-hoc sign so macOS Gatekeeper allows running locally built bundle cleanly
codesign --force --deep --sign - "$APP_BUNDLE" >/dev/null 2>&1 || true

echo "==> Built native macOS app bundle: $APP_BUNDLE"
ls -lh "$APP_BUNDLE/Contents/MacOS/GridShieldApp" "$APP_BUNDLE/Contents/Resources/gridshield"
