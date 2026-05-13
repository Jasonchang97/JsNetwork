#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
QT_DIR="/Users/test/code/debug/xwares/vcpkg_install_arm64/qt5/build_arm64/qtbase"
OPENSSL_DIR="/Users/test/code/debug/xwares/vcpkg_install_arm64/default/arm64-osx-dynamic"
APP_NAME="JsNetwork"
VERSION="1.0.1"

echo "=== Building JsNetwork DMG ==="

# Step 1: Build
echo "[1/5] Building..."
cd "$BUILD_DIR"
cmake .. -DBUILD_TESTS=OFF -DCMAKE_BUILD_TYPE=Release 2>&1 | tail -3
cmake --build . -j$(sysctl -n hw.ncpu) 2>&1 | tail -3

# Step 2: Prepare clean .app bundle
echo "[2/5] Preparing .app bundle..."
APP_BUNDLE="$BUILD_DIR/$APP_NAME.app"

# The post-build step creates:
#   JsNetwork.app/Contents/MacOS/JsNetwork      (launcher script)
#   JsNetwork.app/Contents/MacOS/JsNetwork.bin   (real binary)
# For distribution, replace the launcher with the real binary
cp "$APP_BUNDLE/Contents/MacOS/$APP_NAME.bin" "$APP_BUNDLE/Contents/MacOS/$APP_NAME"
chmod +x "$APP_BUNDLE/Contents/MacOS/$APP_NAME"

# Step 3: Bundle Qt frameworks
echo "[3/5] Bundling Qt frameworks..."
"$QT_DIR/bin/macdeployqt" "$APP_BUNDLE" -verbose=1 2>&1 | grep -E "^(ERROR|WARNING|Processing)" | head -20

# Step 4: Copy OpenSSL libraries
echo "[4/5] Copying OpenSSL libraries..."
mkdir -p "$APP_BUNDLE/Contents/Frameworks"
cp "$OPENSSL_DIR/lib/libssl.1.1.dylib" "$APP_BUNDLE/Contents/Frameworks/" 2>/dev/null || true
cp "$OPENSSL_DIR/lib/libcrypto.1.1.dylib" "$APP_BUNDLE/Contents/Frameworks/" 2>/dev/null || true

# Fix rpath for OpenSSL
install_name_tool -change \
    "$OPENSSL_DIR/lib/libssl.1.1.dylib" \
    "@executable_path/../Frameworks/libssl.1.1.dylib" \
    "$APP_BUNDLE/Contents/MacOS/$APP_NAME" 2>/dev/null || true
install_name_tool -change \
    "$OPENSSL_DIR/lib/libcrypto.1.1.dylib" \
    "@executable_path/../Frameworks/libcrypto.1.1.dylib" \
    "$APP_BUNDLE/Contents/MacOS/$APP_NAME" 2>/dev/null || true

# Step 5: Ad-hoc code signing (fixes invalid framework signatures from macdeployqt)
echo "[5/6] Code signing..."
codesign --force --deep --sign - "$APP_BUNDLE" 2>&1

# Step 6: Create DMG with Applications symlink
echo "[6/6] Creating DMG..."
DMG_NAME="$APP_NAME-$VERSION-macOS.dmg"
rm -f "$BUILD_DIR/$DMG_NAME"

# Create temp directory with app + Applications symlink
DMG_TEMP="$BUILD_DIR/_dmg_temp"
rm -rf "$DMG_TEMP"
mkdir -p "$DMG_TEMP"
cp -R "$APP_BUNDLE" "$DMG_TEMP/"
ln -s /Applications "$DMG_TEMP/Applications"

hdiutil create -volname "$APP_NAME" \
    -srcfolder "$DMG_TEMP" \
    -ov -format UDZO \
    "$BUILD_DIR/$DMG_NAME" 2>&1

rm -rf "$DMG_TEMP"

echo ""
echo "=== Done ==="
echo "DMG: $BUILD_DIR/$DMG_NAME"
ls -lh "$BUILD_DIR/$DMG_NAME"
