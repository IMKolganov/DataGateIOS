#!/bin/bash

# Script to add warning suppression flags to DataGateVPNExtension target
# This suppresses warnings from external libraries (mbedtls, asio, openvpn3)

PROJECT_FILE="./DataGateIOS.xcodeproj/project.pbxproj"

if [ ! -f "$PROJECT_FILE" ]; then
    echo "Error: project.pbxproj not found at $PROJECT_FILE"
    exit 1
fi

# Backup project file
cp "$PROJECT_FILE" "${PROJECT_FILE}.backup"

# Flags to add
C_FLAGS="-Wno-documentation -Wno-documentation-deprecated-sync -Wno-deprecated-declarations -Wno-shorten-64-to-32 -Wno-macro-redefined"
CPP_FLAGS="-Wno-documentation -Wno-documentation-deprecated-sync -Wno-deprecated-declarations -Wno-shorten-64-to-32 -Wno-macro-redefined"

# Check if flags already exist
if grep -q "Wno-documentation" "$PROJECT_FILE"; then
    echo "Warning flags already exist in project.pbxproj"
    echo "Please check Build Settings manually or remove existing flags first"
    exit 0
fi

echo "Adding warning suppression flags to project.pbxproj..."
echo "This script modifies the project file. Make sure you have a backup!"

# Note: Direct modification of .pbxproj is complex and error-prone
# It's better to do it manually through Xcode UI (see SUPPRESS_WARNINGS.md)
echo ""
echo "⚠️  WARNING: Automatic modification of .pbxproj is risky!"
echo "Please use Xcode UI instead (see SUPPRESS_WARNINGS.md for instructions)"
echo ""
echo "To add flags manually:"
echo "1. Open Xcode"
echo "2. Select DataGateVPNExtension target"
echo "3. Build Settings → Other C Flags → Add: $C_FLAGS"
echo "4. Build Settings → Other C++ Flags → Add: $CPP_FLAGS"
echo "5. Clean Build Folder (Cmd+Shift+K)"
echo "6. Build (Cmd+B)"

exit 0
