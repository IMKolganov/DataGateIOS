#!/bin/bash
# Script to update mbedTLS to latest version for iOS

set -e

# Project root = directory where this script lives
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${SCRIPT_DIR}"
LIBS_DIR="${PROJECT_DIR}/DataGateVPNExtension/libs"
TEMP_DIR="/tmp/mbedtls_build_$$"

echo "🔧 Updating mbedTLS for iOS..."
echo "Current version: 2.28.10"
echo "Target version: 3.6.5 (LTS)"

# Cleanup on exit
trap "rm -rf ${TEMP_DIR}" EXIT

# Create temp directory
mkdir -p ${TEMP_DIR}
cd ${TEMP_DIR}

# Clone mbedTLS 3.6.x (LTS)
echo "📥 Cloning mbedTLS 3.6.5..."
git clone --depth 1 --branch mbedtls-3.6.5 https://github.com/Mbed-TLS/mbedtls.git
cd mbedtls

# Initialize submodules
echo "📦 Initializing submodules..."
git submodule update --init --recursive

# Set iOS SDK paths
export IOS_SDK=$(xcrun --sdk iphoneos --show-sdk-path)
export IOS_CC=$(xcrun --sdk iphoneos --find clang)
export IOS_CXX=$(xcrun --sdk iphoneos --find clang++)
export IOS_CFLAGS="-arch arm64 -isysroot ${IOS_SDK} -miphoneos-version-min=17.0 -fembed-bitcode"
export IOS_CXXFLAGS="${IOS_CFLAGS}"

echo "🔨 Building mbedTLS for iOS arm64 using CMake..."

# Create build directory
mkdir -p build-ios
cd build-ios

# Configure with CMake for iOS
cmake .. \
    -DCMAKE_SYSTEM_NAME=iOS \
    -DCMAKE_OSX_ARCHITECTURES=arm64 \
    -DCMAKE_OSX_DEPLOYMENT_TARGET=17.0 \
    -DCMAKE_C_COMPILER="${IOS_CC}" \
    -DCMAKE_CXX_COMPILER="${IOS_CXX}" \
    -DCMAKE_C_FLAGS="${IOS_CFLAGS}" \
    -DCMAKE_CXX_FLAGS="${IOS_CXXFLAGS}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DENABLE_TESTING=OFF \
    -DENABLE_PROGRAMS=OFF

# Build libraries
cmake --build . --target mbedtls mbedx509 mbedcrypto

# Libraries will be in library/ directory
cd ..

# Verify libraries were built
if [ ! -f "build-ios/library/libmbedtls.a" ] || [ ! -f "build-ios/library/libmbedx509.a" ] || [ ! -f "build-ios/library/libmbedcrypto.a" ]; then
    echo "❌ Error: Libraries were not built successfully"
    exit 1
fi

# Backup old libraries
echo "💾 Backing up old libraries..."
mkdir -p "${LIBS_DIR}/backup_$(date +%Y%m%d_%H%M%S)"
cp "${LIBS_DIR}/libmbedtls.a" "${LIBS_DIR}/backup_$(date +%Y%m%d_%H%M%S)/" 2>/dev/null || true
cp "${LIBS_DIR}/libmbedx509.a" "${LIBS_DIR}/backup_$(date +%Y%m%d_%H%M%S)/" 2>/dev/null || true
cp "${LIBS_DIR}/libmbedcrypto.a" "${LIBS_DIR}/backup_$(date +%Y%m%d_%H%M%S)/" 2>/dev/null || true

# Copy new libraries
echo "📦 Copying new libraries..."
cp build-ios/library/libmbedtls.a "${LIBS_DIR}/"
cp build-ios/library/libmbedx509.a "${LIBS_DIR}/"
cp build-ios/library/libmbedcrypto.a "${LIBS_DIR}/"

# Copy headers (update include directory)
echo "📋 Updating headers..."
mkdir -p "${PROJECT_DIR}/DataGateVPNExtension/mbedtls-include"
cp -r include/mbedtls/* "${PROJECT_DIR}/DataGateVPNExtension/mbedtls-include/mbedtls/"

echo "✅ mbedTLS updated successfully!"
echo "📝 Next steps:"
echo "   1. Update Xcode project to use new libraries"
echo "   2. Check for API compatibility issues"
echo "   3. Rebuild the project"
