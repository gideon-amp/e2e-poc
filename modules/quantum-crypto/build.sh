#!/bin/bash

# Build liboqs XCFramework from proper header structure
set -e

LIBOQS_DIR="~/liboqs-main"  # Update this path to cloned liboqs-main folder, i.e /Users/${USER}/Downloads/liboqs-main
PROJECT_ROOT="$(pwd)"
OUTPUT_DIR="$PROJECT_ROOT/modules/quantum-crypto/ios"

echo "🔨 Building liboqs.xcframework with proper headers from git clone..."

cd "$LIBOQS_DIR"

# Clean any previous iOS builds
rm -rf build-ios-device build-ios-simulator liboqs.xcframework

# Build for iOS Device (ARM64)
echo "📱 Building for iOS Device (ARM64)..."
cmake -B build-ios-device \
  -GNinja \
  -DCMAKE_SYSTEM_NAME=iOS \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=15.0 \
  -DCMAKE_OSX_ARCHITECTURES=arm64 \
  -DCMAKE_BUILD_TYPE=Release \
  -DOQS_BUILD_ONLY_LIB=ON \
  -DOQS_MINIMAL_BUILD="KEM_kyber_768;SIG_dilithium_3" \
  -DOQS_USE_OPENSSL=OFF \
  -DOQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON \
  -DCMAKE_C_COMPILER=$(xcrun --find clang) \
  -DCMAKE_CXX_COMPILER=$(xcrun --find clang++) \
  -DCMAKE_OSX_SYSROOT=$(xcrun --sdk iphoneos --show-sdk-path) \
  .

ninja -C build-ios-device

# Build for iOS Simulator (x86_64 + ARM64)
echo "🖥️  Building for iOS Simulator..."
cmake -B build-ios-simulator \
  -GNinja \
  -DCMAKE_SYSTEM_NAME=iOS \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=15.0 \
  -DCMAKE_OSX_ARCHITECTURES="x86_64;arm64" \
  -DCMAKE_BUILD_TYPE=Release \
  -DOQS_BUILD_ONLY_LIB=ON \
  -DOQS_MINIMAL_BUILD="KEM_kyber_768;SIG_dilithium_3" \
  -DOQS_USE_OPENSSL=OFF \
  -DOQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON \
  -DCMAKE_C_COMPILER=$(xcrun --find clang) \
  -DCMAKE_CXX_COMPILER=$(xcrun --find clang++) \
  -DCMAKE_OSX_SYSROOT=$(xcrun --sdk iphonesimulator --show-sdk-path) \
  .

ninja -C build-ios-simulator

# Verify libraries exist
if [ ! -f "build-ios-device/lib/liboqs.a" ]; then
    echo "❌ iOS device library not found"
    exit 1
fi

if [ ! -f "build-ios-simulator/lib/liboqs.a" ]; then
    echo "❌ iOS simulator library not found"
    exit 1
fi

echo "✅ Both iOS libraries built successfully!"

# Check architectures
echo "📋 Checking architectures..."
echo "Device library:"
lipo -info build-ios-device/lib/liboqs.a

echo "Simulator library:"
lipo -info build-ios-simulator/lib/liboqs.a

# Use the proper include directory with oqs/ subdirectory
echo "📄 Using headers from build/include (with proper oqs/ structure)..."

# Verify the header structure exists
if [ ! -d "build/include/oqs" ]; then
    echo "❌ Headers not found in build/include/oqs"
    echo "Please run the initial build first:"
    echo "mkdir build && cd build && cmake -GNinja .. && ninja"
    exit 1
fi

echo "📋 Available headers in build/include/oqs/:"
ls -la build/include/oqs/ | head -10

# Create XCFramework using the proper include directory
echo "📦 Creating XCFramework with proper header structure..."
xcodebuild -create-xcframework \
  -library build-ios-device/lib/liboqs.a \
  -headers build/include \
  -library build-ios-simulator/lib/liboqs.a \
  -headers build/include \
  -output liboqs.xcframework \
  -allow-internal-distribution

# Verify XCFramework was created successfully
if [ ! -d "liboqs.xcframework" ]; then
    echo "❌ XCFramework creation failed"
    exit 1
fi

echo "✅ XCFramework created successfully!"

# Verify the header structure in the XCFramework
echo "📋 Verifying XCFramework header structure..."

# Check that headers are in the oqs subdirectory
if [ -f "liboqs.xcframework/ios-arm64/Headers/oqs/oqs.h" ]; then
    echo "✅ Headers properly placed in oqs/ subdirectory"
else
    echo "❌ Headers not in expected oqs/ subdirectory"
    echo "📁 Current structure:"
    find liboqs.xcframework -name "*.h" | head -5
fi

# Essential headers
essential_headers=("oqs.h" "common.h" "kem_kyber.h" "sig_dilithium.h" "aes.h" "sha2.h" "sha3.h" "rand.h")
echo ""
echo "📋 Checking for essential headers:"
for header in "${essential_headers[@]}"; do
    if [ -f "liboqs.xcframework/ios-arm64/Headers/oqs/$header" ]; then
        echo "✅ $header"
    else
        echo "❌ $header (missing)"
    fi
done

# Total header count
header_count=$(find liboqs.xcframework -name "*.h" | wc -l)
echo ""
echo "📊 Total headers in XCFramework: $header_count"

# Copy to project
echo ""
echo "📁 Copying to project..."
mkdir -p "$OUTPUT_DIR"
rm -rf "$OUTPUT_DIR/liboqs.xcframework"
cp -r liboqs.xcframework "$OUTPUT_DIR/"

echo ""
echo "🎉 liboqs.xcframework built and installed successfully!"
echo "📍 Location: $OUTPUT_DIR/liboqs.xcframework"
echo "📋 Header structure: Headers/oqs/*.h ✅"
echo ""
echo "🚀 Next steps:"
echo "1. cd $PROJECT_ROOT"
echo "2. rm -rf ios/ node_modules/"
echo "3. npm install"
echo "4. npx expo prebuild --clean"
echo "5. npx expo run:ios"