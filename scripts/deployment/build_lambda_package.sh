#!/bin/bash
set -e

# This script prepares the AWS Lambda deployment package.

PACKAGE_DIR="build/lambda"
OUTPUT_ZIP="deployment_package.zip"

echo "📦 Creating Lambda deployment package..."

# 1. Clean up previous builds
rm -rf build
mkdir -p "$PACKAGE_DIR"

# 2. Copy source code and configuration
echo "Copying source code and configs..."
cp -r src/ "$PACKAGE_DIR/"
cp -r config/ "$PACKAGE_DIR/"

# 3. Install Python dependencies
echo "Installing dependencies..."
pip install -r requirements.txt --target "$PACKAGE_DIR"

# 4. Create the ZIP file
echo "Creating ZIP file: $OUTPUT_ZIP"
cd "$PACKAGE_DIR"
zip -r ../../"$OUTPUT_ZIP" . > /dev/null
cd ../../

# 5. Clean up the build directory
rm -rf "$PACKAGE_DIR"

echo "✅ Lambda package created successfully at $OUTPUT_ZIP"
