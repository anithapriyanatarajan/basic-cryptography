#!/bin/bash

# Build script for Basic Cryptography Demo Application

echo "🔨 Building Basic Cryptography Demo Application..."

# Create build directory
mkdir -p build

# Compile all Java files
echo "📦 Compiling Java source files..."
javac -d build src/main/java/com/example/crypto/*.java

if [ $? -eq 0 ]; then
    echo "✅ Compilation successful!"
    echo ""
    echo "🚀 To run the interactive application:"
    echo "   cd build && java com.example.crypto.CryptographyApp"
    echo ""
    echo "🧪 To run the test suite:"
    echo "   cd build && java com.example.crypto.CryptographyTest"
    echo ""
    echo "📚 To see security demonstrations:"
    echo "   cd build && java com.example.crypto.CryptographyDemo"
else
    echo "❌ Compilation failed!"
    exit 1
fi
