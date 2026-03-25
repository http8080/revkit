#!/bin/bash
# build.sh — JEB Java server build (Phase 0.5)
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
JEB_HOME="${JEB_HOME:-/home/http80/JEB-5.38}"
SRC_DIR="$SCRIPT_DIR/src"
BUILD_DIR="$SCRIPT_DIR/build"
OUT_JAR="$SCRIPT_DIR/revkit-jeb-server.jar"

# json-simple is bundled with JEB
CP="$JEB_HOME/bin/app/*"

if [ ! -d "$JEB_HOME/bin/app" ]; then
    echo "ERROR: JEB_HOME not found at $JEB_HOME"
    echo "Set JEB_HOME environment variable to your JEB installation directory."
    exit 1
fi

echo "Building JEB Java server..."
echo "  JEB_HOME: $JEB_HOME"
echo "  Source:   $SRC_DIR"
echo "  Output:   $OUT_JAR"

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/classes"

# Collect source files
find "$SRC_DIR" -name "*.java" > "$BUILD_DIR/sources.txt"
echo "  Sources:  $(wc -l < "$BUILD_DIR/sources.txt") files"

# Compile
javac -cp "$CP" \
    -d "$BUILD_DIR/classes" \
    -source 11 -target 11 \
    -encoding UTF-8 \
    @"$BUILD_DIR/sources.txt"

# Package
jar cfe "$OUT_JAR" revkit.server.JebRpcServer -C "$BUILD_DIR/classes" .

echo "Built: $OUT_JAR ($(du -h "$OUT_JAR" | cut -f1))"
