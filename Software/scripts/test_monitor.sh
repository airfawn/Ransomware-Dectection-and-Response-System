#!/bin/bash
# Test script for RDRS Filesystem Monitor
# This script demonstrates the monitor working with actual file operations

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOFTWARE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$SOFTWARE_DIR" || exit 1

echo "=========================================="
echo "RDRS Filesystem Monitor - Live Test"
echo "=========================================="
echo ""

# Get the Python path from the virtual environment if available
PYTHON="$SOFTWARE_DIR/rdrs/bin/python"
if [ ! -x "$PYTHON" ]; then
    PYTHON="python3"
fi
MONITOR_DIR="/tmp/rdrs_test_$$"

# Create test directory
mkdir -p "$MONITOR_DIR"
echo "✓ Created test directory: $MONITOR_DIR"
echo ""

# Start monitor in background
echo "Starting monitor in background..."
"$PYTHON" "$SOFTWARE_DIR/main.py" --path "$MONITOR_DIR" &
MONITOR_PID=$!
echo "✓ Monitor started (PID: $MONITOR_PID)"
echo ""

# Wait for monitor to initialize
sleep 2

# Create test file
echo "Creating test file..."
echo "This is a test file" > "$MONITOR_DIR/test_file.txt"
echo "✓ File created"
sleep 1

# Delete test file
echo "Deleting test file..."
rm "$MONITOR_DIR/test_file.txt"
echo "✓ File deleted"
sleep 1

# Create another file
echo "Creating another test file..."
echo "Another test" > "$MONITOR_DIR/test2.txt"
sleep 1

# Stop monitor
echo ""
echo "Stopping monitor..."
kill "$MONITOR_PID" 2>/dev/null
wait "$MONITOR_PID" 2>/dev/null
echo "✓ Monitor stopped"
echo ""

# Cleanup
rm -rf "$MONITOR_DIR"
echo "✓ Test directory cleaned up"
echo ""
echo "=========================================="
echo "Test Complete!"
echo "=========================================="
