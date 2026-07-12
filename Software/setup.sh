#!/bin/bash
# Setup and testing script for RDRS Filesystem Monitor
# This script demonstrates virtual environment creation and system testing

echo "=========================================="
echo "RDRS Filesystem Monitor - Setup Guide"
echo "=========================================="
echo ""

# Detect OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macOS"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="Linux"
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
    OS="Windows"
else
    OS="Unknown"
fi

echo "Detected OS: $OS"
echo ""

# Create virtual environment
echo "Step 1: Creating Python virtual environment..."
if [ -d "rdrs" ]; then
    echo "Virtual environment already exists at './rdrs'"
else
    python3 -m venv rdrs
    echo "✓ Virtual environment created at './rdrs'"
fi
echo ""

# Activate virtual environment
echo "Step 2: Activating virtual environment..."
if [[ "$OS" == "Windows" ]]; then
    echo "On Windows PowerShell, run: .\rdrs\Scripts\Activate.ps1"
    echo "On Windows cmd.exe, run: rdrs\Scripts\activate.bat"
else
    source rdrs/bin/activate
    echo "✓ Virtual environment activated"
fi
echo ""

# Upgrade pip
echo "Step 3: Upgrading pip..."
pip install --upgrade pip > /dev/null 2>&1
echo "✓ pip upgraded"
echo ""

# Install dependencies
echo "Step 4: Installing dependencies from requirements.txt..."
pip install -r requirements.txt > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "✓ Dependencies installed successfully"
else
    echo "✗ Failed to install dependencies"
    exit 1
fi
echo ""

# Verify installation
echo "Step 5: Verifying installation..."
python3 -c "import watchdog; print(f'✓ watchdog {watchdog.__version__}')" 2>/dev/null
python3 -c "import psutil; print(f'✓ psutil {psutil.__version__}')" 2>/dev/null
echo ""

# Show usage information
echo "=========================================="
echo "Installation Complete!"
echo "=========================================="
echo ""
echo "To start monitoring:"
echo "  python main.py --path /path/to/watch --recursive"
echo ""
echo "To stop monitoring:"
echo "  Press Ctrl+C"
echo ""
echo "For more information, see README.md"
echo ""
