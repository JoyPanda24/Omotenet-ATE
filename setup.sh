#!/bin/bash

# Attack Thinking Engine (ATE) - Cross-Distro Setup Script
# Supports: Kali, Arch, BlackArch, Parrot OS

set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║     Attack Thinking Engine (ATE) - Setup Script            ║"
echo "║     Multi-Distro Setup for Kali, Arch, BlackArch, Parrot   ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Detect package manager
if command -v apt-get &> /dev/null; then
    echo "[*] Detected Debian-based distro (Kali/Parrot)"
    PKG_MANAGER="apt"
    PYTHON_PKG="python3-pip python3-venv python3-dev"
    GRAPHVIZ_PKG="graphviz graphviz-dev"
elif command -v pacman &> /dev/null; then
    echo "[*] Detected Arch-based distro (Arch/BlackArch)"
    PKG_MANAGER="pacman"
    PYTHON_PKG="python python-pip"
    GRAPHVIZ_PKG="graphviz"
else
    echo "[-] Unsupported package manager. Please install Python 3.13+ and graphviz manually."
    exit 1
fi

# Update package manager
echo "[*] Updating package manager..."
if [ "$PKG_MANAGER" == "apt" ]; then
    sudo apt-get update -qq
    sudo apt-get install -y $PYTHON_PKG $GRAPHVIZ_PKG build-essential
elif [ "$PKG_MANAGER" == "pacman" ]; then
    sudo pacman -Syu --noconfirm
    sudo pacman -S --noconfirm $PYTHON_PKG $GRAPHVIZ_PKG base-devel
fi

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)

echo "[+] Found Python $PYTHON_VERSION"

if [ $PYTHON_MAJOR -lt 3 ] || ([ $PYTHON_MAJOR -eq 3 ] && [ $PYTHON_MINOR -lt 10 ]); then
    echo "[-] Python 3.13+ is the validated target for this project. Current version: $PYTHON_VERSION"
    exit 1
fi

# Create virtual environment
echo "[*] Creating Python virtual environment..."
if [ -d "venv" ]; then
    echo "[*] Virtual environment already exists. Skipping..."
else
    python3 -m venv venv
fi

# Activate virtual environment
echo "[*] Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "[*] Upgrading pip..."
pip install --upgrade pip setuptools wheel -q

# Install dependencies
echo "[*] Installing Python dependencies from requirements.txt..."
pip install -r requirements.txt -q

# Verify installations
echo ""
echo "[*] Verifying installations..."
python3 -c "import networkx; print('[+] NetworkX:', networkx.__version__)"
python3 -c "import rich; print('[+] Rich:', rich.__version__)"
python3 -c "import fastapi; print('[+] FastAPI:', fastapi.__version__)"

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║           Setup Complete!                                  ║"
echo "║                                                            ║"
echo "║  Activate environment:  source venv/bin/activate           ║"
echo "║  Run ATE:               python -m ate.cli.main             ║"
echo "║  Run tests:             pytest tests/                      ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
