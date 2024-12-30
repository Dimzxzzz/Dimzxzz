#!/bin/bash
set -e

echo "[INFO] Starting installation process..."

detect_terminal() {
    if [ -n "$TERMUX_VERSION" ]; then
        echo "termux"
    elif [ "$(uname)" == "Linux" ]; then
        if [ -f "/etc/debian_version" ]; then
            echo "debian"
        elif [ -f "/etc/redhat-release" ]; then
            echo "redhat"
        else
            echo "unknown-linux"
        fi
    elif [ "$(uname)" == "Darwin" ]; then
        echo "macos"
    else
        echo "unknown"
    fi
}

install_python_termux() {
    pkg update -y && pkg install python -y
    if ! command -v pip3 &> /dev/null; then
        echo "[INFO] Installing pip3..."
        python3 -m ensurepip
    fi
}

install_python_linux() {
    sudo apt update -y && sudo apt install python3 python3-pip -y || {
        echo "[INFO] Trying alternative methods..."
        sudo apt-get install python3 python3-pip -y || sudo yum install python3 python3-pip -y
    }
}

install_python_macos() {
    if ! command -v brew &> /dev/null; then
        echo "[ERROR] Homebrew is not installed. Please install Homebrew first."
        exit 1
    fi
    brew install python3
}

install_dependencies() {
    echo "[INFO] Installing Python dependencies..."
    pip3 install -r requirements.txt || {
        echo "[ERROR] pip installation failed. Retrying with alternative methods..."
        python3 -m pip install --upgrade pip
        python3 -m pip install -r requirements.txt
    }
}

terminal=$(detect_terminal)
echo "[INFO] Detected terminal: $terminal"

if [ "$terminal" == "termux" ]; then
    install_python_termux
elif [ "$terminal" == "debian" ] || [ "$terminal" == "redhat" ]; then
    install_python_linux
elif [ "$terminal" == "macos" ]; then
    install_python_macos
else
    echo "[ERROR] Unsupported terminal. Exiting."
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python3 could not be installed. Please install it manually."
    exit 1
fi

if ! command -v pip3 &> /dev/null; then
    echo "[ERROR] pip3 could not be installed. Please install it manually."
    exit 1
fi

install_dependencies
echo "[INFO] Installation completed successfully."
