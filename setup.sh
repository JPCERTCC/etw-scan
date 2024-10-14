#!/bin/bash

# Usage:
# git clone https://github.com/JPCERTCC/etw-scan.git
# cd etw-scan
# chmod +x setup.sh
# ./setup.sh [--install] 

set -eu

INSTALL_VOL=false

while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --install)
            INSTALL_VOL=true
            shift
            ;;
        *)
            echo "Usage: $0 [--install]"
            exit 1
            ;;
    esac
done

download_volatility() {
    if [ -d volatility3 ]; then
        echo "[+] Already downloaded volatility3"
        echo "[+] Delete volatility3 directory"
        rm -rf volatility3
    fi
    echo "[+] Download volatility3"
    git clone https://github.com/volatilityfoundation/volatility3.git
    cd volatility3
    echo "[+] Install requirements"
    pip3 install -r requirements.txt
    cd ..
}

install_etwscan() {
    echo "[+] Install ETW Scanner"
    if [ ! -d plugins ]; then
        git clone https://github.com/JPCERTCC/etw-scan.git .
    fi
    cat patch/windows_init.patch >> volatility3/volatility3/framework/symbols/windows/__init__.py
    cat patch/extensions_init.patch >> volatility3/volatility3/framework/symbols/windows/extensions/__init__.py
}

install_volatility() {
    echo "[+] Install volatility"
    cd volatility3
    python setup.py install
    cd ..
}

help_etwscan() {
    echo
    echo "=== ETW Scanner ==="
    echo "Usage: python3 vol.py -f <memory image> -p etw-scan/plugins/  [etwscan.etwProvider|etwscan.etwConsumer]"
    echo "==================="
}

main() {
    echo "[+] Start setup"
    download_volatility
    install_etwscan
    if [ "$INSTALL_VOL" = true ]; then
        install_volatility
    else
        echo "[+] Skip install volatility"
        echo "[+] Install path: $(pwd)/volatility3"
    fi
    echo "[+] Finished"
    help_etwscan
}

main
