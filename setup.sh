#!/bin/bash

echo "[*] Installing 1Recon Dependencies..."


pip install -r requirements.txt

if ! command -v go &> /dev/null
then
    echo "[-] Go is not installed. Please install it first."
else
    echo "[+] Go is ready."
fi


chmod +x 1recon.py

echo "[+] Setup Complete! Use '.env' to add your API keys."
