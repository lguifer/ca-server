#!/bin/bash

# Ensure script is run with sudo
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

# Update package list
echo "Updating package list..."
sudo apt-get update

# Install Python 3 and pip if not installed
echo "Installing Python 3 and pip..."
sudo apt-get install -y python3 python3-pip

# Install Flask
echo "Installing Flask..."
pip3 install Flask

# Install required Python packages
echo "Installing required Python packages..."
pip3 install cryptography pyOpenSSL configparser

# Verify installation
echo "Verifying installation..."
pip3 freeze | grep -E 'cryptography|OpenSSL|Flask|configparser'

echo "Installation complete."
