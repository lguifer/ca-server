# Ensure running as Administrator
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Warning "You do not have Administrator rights to run this script.`nPlease re-run this script as an Administrator."
    exit
}

# Install Python 3 if not installed
Write-Host "Checking if Python 3 is installed..."
if (-Not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "Installing Python 3..."
    Start-Process "msiexec.exe" -ArgumentList "/i https://www.python.org/ftp/python/3.10.0/python-3.10.0-amd64.exe /quiet InstallAllUsers=1 PrependPath=1" -Wait
}

# Upgrade pip
Write-Host "Upgrading pip..."
python -m ensurepip --upgrade
python -m pip install --upgrade pip

# Install required Python packages
Write-Host "Installing required Python packages..."
pip install cryptography pyOpenSSL Flask

# Verify installation
Write-Host "Verifying installation..."
pip freeze | Select-String -Pattern "cryptography|OpenSSL|Flask"

Write-Host "Installation complete."
