
# CA Server Application

This is a Flask-based web application for managing a Certificate Authority (CA). The application allows you to generate a CA, sign certificates, list certificates, and revoke certificates, with support for TLS and mutual TLS (mTLS).

## Prerequisites

### Software Requirements
- **Python 3.x**: Make sure Python 3.x is installed.
- **Pip**: Python package installer.
- **Flask**: Web framework for Python.
- **Other Python Libraries**: cryptography, OpenSSL, configparser

## Installation

### Linux/macOS

1. Clone the repository and navigate to the project directory.
2. Run the provided `install_packages.sh` script to install all required dependencies.

```bash
chmod +x install_packages.sh
./install_packages.sh
```

### Windows

1. Clone the repository and navigate to the project directory.
2. Run the provided `install_packages.ps1` script to install all required dependencies. Make sure to run PowerShell as Administrator.

```powershell
.\install_packages.ps1
```

## Configuration

The configuration file `ca-server.conf` must contain the following fields:

- `ca_key_path`: Path to the CA private key.
- `ca_cert_path`: Path to the CA certificate.
- `use_tls`: Enable or disable TLS (True/False).
- `use_mtls`: Enable or disable mutual TLS (True/False).
- `web_cert_path`: Path to the server certificate.
- `web_key_path`: Path to the server private key.
- `ca_directory`: Directory for storing CA files.
- `crl_path`: Path for the certificate revocation list.

## Running the Application

Once the dependencies are installed and the configuration is set, run the application with:

```bash
python3 main.py
```

The server will automatically determine whether to run with HTTP, HTTPS, or mTLS based on the configuration in `ca-server.conf`.

## Usage

### Generate a CA

To generate a new Certificate Authority (CA), submit the "generate_ca" command via the web interface.

### Sign a Certificate

To sign a new certificate, provide the common name, output key file, and output certificate file. Submit the "sign_cert" command.

### List Certificates

To list all certificates managed by the CA, submit the "list_certs" command.

### Revoke a Certificate

To revoke an existing certificate, provide the certificate path and submit the "revoke_cert" command.

## License

This project is licensed under the MIT License.
