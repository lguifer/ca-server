
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

The `ca-server.conf` file is essential for the proper operation of the Certificate Authority (CA) server. It should contain the following structure, with different sections that configure both the CA and the web server. Below is a detailed explanation of each field:

### Sections of the Configuration File

#### `[ca]`

This section contains the basic information about the Certificate Authority (CA):

- `country`: The country where the CA is registered, for example, `"ES"` for Spain.
- `state`: The state or province where the CA is located, for example, `"Madrid"`.
- `locality`: The locality or city where the CA is based, for example, `"Madrid"`.
- `organization`: The name of the organization that owns the CA, for example, `"Example"`.
- `common_name`: The common name that identifies the CA, usually used for the root certificate, for example, `"Example Root CA"`.

#### `[cert]`

This section sets parameters for the certificates issued by the CA:

- `validity_days`: The number of days that the issued certificates will be valid, for example, `3650` for a certificate valid for 10 years.
- `key_size`: The size (in bits) of the keys generated for certificates. Common values are `2048` or `4096` bits.

#### `[directories]`

This section defines the paths where key and certificate files will be stored:

- `ca_key_path`: The path to the CA’s private key file, for example, `ca/ca_key.pem`.
- `ca_cert_path`: The path to the CA’s public certificate file, for example, `ca/ca_cert.pem`.
- `ca_directory`: The directory where CA-related files (keys, certificates) are stored, for example, `ca/`.
- `server_directory`: The directory where server-related files are stored, for example, `server/`.
- `crl_path`: The path where the Certificate Revocation List (CRL) is stored, for example, `ca/crl`.

#### `[webserver]`

This section defines the configuration for the web server, which will manage the CA operations through a web interface:

- `IP`: The IP address where the web server will bind, for example, `0.0.0.0` to listen on all interfaces. Other values could be specific IPs like `127.0.0.1` (localhost) or a private IP like `192.168.10.10`.
- `port`: The port on which the web server will run. Typically, `443` for HTTPS, but it can be changed.
- `use_tls`: Specifies whether to use TLS (Transport Layer Security) for secure communication. Valid values:
  - `none`: No TLS (HTTP only).
  - `tls`: Enables TLS (HTTPS).
  - `mtls`: Enables mutual TLS (both client and server authentication).
- `web_key_path`: The path to the server’s private key, used for TLS or mTLS, for example, `CA-server_key.pem`.
- `web_cert_path`: The path to the server’s certificate, used for TLS or mTLS, for example, `CA-server_cert.pem`.


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
