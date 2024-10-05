
# FAQ: Certificate Authority (CA) Web Tool using Flask and Cryptography

## 1. What is the purpose of this tool?
This tool provides a web interface for managing Certificate Authority (CA) functions such as generating a CA, signing certificates, checking their validity, listing certificates, and revoking certificates. It uses Flask for the web interface and the `cryptography` library for certificate management.

## 2. What libraries and technologies are used?
- **Flask**: For creating the web interface.
- **cryptography**: For handling certificate-related tasks such as generating keys, signing certificates, and creating Certificate Revocation Lists (CRLs).
- **ConfigParser**: To read configuration settings from a `.conf` file.
- **HTML/CSS (Bootstrap)**: For structuring and styling the user interface.
- **Python Standard Libraries**: Including `datetime`, `os`, `subprocess`, and `traceback`.

## 3. How do I configure the tool?
The tool reads configurations from a file named `ca-server.conf`. It defines paths for certificates, keys, and CRLs, as well as certificate validity periods. Make sure the file includes the following sections:
```ini
[directories]
ca_cert_path = /path/to/ca_cert.pem
ca_key_path = /path/to/ca_key.pem
ca_directory = /path/to/ca_directory
server_directory = /path/to/server_directory
crl_path = /path/to/crl.pem

[cert]
validity_days = 365
```

## 4. What are the key features of the tool?
- **Generate CA**: Creates a new CA by generating a private key and a self-signed CA certificate.
- **Sign Certificate**: Signs a certificate for a server or client, creating both the private key and the certificate.
- **List Certificates**: Displays a list of all the valid certificates in the configured directory.
- **Check Certificate**: Verifies the validity of a given certificate, checking the signature and expiration.
- **Revoke Certificate**: Revokes a certificate by adding it to the CRL.

## 5. How does certificate signing work?
When signing a certificate:
1. A private key is generated.
2. The certificate's subject name is defined based on the input (e.g., common name).
3. The certificate is signed using the CA's private key, and it is valid for the configured number of days.
4. The certificate and private key are saved to disk in PEM format.

## 6. How can I revoke a certificate?
The tool uses a CRL (Certificate Revocation List) to track revoked certificates. When a certificate is revoked, it is added to the CRL, and the CRL is updated. This CRL can then be distributed to clients or servers that need to check the status of a certificate.

## 7. How do I check if a certificate is valid?
The `check_certificate` function ensures that:
1. The certificate is not expired.
2. The certificate is signed by the CA.
3. The certificate is not listed in the CRL.

If all conditions are met, the certificate is considered valid.

## 8. What does the configuration file do?
The configuration file (`ca-server.conf`) specifies directories where CA keys, certificates, and CRLs are stored. It also includes parameters like the number of days the certificate is valid (`validity_days`).

## 9. How are certificates listed?
The tool scans the `server_directory` for files that match the pattern `*_cert.pem` and attempts to load each file as a certificate. It checks each certificate’s validity and, if valid, includes it in the displayed list.

## 10. Can I customize the paths where keys and certificates are stored?
Yes, you can customize these paths in the configuration file. The settings for `ca_cert_path`, `ca_key_path`, `server_directory`, and `ca_directory` define where files are stored and managed.

## 11. How do I run the application?
Ensure you have the required libraries installed:
```bash
pip install flask cryptography configparser
```

Then, start the Flask app with:
```bash
python app.py
```

The application will be accessible via `http://127.0.0.1:5000/` in your web browser.

## 12. What happens when I revoke a certificate?
When you revoke a certificate, it is added to the CRL (Certificate Revocation List). The CRL is updated and saved to the path defined in `ca-server.conf`. Other services can check this CRL to ensure the certificate is no longer trusted.

## 13. How do I handle errors?
Errors related to loading certificates or keys are logged using the `display_data()` function, which sends error messages to the web interface for better visibility.
