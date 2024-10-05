# -*- coding: utf-8 -*-

# Cryptography library imports
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, load_pem_private_key
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import NameOID

# Standard library imports
import os
import datetime
from datetime import timezone
import traceback
import subprocess

# Config parser
import configparser


# Leer el archivo de configuración
config = configparser.ConfigParser()
config.read('ca-server.conf')

#Variables globales
crl_path = config['directories']['crl_path']
ca_key_path = config['directories']['ca_key_path']
ca_cert_path = config['directories']['ca_cert_path']
validity_days = int(config['cert']['validity_days'])
ca_directory = config['directories']['ca_directory'].strip()
server_directory = config['directories']['server_directory'].strip()



def create_crl(ca_private_key, ca_cert, cert_to_revoke, crl_path):
    """
    Revoca un certificado y genera una CRL (Certificate Revocation List).

    :param ca_private_key: La clave privada de la CA
    :param ca_cert: El certificado de la CA
    :param cert_to_revoke: El certificado a revocar
    :param crl_path: La ruta donde se guardará la CRL
    """
    # Get serial number from certificate to revoke
    revoked_cert = x509.RevokedCertificateBuilder().serial_number(
        cert_to_revoke.serial_number
    ).revocation_date(
        datetime.datetime.now(datetime.timezone.utc)
    ).build(default_backend())

    # Try to load existing CRL
    if os.path.exists(crl_path):
        with open(crl_path, "rb") as f:
            crl_data = f.read()
            existing_crl = x509.load_pem_x509_crl(crl_data, default_backend())
            crl_builder = x509.CertificateRevocationListBuilder().issuer_name(existing_crl.issuer)
            
            # Add revoked certificate to CRL
            for revoked in existing_crl:
                crl_builder = crl_builder.add_revoked_certificate(revoked)
    else:
        crl_builder = x509.CertificateRevocationListBuilder()
        crl_builder = crl_builder.issuer_name(ca_cert.subject)

    # Add revoked certificate to CRL
    crl_builder = crl_builder.add_revoked_certificate(revoked_cert)

    # Establish last date and next date updates
    current_time = datetime.datetime.now(datetime.timezone.utc)
    crl_builder = crl_builder.last_update(current_time)
    crl_builder = crl_builder.next_update(current_time + datetime.timedelta(days=30))

    # Sign CRL with private key
    crl = crl_builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256(), backend=default_backend())

    # Save CRL to file
    with open(crl_path, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))

    print(f"CRL updated and saved: {crl_path}")


# Generate RSA private key
def generate_private_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key

# Generate autosigned certificate for CA
def generate_ca_cert(private_key, validity_days):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Madrid"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Madrid"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Example"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"Example Root CA"),
    ])
    
    now = datetime.datetime.now(datetime.timezone.utc)

    ca_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now
    ).not_valid_after(
        now + datetime.timedelta(days=validity_days)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(private_key, hashes.SHA256(), default_backend())
    
    return ca_cert

def save_to_files(private_key, cert, key_filename, cert_filename):
    with open(key_filename, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption()
        ))
    
    with open(cert_filename, "wb") as f:
        f.write(cert.public_bytes(Encoding.PEM))

def load_private_key(key_file):

    try:
        with open(key_file, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,  
                backend=default_backend()
            )
        return private_key
    except (FileNotFoundError, ValueError) as e:
        print(f"Error al cargar la clave privada: {e}")
        raise

def load_cert(cert_file):

    try:
        with open(cert_file, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        return cert
    except (FileNotFoundError, ValueError) as e:
        print(f"Error al cargar el certificado: {e}")
        raise
def sign_certificate(common_name, ca_private_key, ca_cert, validity_days):

    private_key = generate_private_key()
    
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Madrid"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Madrid"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Example"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject  
    ).public_key(
        private_key.public_key()  
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)  
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=validity_days) 
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(common_name)]),
        critical=False,
    ).sign(ca_private_key, hashes.SHA256(), default_backend())

    return private_key, cert

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import datetime
import traceback

def check_certificate(ca_cert, cert, crl_path):

    current_time = datetime.datetime.now(datetime.timezone.utc)

    if current_time < cert.not_valid_before_utc.replace(tzinfo=datetime.timezone.utc) or \
       current_time > cert.not_valid_after_utc.replace(tzinfo=datetime.timezone.utc):
        return False

    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),  
            cert.signature_hash_algorithm,
        )
    except InvalidSignature:
        traceback.print_exc() 
        return False
    except Exception as e:

        print("Error during sign verification:")
        traceback.print_exc() 
        return False

    if check_revocation(cert.serial_number, crl_path):
        return False

    return True

def check_revocation(serial_number, crl_path):
  
    if not os.path.exists(crl_path):
        print(f"CRL not found on {crl_path}.")
        return False

    with open(crl_path, "rb") as f:
        crl_data = f.read()
        crl = x509.load_pem_x509_crl(crl_data, default_backend())

    for revoked in crl:
        if revoked.serial_number == serial_number:
            return True  

    return False


def list_certificates(ca_cert, directory):
  
    cert_files = [f for f in os.listdir(directory) if f.endswith('_cert.pem')]
    
    if cert_files:
        for cert_file in cert_files:
            cert_path = os.path.join(directory, cert_file)
            cert = load_cert(cert_path)

            try:
                if check_certificate(ca_cert, cert, crl_path):
                    print(f"{cert_file}")
            except Exception as e:
                print(f"{cert_file}: Not valid ({str(e)})")

def main():
    global ca_cert_path, ca_directory, server_directory, server_cert_path, server_key_path, ca_key_path
    ca_cert = load_cert(ca_cert_path)
    parser = argparse.ArgumentParser(description="CA Tool: Generate CA and manage certificates.")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Command to generate the CA
    parser_ca = subparsers.add_parser("generate_ca", help="Generate a new CA.")
    
    # Command to manage certificates
    parser_manage_certs = subparsers.add_parser("manage-certificates", help="Manage certificates.")
    manage_subparsers = parser_manage_certs.add_subparsers(dest="manage_command", help="Actions within manage certificates.")

    # Subcommand to sign certificates
    parser_sign = manage_subparsers.add_parser("sign_cert", help="Sign a certificate with the CA.")
    parser_sign.add_argument("--common-name", required=True, help="Common Name for the certificate.")
    parser_sign.add_argument("--output-key", default="server_key.pem", help="File to save the server/client private key.")
    parser_sign.add_argument("--output-cert", default="server_cert.pem", help="File to save the server/client certificate.")

    # Subcommand to check the validity of a certificate
    parser_check = manage_subparsers.add_parser("check_cert", help="Check the validity of a certificate.")
    parser_check.add_argument("--path", required=True, help="Path to the certificate to check.")

    # Subcommand to list signed certificates
    parser_list = manage_subparsers.add_parser("list_certs", help="List certificates signed by the CA.")

    # Subcommand to revoke a certificate
    parser_revoke = manage_subparsers.add_parser("revoke_cert", help="Revoke a certificate and update the CRL.")
    parser_revoke.add_argument("--cert-path", required=True, help="Path of the certificate to revoke.")

    args = parser.parse_args()

    if args.command == "generate_ca":
        # Get the directory paths and clean them

        # Create directories if they do not exist
        os.makedirs(ca_directory, exist_ok=True)
        os.makedirs(server_directory, exist_ok=True)

        # Get validity information
        validity_days = config['cert'].getint('validity_days')

        # Logic to generate the CA
        ca_private_key = generate_private_key()
        ca_cert = generate_ca_cert(ca_private_key, validity_days)
        
        # Save the files in the correct directories
        ca_key_path = os.path.join(ca_directory, 'ca_key.pem')
        ca_cert_path = os.path.join(ca_directory, 'ca_cert.pem')
        
        save_to_files(ca_private_key, ca_cert, ca_key_path, ca_cert_path)
        
        print(f"CA generated and saved at {ca_key_path} and {ca_cert_path}")

    elif args.command == "manage-certificates":
        if args.manage_command == "sign_cert":

            # Sign certificate
            private_key, cert = sign_certificate(args.common_name, ca_private_key, ca_cert, validity_days)
        
            # Save generated files
            server_key_path = os.path.join(server_directory, f"{args.common_name}_key.pem")
            server_cert_path = os.path.join(server_directory, f"{args.common_name}_cert.pem")
            save_to_files(private_key, cert, server_key_path, server_cert_path)

            print(f"Signed certificate for '{args.common_name}' and saved at {server_key_path} and {server_cert_path}")

        elif args.manage_command == "check_cert":
            # Check validity certificate
            cert = load_cert(args.path)          
            if check_certificate(ca_cert, cert, crl_path):  # Check validity certificate
                print("Certificate OK.")
            else:
                print("Certificate INVALID.")       
        elif args.manage_command == "list_certs":
            list_certificates(ca_cert, server_directory)
        elif args.manage_command == "revoke_cert":

            # Load certificate to revoke, private key, and CA Cert
            cert_to_revoke = load_cert(args.cert_path)
            ca_private_key = load_private_key(ca_key_path)
            ca_cert = load_cert(ca_cert_path)

            # Create or update the CRL
            create_crl(ca_private_key, ca_cert, cert_to_revoke, crl_path)
            print(f"Certificate revoked: {args.cert_path} and CRL updated at {crl_path}")


if __name__ == "__main__":
    main()

