# Cryptography library imports
from msilib import Table
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

# Flask imports
from flask import Flask, render_template, request, redirect, url_for, jsonify

# Config parser
import configparser

from itsdangerous import NoneAlgorithm

app = Flask(__name__)

# Read the configuration file
config = configparser.ConfigParser()
config.read('ca-server.conf')

# Global variables
ca_cert_path = config['directories']['ca_cert_path']
ca_key_path = config['directories']['ca_key_path']
ca_directory = config['directories']['ca_directory'].strip()
server_directory = config['directories']['server_directory'].strip()
validity_days = int(config['cert']['validity_days'].strip())
crl_path = config['directories']['crl_path']
table_content = ""
table_rows = ""
buffer = ""

def display_data(data):
    global table_content, table_rows
    # Prepare data for table
    data_lines = data.splitlines()  # Split the input data into lines
    table_rows += "".join(f"<tr><td>{line}</td></tr>" for line in data_lines)
    table_content = f"<table class='table table-bordered'><tbody>{table_rows}</tbody></table>"
    #return render_template('index.html', table_content=table_content)
def create_crl(ca_private_key, ca_cert, cert_to_revoke, crl_path):
    global buffer
    """
    Revokes a certificate and generates a CRL (Certificate Revocation List).

    :param ca_private_key: The private key of the CA
    :param ca_cert: The certificate of the CA
    :param cert_to_revoke: The certificate to revoke
    :param crl_path: The path where the CRL will be saved
    """
    try:
        # Get serial number from the certificate to revoke
        revoked_cert = x509.RevokedCertificateBuilder().serial_number(
            cert_to_revoke.serial_number
        ).revocation_date(
            datetime.datetime.now(datetime.timezone.utc)
        ).build(default_backend())

        # Try to load the existing CRL
        if os.path.exists(crl_path):
            with open(crl_path, "rb") as f:
                crl_data = f.read()
                existing_crl = x509.load_pem_x509_crl(crl_data, default_backend())
                crl_builder = x509.CertificateRevocationListBuilder().issuer_name(existing_crl.issuer)

                # Add revoked certificate to the CRL
                for revoked in existing_crl:
                    crl_builder = crl_builder.add_revoked_certificate(revoked)
        else:
            crl_builder = x509.CertificateRevocationListBuilder()
            crl_builder = crl_builder.issuer_name(ca_cert.subject)

        # Add revoked certificate to the CRL
        crl_builder = crl_builder.add_revoked_certificate(revoked_cert)

        # Establish last update and next update dates
        current_time = datetime.datetime.now(datetime.timezone.utc)
        crl_builder = crl_builder.last_update(current_time)
        crl_builder = crl_builder.next_update(current_time + datetime.timedelta(days=30))

        # Sign the CRL with the private key
        crl = crl_builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256(), backend=default_backend())

        # Save the CRL to a file
        with open(crl_path, "wb") as f:
            f.write(crl.public_bytes(serialization.Encoding.PEM))

        buffer += (f"CRL updated and saved: {crl_path}")
    except:
        buffer += "Found a problem during revoking certificate"

# Generate RSA private key
def generate_private_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key

def load_private_key(file_name="private_key.pem"):
    with open(file_name, 'rb') as pem_in:
        private_key = serialization.load_pem_private_key(
            pem_in.read(),
            password=None,  # If ciphered, provide password here
            backend=default_backend()
        )
    return private_key

# Generate self-signed certificate for CA
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
        display_data(f"Error loading the private key: {e}")
        raise

def load_cert(cert_file):
    try:
        with open(cert_file, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        return cert
    except (FileNotFoundError, ValueError) as e:
        display_data(f"Error loading the certificate: {e}")
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
        traceback.display_data_exc() 
        return False
    except Exception as e:
        display_data("Error during signature verification:")
        traceback.display_data_exc() 
        return False

    if check_revocation(cert.serial_number, crl_path):
        return False

    return True

def check_revocation(serial_number, crl_path):
    if not os.path.exists(crl_path):
        display_data(f"CRL not found at {crl_path}.")
        return False

    with open(crl_path, "rb") as f:
        crl_data = f.read()
        crl = x509.load_pem_x509_crl(crl_data, default_backend())

    for revoked in crl:
        if revoked.serial_number == serial_number:
            return True  

    return False

def list_certificates(ca_cert, directory):
    buffer = ""
    cert_files = [f for f in os.listdir(directory) if f.endswith('_cert.pem')]
    
    if cert_files:
        for cert_file in cert_files:
            cert_path = os.path.join(directory, cert_file)
            cert = load_cert(cert_path)

            try:
                if check_certificate(ca_cert, cert, crl_path):
                    buffer += (f"{cert_file}\n")
            except Exception as e:
                pass
    if buffer == "": buffer = "Certificates not found."
    return buffer
def get_certificates(ca_cert, directory):
    global crl_path
    certificates = []
    cert_files = [f for f in os.listdir(directory) if f.endswith('_cert.pem')]
    
    if cert_files:
        for cert_file in cert_files:
            cert_path = os.path.join(directory, cert_file)
            cert = load_cert(cert_path)

            try:
                # Check if the certificate is valid
                if check_certificate(ca_cert, cert, crl_path):
                    # Append to the list in the required format
                    certificates.append({
                        'path': cert_path,  # Full path of the certificate
                        'name': cert_file   # File name used as certificate name
                    })
            except Exception as e:
                pass
    print(certificates)
    return certificates

@app.route('/', methods=['GET', 'POST'])
def index():
    global table_content, table_rows, buffer, ca_key_path, ca_cert_path, validity_days, server_directory
    table_content = ""
    table_rows = ""
    buffer = ""
    ca_private_key = load_private_key(ca_key_path)
    ca_cert = load_cert(ca_cert_path)
    certificates = get_certificates(ca_cert, server_directory)
    print(f"certs: {certificates}")
    if request.method == 'POST':
        command = request.form.get('command')
        print(f"command: {command}")
        if command == "generate_ca":
            # Get the directory paths and clean them

            # Create directories if they do not exist
            os.makedirs(ca_directory, exist_ok=True)
            os.makedirs(server_directory, exist_ok=True)
            display_data("CA folder OK")
            display_data("SERVER folder OK")
            # Get validity information
            validity_days = config['cert'].getint('validity_days')

            # Logic to generate the CA
            ca_private_key = generate_private_key()
            ca_cert = generate_ca_cert(ca_private_key, validity_days)
        
            # Save the files in the correct directories
            ca_key_path = os.path.join(ca_directory, 'ca_key.pem')
            ca_cert_path = os.path.join(ca_directory, 'ca_cert.pem')
         
            save_to_files(ca_private_key, ca_cert, ca_key_path, ca_cert_path)
            display_data("CA Keys generated and saved in CA folder")
            

            pass
        if command is None:
            manage_command = request.form.get('manage_command')
            print(manage_command)
            if manage_command == "sign_cert":
                common_name = request.form.get('common_name')
                output_key = request.form.get('output_key', 'server_key.pem')
                output_cert = request.form.get('output_cert', 'server_cert.pem')

                # Logic to sign certificate will be implemented here
                # Sign certificate
                private_key, cert = sign_certificate(common_name, ca_private_key, ca_cert, validity_days)
        
                # Save generated files
                server_key_path = os.path.join(server_directory, f"{common_name}_key.pem")
                server_cert_path = os.path.join(server_directory, f"{common_name}_cert.pem")
                print(f"{server_key_path}, {server_cert_path}")
                save_to_files(private_key, cert, server_key_path, server_cert_path)

                display_data(f"Signed certificate for '{common_name}' and saved at {server_key_path} and {server_cert_path}")
                pass

            elif manage_command == "check_cert":
                cert_path = request.form.get('path')
                # Logic to check certificate validity will be implemented here
                pass

            elif manage_command == "list_certs":
                # Logic to list signed certificates will be implemented here
                buffer = list_certificates(ca_cert, server_directory)
                display_data(buffer)
                #pass

            elif manage_command == "revoke_cert":
                cert_path = request.form.get('cert_path')
                # Load certificate to revoke, private key, and CA Cert
                cert_to_revoke = load_cert(cert_path)
                ca_private_key = load_private_key(ca_key_path)
                ca_cert = load_cert(ca_cert_path)

                # Create or update the CRL
                create_crl(ca_private_key, ca_cert, cert_to_revoke, crl_path)
                
                display_data(buffer)
                pass
    print(table_content)

    return render_template('index.html', table_content=table_content, certificates=certificates)

if __name__ == '__main__':
    app.run(debug=True)
