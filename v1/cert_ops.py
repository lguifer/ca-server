import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa, padding


import crypto_utils
import config
import utils
import ca
import datetime
import traceback


config = config.load_config('ca-server.conf')
ca_cert = crypto_utils.load_cert(config.ca_cert_path)
directory = config.server_directory
crl_path = config.crl_path

def sign_certificate(common_name, ca_private_key, ca_cert, validity_days):
    private_key = crypto_utils.generate_private_key()

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

def list_certificates():

    msg = ""
    cert_files = [f for f in os.listdir(directory) if f.endswith('_cert.pem')]
    
    if cert_files:
        for cert_file in cert_files:
            cert_path = os.path.join(directory, cert_file)
            cert = crypto_utils.load_cert(cert_path)

            try:
                print(ca_cert)
                print(cert)
                print(crl_path)
                if check_certificate(ca_cert, cert, crl_path):
                    msg += (f"{cert_file}\n")
            except Exception as e:
                pass
    if msg == "": msg = "Certificates not found."
    utils.display_data(msg)
    

def get_certificates():
    certificates = []
    cert_files = [f for f in os.listdir(directory) if f.endswith('_cert.pem')]
    
    if cert_files:
        for cert_file in cert_files:
            cert_path = os.path.join(directory, cert_file)
            cert = crypto_utils.load_cert(cert_path)

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

def check_revocation(serial_number, crl_path):
    if not os.path.exists(crl_path):
        utils.display_data(f"CRL not found at {crl_path}.")
        return False

    with open(crl_path, "rb") as f:
        crl_data = f.read()
        crl = x509.load_pem_x509_crl(crl_data, default_backend())

    for revoked in crl:
        if revoked.serial_number == serial_number:
            return True  

    return False

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
        utils.display_data("Error during signature verification:")
        traceback.display_data_exc() 
        return False

    if check_revocation(cert.serial_number, crl_path):
        return False

    return True

def create_certificate(common_name, output_key, output_cert):
    #common_name = request.form.get('common_name')
    #output_key = request.form.get('output_key', 'server_key.pem')
    #output_cert = request.form.get('output_cert', 'server_cert.pem')

    # Logic to sign certificate will be implemented here
    # Sign certificate
    private_key, cert = sign_certificate(common_name, crypto_utils.load_private_key(config.ca_key_path), crypto_utils.load_cert(config.ca_cert_path), config.validity_days)
        
    # Save generated files
    server_key_path = os.path.join(config.server_directory, f"{common_name}_key.pem")
    server_cert_path = os.path.join(config.server_directory, f"{common_name}_cert.pem")
    print(f"{server_key_path}, {server_cert_path}")
    crypto_utils.save_to_files(private_key, cert, server_key_path, server_cert_path)
    utils.display_data(f"Signed certificate for '{common_name}' and saved at {server_key_path} and {server_cert_path}")

def revoke_certificate(cert_path):
    # Load certificate to revoke, private key, and CA Cert
    cert_to_revoke = crypto_utils.load_cert(cert_path)
    ca_private_key = crypto_utils.load_private_key(config.ca_key_path)
    # Create or update the CRL
    ca.create_crl(ca_private_key, ca_cert, cert_to_revoke, crl_path)