import os
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

def load_private_key(file_name):
    with open(file_name, 'rb') as pem_in:
        private_key = serialization.load_pem_private_key(
            pem_in.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

def load_cert(cert_file):
    try:
        with open(cert_file, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        return cert
    except (FileNotFoundError, ValueError) as e:
        display_data(f"Error loading the certificate: {e}")
        raise
def save_to_files(private_key, cert, key_filename, cert_filename):
    with open(key_filename, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption()
        ))

    with open(cert_filename, "wb") as f:
        f.write(cert.public_bytes(Encoding.PEM))

def generate_private_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

def generate_ca_cert(private_key, validity_days):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Madrid"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Madrid"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Example"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"Example Root CA"),
    ])
    
    now = datetime.datetime.now(datetime.timezone.utc)
    return x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(private_key.public_key()).serial_number(
        x509.random_serial_number()).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=validity_days)).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(private_key, hashes.SHA256(), default_backend())
