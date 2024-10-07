import os
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization

import utils
import config
import crypto_utils

config = config.load_config('ca-server.conf')

def create_crl(ca_private_key, ca_cert, cert_to_revoke, crl_path):
    msg = ""
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

        msg += (f"CRL updated and saved.")
    except:
        msg += "Found a problem during revoking certificate"

    utils.display_data(msg)

def generate_ca():
    # Create directories if they do not exist
    os.makedirs(config.ca_directory, exist_ok=True)
    os.makedirs(config.server_directory, exist_ok=True)
    utils.display_data("CA folder OK")
    utils.display_data("SERVER folder OK")

    # Logic to generate the CA
    ca_private_key = crypto_utils.generate_private_key()
    ca_cert = crypto_utils.generate_ca_cert(ca_private_key, config.validity_days)
        
    # Save the files in the correct directories
    ca_key_path = os.path.join(config.ca_directory, 'ca_key.pem')
    ca_cert_path = os.path.join(config.ca_directory, 'ca_cert.pem')
         
    crypto_utils.save_to_files(ca_private_key, ca_cert, ca_key_path, ca_cert_path)
    utils.display_data("CA Keys generated and saved in CA folder")

