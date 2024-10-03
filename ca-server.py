import argparse
import configparser
import datetime
import os
import subprocess
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

# Generar una clave privada RSA
def generate_private_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key

# Generar un certificado autofirmado para la CA
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

# Guardar clave privada y certificado en archivos
def save_to_files(private_key, cert, key_filename, cert_filename):
    # Guardar la clave privada en un archivo
    with open(key_filename, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption()
        ))
    
    # Guardar el certificado en un archivo
    with open(cert_filename, "wb") as f:
        f.write(cert.public_bytes(Encoding.PEM))

# Función principal
def main():
    parser = argparse.ArgumentParser(description="CA Tool: Generar CA y firmar certificados.")
    parser.add_argument('command', choices=['generate_ca'], help="Comando a ejecutar")

    # Leer el archivo de configuración
    config = configparser.ConfigParser()
    config.read('ca-server.conf')

    # Obtener la información de configuración
    directories = config['directories']

    # Definir args para el uso posterior
    args = parser.parse_args()

    if args.command == "generate_ca":
        # Obtener las rutas de los directorios y limpiarlas
        ca_key_directory = directories['ca_key_directory'].strip()
        ca_cert_directory = directories['ca_cert_directory'].strip()
        server_key_directory = directories['server_key_directory'].strip()

        # Crear directorios si no existen
        os.makedirs(ca_key_directory, exist_ok=True)
        os.makedirs(ca_cert_directory, exist_ok=True)
        os.makedirs(server_key_directory, exist_ok=True)

        # Obtener información de validez
        validity_days = config['cert'].getint('validity_days')

        # Lógica para generar la CA
        ca_private_key = generate_private_key()
        ca_cert = generate_ca_cert(ca_private_key, validity_days)
        
        # Guardar los archivos en los directorios correctos
        ca_key_path = os.path.join(ca_key_directory, 'ca_key.pem')
        ca_cert_path = os.path.join(ca_cert_directory, 'ca_cert.pem')
        
        save_to_files(ca_private_key, ca_cert, ca_key_path, ca_cert_path)
        
        print(f"CA generada y guardada en {ca_key_path} y {ca_cert_path}")

if __name__ == "__main__":
    main()
