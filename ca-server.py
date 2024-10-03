import argparse
import datetime
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
def generate_ca_cert(private_key):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"My Company Root CA"),
    ])
    
    ca_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # El certificado es válido por 10 años
        datetime.datetime.utcnow() + datetime.timedelta(days=365*10)
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

# Firmar un certificado de servidor/cliente con la CA
def sign_certificate(common_name, ca_private_key, ca_cert):
    private_key = generate_private_key()
    
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
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
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(common_name)]),
        critical=False,
    ).sign(ca_private_key, hashes.SHA256(), default_backend())

    return private_key, cert

# Cargar un certificado desde un archivo
def load_cert(cert_file):
    with open(cert_file, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    return cert

# Cargar una clave privada desde un archivo
def load_private_key(key_file):
    with open(key_file, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    return private_key

# Función para enviar los certificados mediante SCP
def send_certs(destination_ip, key_filename, cert_filename):
    try:
        subprocess.run(["scp", key_filename, cert_filename, f"{destination_ip}:~/"], check=True)
        print(f"Certificados enviados a {destination_ip}")
    except subprocess.CalledProcessError as e:
        print(f"Error enviando certificados: {e}")

# Función principal
def main():
    parser = argparse.ArgumentParser(description="CA Tool: Generar CA y firmar certificados.")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Comando para generar la CA
    parser_ca = subparsers.add_parser("generate_ca", help="Generar una nueva CA.")
    parser_ca.add_argument("--ca-key", default="ca_key.pem", help="Archivo para guardar la clave privada de la CA.")
    parser_ca.add_argument("--ca-cert", default="ca_cert.pem", help="Archivo para guardar el certificado de la CA.")

    # Comando para firmar certificados
    parser_sign = subparsers.add_parser("sign_cert", help="Firmar un certificado de servidor o cliente.")
    parser_sign.add_argument("--common-name", required=True, help="Nombre común (Common Name) para el certificado.")
    parser_sign.add_argument("--ca-key", default="ca_key.pem", help="Clave privada de la CA.")
    parser_sign.add_argument("--ca-cert", default="ca_cert.pem", help="Certificado de la CA.")
    parser_sign.add_argument("--output-key", default="server_key.pem", help="Archivo para guardar la clave privada del servidor/cliente.")
    parser_sign.add_argument("--output-cert", default="server_cert.pem", help="Archivo para guardar el certificado del servidor/cliente.")
    parser_sign.add_argument("--send-certs", help="IP de la máquina destino a la cual enviar los certificados vía SCP.")

    args = parser.parse_args()

    if args.command == "generate_ca":
        # Generar la CA
        ca_private_key = generate_private_key()
        ca_cert = generate_ca_cert(ca_private_key)
        save_to_files(ca_private_key, ca_cert, args.ca_key, args.ca_cert)
        print(f"CA generada y guardada en {args.ca_key} y {args.ca_cert}")
    
    elif args.command == "sign_cert":
        # Firmar un certificado de servidor o cliente
        ca_private_key = load_private_key(args.ca_key)
        ca_cert = load_cert(args.ca_cert)
        private_key, cert = sign_certificate(args.common_name, ca_private_key, ca_cert)
        save_to_files(private_key, cert, args.output_key, args.output_cert)
        print(f"Certificado firmado para '{args.common_name}' y guardado en {args.output_key} y {args.output_cert}")
        
        # Enviar los certificados si se proporciona la opción --send-certs
        if args.send_certs:
            send_certs(args.send_certs, args.output_key, args.output_cert)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
