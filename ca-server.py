import argparse
import configparser
import datetime
import os
import subprocess
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
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

def load_private_key(key_file):
    """
    Carga una clave privada desde un archivo PEM.

    :param key_file: Ruta al archivo de la clave privada.
    :return: La clave privada cargada.
    :raises ValueError: Si hay un error al cargar la clave.
    """
    try:
        with open(key_file, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,  # Cambiar esto si la clave está cifrada
                backend=default_backend()
            )
        return private_key
    except (FileNotFoundError, ValueError) as e:
        print(f"Error al cargar la clave privada: {e}")
        raise

def load_cert(cert_file):
    """
    Carga un certificado desde un archivo PEM.

    :param cert_file: Ruta al archivo del certificado.
    :return: El certificado cargado.
    :raises ValueError: Si hay un error al cargar el certificado.
    """
    try:
        with open(cert_file, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        return cert
    except (FileNotFoundError, ValueError) as e:
        print(f"Error al cargar el certificado: {e}")
        raise
def sign_certificate(common_name, ca_private_key, ca_cert, validity_days):
    """
    Firma un certificado de servidor o cliente con la CA.

    :param common_name: Nombre común (Common Name) para el certificado.
    :param ca_private_key: Clave privada de la CA para firmar el certificado.
    :param ca_cert: Certificado de la CA que firma el nuevo certificado.
    :param validity_days: Días de validez del certificado.
    :return: La clave privada y el certificado firmado.
    """
    # Generar una nueva clave privada para el certificado
    private_key = generate_private_key()
    
    # Crear el sujeto del certificado
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Madrid"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Madrid"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Example"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    # Construir el certificado
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject  # La CA es el emisor
    ).public_key(
        private_key.public_key()  # Clave pública del nuevo certificado
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)  # Fecha de inicio de validez
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=validity_days)  # Fecha de expiración
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(common_name)]),
        critical=False,
    ).sign(ca_private_key, hashes.SHA256(), default_backend())  # Firmar el certificado con la clave privada de la CA

    return private_key, cert

def check_certificate(ca_cert, cert):
    # Obtener la hora actual con zona horaria UTC
    current_time = datetime.datetime.now(datetime.timezone.utc)

    # Verificar las fechas de validez del certificado
    if current_time < cert.not_valid_before.replace(tzinfo=datetime.timezone.utc) or \
       current_time > cert.not_valid_after.replace(tzinfo=datetime.timezone.utc):
        print("El certificado no es válido (fuera de las fechas de validez).")
        return False
    else:
        print("El certificado está dentro de las fechas de validez.")

    # Verificar que el certificado esté firmado por la CA
    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),  # Padding para la verificación de la firma
            cert.signature_hash_algorithm,
        )
        print("La firma del certificado es válida y está firmada por la CA.")
        return True
    except Exception as e:
        print(f"La firma del certificado no es válida: {e}")
        return False

# Función principal
def main():
    parser = argparse.ArgumentParser(description="CA Tool: Generar CA y firmar certificados.")
    subparsers = parser.add_subparsers(dest="command", help="Comandos disponibles")

    # Comando para generar la CA
    parser_ca = subparsers.add_parser("generate_ca", help="Generar una nueva CA.")
    
    # Comando para firmar certificados
    parser_sign = subparsers.add_parser("sign_cert", help="Firmar un certificado con la CA.")
    parser_sign.add_argument("--common-name", required=True, help="Nombre común (Common Name) para el certificado.")
    parser_sign.add_argument("--output-key", default="server_key.pem", help="Archivo para guardar la clave privada del servidor/cliente.")
    parser_sign.add_argument("--output-cert", default="server_cert.pem", help="Archivo para guardar el certificado del servidor/cliente.")

    # Comando para comprobar la validez de un certificado
    parser_check = subparsers.add_parser("check-cert", help="Comprobar la validez de un certificado.")
    parser_check.add_argument("--path", required=True, help="Ruta al certificado a comprobar.")


    # Comando para enviar certificados
    parser_send = subparsers.add_parser("send_certs", help="Enviar certificados a una IP remota.")
    parser_send.add_argument("--destination-ip", required=True, help="IP de la máquina destino a la cual enviar los certificados.")
    parser_send.add_argument("--cert-file", required=True, help="Archivo del certificado a enviar.")
    parser_send.add_argument("--key-file", required=True, help="Archivo de la clave privada a enviar.")

    # Leer el archivo de configuración
    config = configparser.ConfigParser()
    config.read('ca-server.conf')

    args = parser.parse_args()

    if args.command == "generate_ca":
        # Obtener las rutas de los directorios y limpiarlas
        ca_key_directory = directories['ca_key_directory'].strip()
        ca_cert_directory = directories['ca_cert_directory'].strip()
        server_directory = directories['server_directory'].strip()

        # Crear directorios si no existen
        os.makedirs(ca_key_directory, exist_ok=True)
        os.makedirs(ca_cert_directory, exist_ok=True)
        os.makedirs(server_directory, exist_ok=True)

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

    elif args.command == "sign_cert":
        # Cargar la configuración
        validity_days = int(config['cert']['validity_days'])
    
        # Cargar la clave privada de la CA
        ca_private_key = load_private_key(config['directories']['ca_key_directory'] + "/ca_key.pem")
    
        # Cargar el certificado de la CA
        ca_cert = load_cert(config['directories']['ca_cert_directory'] + "/ca_cert.pem")

        # Firmar el certificado
        private_key, cert = sign_certificate(args.common_name, ca_private_key, ca_cert, validity_days)
    
        # Guardar los archivos generados
        server_key_path = f"{config['directories']['server_directory']}/{args.common_name}_key.pem"
        server_cert_path = f"{config['directories']['server_directory']}/{args.common_name}_cert.pem"
        save_to_files(private_key, cert, server_key_path, server_cert_path)

        print(f"Certificado firmado para '{args.common_name}' y guardado en {server_key_path} y {server_cert_path}")

    elif args.command == "check-cert":
        # Lógica para comprobar la validez de un certificado
        #server_key_path = f"{config['directories']['ca_key_path']}"
        server_cert_path = f"{config['directories']['ca_cert_path']}"
        cert = load_cert(args.path)
        ca_cert = load_cert(server_cert_path)
        check_certificate(cert, ca_cert)  # Comprobar la validez del certificado

    elif args.command == "send_certs":
        # Lógica para enviar certificados
        pass  # Implementar lógica de envío de certificados

if __name__ == "__main__":
    main()
