# -*- coding: utf-8 -*-

from flask import Flask, render_template, request, redirect, url_for, flash
import os
import configparser
from ca_server import *

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Cambia esto por una clave secreta real

# Leer el archivo de configuración
config = configparser.ConfigParser()
config.read('ca-server.conf')

# Rutas de directorio y archivos
ca_directory = config['directories']['ca_directory'].strip()
server_directory = config['directories']['server_directory'].strip()
crl_path = config['directories']['crl_path']
ca_cert_path = config['directories']['ca_cert_path']
ca_key_path = config['directories']['ca_key_path']
validity_days = int(config['cert']['validity_days'])

@app.route('/')
def index():
    certs = list_certificates(load_cert(ca_cert_path), server_directory)
    return render_template('index.html', certs=certs)

@app.route('/generate_ca', methods=['POST'])
def generate_ca():
    ca_private_key = generate_private_key()
    ca_cert = generate_ca_cert(ca_private_key, validity_days)
    save_to_files(ca_private_key, ca_cert, ca_key_path, ca_cert_path)
    flash('CA generada correctamente.')
    return redirect(url_for('index'))

@app.route('/sign_cert', methods=['POST'])
def sign_cert():
    common_name = request.form['common_name']
    private_key, cert = sign_certificate(common_name, load_private_key(ca_key_path), load_cert(ca_cert_path), validity_days)
    server_key_path = os.path.join(server_directory, f"{common_name}_key.pem")
    server_cert_path = os.path.join(server_directory, f"{common_name}_cert.pem")
    save_to_files(private_key, cert, server_key_path, server_cert_path)
    flash(f'Certificado firmado para "{common_name}".')
    return redirect(url_for('index'))

@app.route('/check_cert', methods=['POST'])
def check_cert():
    cert_path = request.form['cert_path']
    cert = load_cert(cert_path)          
    if check_certificate(load_cert(ca_cert_path), cert, crl_path):
        flash('Certificado OK.')
    else:
        flash('Certificado NO OK.')
    return redirect(url_for('index'))

@app.route('/revoke_cert', methods=['POST'])
def revoke_cert():
    cert_path = request.form['cert_path']
    cert_to_revoke = load_cert(cert_path)
    create_crl(load_private_key(ca_key_path), load_cert(ca_cert_path), cert_to_revoke, crl_path)
    flash(f'Certificado revocado: {cert_path}.')
    return redirect(url_for('index'))

@app.route('/list_certs', methods=['GET'])
def list_certs():
    cert_files = [f for f in os.listdir(server_directory) if f.endswith('_cert.pem')]
    valid_certs = []

    # Cargar el certificado CA
    ca_cert = load_cert(ca_cert_path)

    for cert_file in cert_files:
        cert_path = os.path.join(server_directory, cert_file)
        cert = load_cert(cert_path)

        if check_certificate(ca_cert, cert, crl_path):
            valid_certs.append(cert_file)

    return render_template('index.html', valid_certs=valid_certs)

if __name__ == "__main__":
    app.run(debug=True)
