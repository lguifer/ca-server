from flask import Flask, render_template, request, jsonify
from ca_server import generate_ca, sign_certificate, check_certificate

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_ca', methods=['POST'])
def generate_ca_route():
    # L�gica para generar la CA
    try:
        generate_ca()  # Implementa esta funci�n en ca_server.py
        return jsonify("CA generada correctamente.")
    except Exception as e:
        return jsonify(f"Error al generar la CA: {str(e)}"), 500

@app.route('/sign_cert', methods=['POST'])
def sign_cert_route():
    common_name = request.form['common_name']
    # L�gica para firmar el certificado
    try:
        sign_certificate(common_name)  # Implementa esta funci�n en ca_server.py
        return jsonify(f"Certificado firmado para '{common_name}'.")
    except Exception as e:
        return jsonify(f"Error al firmar el certificado: {str(e)}"), 500

@app.route('/check_cert', methods=['POST'])
def check_cert_route():
    cert_path = request.form['cert_path']
    # L�gica para comprobar la validez del certificado
    try:
        result = check_certificate(cert_path)  # Implementa esta funci�n en ca_server.py
        return jsonify(result)
    except Exception as e:
        return jsonify(f"Error al comprobar el certificado: {str(e)}"), 500

if __name__ == '__main__':
    app.run(debug=True)
