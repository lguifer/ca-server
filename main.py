from flask import Flask, render_template, request
import config
import crypto_utils
import ca
import utils
import cert_ops
import ssl

app = Flask(__name__)

# Load configuration
app_config = config.load_config('ca-server.conf')

# Load CA private key and certificate
ca_private_key = crypto_utils.load_private_key(app_config.ca_key_path)
ca_cert = crypto_utils.load_cert(app_config.ca_cert_path)

@app.route('/', methods=['GET', 'POST'])
def index():
    msg = ""
    
    if request.method == 'POST':
        command = request.form.get('command')
        manage_command = request.form.get('manage_command')
        
        if command == "generate_ca":
            ca.generate_ca()
            msg = "CA generated successfully."
        elif manage_command == "sign_cert":
            common_name = request.form.get('common_name')
            output_key = request.form.get('output_key', 'server_key.pem')
            output_cert = request.form.get('output_cert', 'server_cert.pem')
            cert_ops.create_certificate(common_name, output_key, output_cert)
            msg = "Certificate signed successfully."
        elif manage_command == "list_certs":
            cert_ops.list_certificates()
        elif manage_command == "revoke_cert":
            cert_path = request.form.get('cert_path')
            cert_ops.revoke_certificate(cert_path)
            msg = "Certificate revoked successfully."

    return render_template('index.html', table_content=utils.table_content, certificates=cert_ops.get_certificates(), message=msg)

if __name__ == '__main__':
    # Determine whether to run with HTTP, HTTPS, or mTLS based on configuration
    if app_config.use_tls == 'mtls':
        print("Running with mTLS (mutual TLS).")
        # Configure mTLS: both server and client will verify certificates
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=app_config.web_cert_path, keyfile=app_config.web_key_path)
        context.load_verify_locations(cafile=app_config.ca_cert_path)
        context.verify_mode = ssl.CERT_REQUIRED
        app.run(host=app_config.IP, port=app_config.port, ssl_context=context)
    elif app_config.use_tls == 'tls':
            print("Running with TLS (HTTPS).")
            # Only configure TLS (HTTPS)
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=app_config.web_cert_path, keyfile=app_config.web_key_path)
            app.run(host=app_config.IP, port=app_config.port, ssl_context=context)
    else:
        print("Running without TLS (HTTP).")
        # Run HTTP server (no TLS)
        app.run(host=app_config.IP, port=app_config.port, debug=True)
