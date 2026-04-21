from flask import Flask

class CertificateHttpsServer:
    def __init__(self):
        self.server = Flask(__name__)

        @self.server.route("/", methods=['GET'])
        def cert_https():
            return "Certificate HTTPS Server"

    def start_server(self, host, port, key, certificate):
        self.server.run(host=host, port=port, ssl_context=(certificate, key), threaded=True)